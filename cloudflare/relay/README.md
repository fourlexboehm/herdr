# Herdr Cloudflare relay

This package is the opaque rendezvous and signaling layer for Herdr's
experimental native end-to-end encrypted peer transport. It contains a
front-door Worker and one SQLite-backed, hibernating `TargetRelay` Durable
Object per target route. Herdr peers use the WebSocket connection for Noise
authentication, ICE signaling, and connection lifecycle. Endpoint traffic
requires an ordered WebRTC data channel over direct ICE/STUN or TURN and never
uses the WebSocket.

The relay never parses Herdr or Noise messages and never persists traffic,
keys, invitations, or raw registration capabilities. Structured logs contain
only event categories and socket roles. Automatic invocation logs and traces
are disabled because route ids are carried in request paths.

## HTTP and authentication

- `GET /healthz`
- `GET /v1/targets/{route_id}` with `Upgrade: websocket` and
  `Authorization: Bearer <registration_capability>`
- `GET /v1/controllers/{route_id}` with `Upgrade: websocket`
- `POST /v1/turn-credentials/{route_id}` with the target registration
  capability

Route ids and registration capabilities are independent unpadded base64url
encodings of 32 random bytes. The first successful target registration stores
only a random salt and:

```text
SHA-256(salt || route_id_bytes || registration_capability_bytes)
```

Subsequent target connections are checked against that verifier with a
constant-time comparison. Controllers are intentionally unauthenticated by
the relay; the end-to-end encrypted Herdr protocol authenticates them.

The optional TURN endpoint never creates a route registration. After a target
has registered, it can request two independent 24-hour Cloudflare TURN
allocations for an authenticated controller connection. ICE tries direct paths
first and uses TURN only when NAT or firewall behavior prevents them.

Create a Cloudflare Realtime TURN key, then configure its ID and API token as
Worker secrets, plus an account id and an analytics token for usage accounting:

```bash
npx wrangler secret put TURN_KEY_ID
npx wrangler secret put TURN_KEY_API_TOKEN
npx wrangler secret put CF_ACCOUNT_ID
npx wrangler secret put TURN_ANALYTICS_API_TOKEN
```

`TURN_ANALYTICS_API_TOKEN` needs the **Account Analytics** read permission and
is only used to measure usage. Without `TURN_KEY_ID` or `TURN_KEY_API_TOKEN`
the endpoint returns `turn_not_configured`. Without `CF_ACCOUNT_ID` or
`TURN_ANALYTICS_API_TOKEN` it also returns `turn_not_configured`, because the
egress budget below fails closed and the relay will not broker credentials it
cannot account for. In both cases Herdr still tries direct ICE/STUN, but the
connection fails and retries if no direct path opens. The long-lived TURN API
token is never returned to Herdr. Only the generated short-lived credentials
cross the target-authenticated endpoint.

## TURN egress budget

Cloudflare Realtime bills TURN on `egressBytes` and exposes no native data cap,
and the relay is not on the TURN data path, so the monthly ceiling is a
**measured circuit breaker, not a hard limit**.

`TURN_MONTHLY_EGRESS_LIMIT_BYTES` (default `1000000000000`, 1 TB, matching the
1,000 GB Realtime free tier shared by SFU and TURN) sets the ceiling. A
singleton `TurnQuota` Durable Object queries month-to-date `sum(egressBytes)`
for the configured `keyId` from the `callsTurnUsageAdaptiveGroups` GraphQL
dataset, caches the reading for five minutes, and coalesces concurrent
refreshes into one query. Minting stops at 95% of the ceiling because TURN
analytics is adaptively sampled at collection and at query time, so the figure
is an estimate rather than an exact count.

The budget fails closed. A missing reading, a reading older than fifteen
minutes, a reading from a previous month, an analytics outage, or a
misconfigured account id all resolve to `turn_budget_exhausted` (HTTP 503)
rather than permitting unaccounted spend. An empty analytics `accounts` array
is treated as an error, never as zero usage. Herdr treats any non-success
response as "TURN unavailable" and continues with direct ICE/STUN.

Credentials already issued keep working until their 24-hour TTL expires, so the
effective ceiling exceeds the configured one by whatever outstanding
credentials can still pull before expiring.

## Relay protocol version 1

Controller WebSocket application messages are opaque binary handshake and
signaling payloads no larger than 1 MiB. The relay wraps each controller frame
in a target `data` envelope. Target `data` payloads are unwrapped and sent to
the selected controller without interpretation. Herdr rejects WebSocket
endpoint data after the peer transport activates.

Every target WebSocket application message is a binary envelope:

```text
byte 0       version (1)
byte 1       kind (open=1, data=2, close=3, notice=4)
bytes 2..5   u32 big-endian connection_id
bytes 6..9   u32 big-endian payload_len
bytes 10..   payload
```

Connection id `0` is reserved for relay-level notices. Controller ids are
random non-zero `u32` values. `open` has an empty payload. `data` is opaque and
may be empty. `close` and `notice` contain at most 512 bytes of valid UTF-8.
Payload length is capped at 1 MiB and must exactly match the header.

Hibernating sockets serialize only protocol version, role, and connection id.
SQLite stores the salted target verifier and bounded connection-attempt and
TURN-credential request counters only. The budget singleton stores a single
measured month-to-date egress reading. Peer configuration and SDP signaling
are inside the end-to-end encrypted controller payloads and remain opaque to
the Worker.

## Data path

The ordered, reliable WebRTC data channel owns endpoint delivery and
backpressure. WebSocket messages stop after bounded authentication and ICE
signaling, apart from protocol ping/pong and close lifecycle traffic. The
Durable Object therefore never queues or forwards terminal output.

## Local validation

```bash
npm install
npm run types
npm run check
npm run deploy:dry-run
```

`wrangler types` generates `worker-configuration.d.ts` from
`wrangler.jsonc`. Local secrets belong in ignored `.dev.vars` or `.env` files.
No credentials are required for tests or the deployment dry run.
