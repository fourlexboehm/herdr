# Herdr Cloudflare relay

This package is the opaque rendezvous layer for Herdr's experimental native
end-to-end encrypted relay transport. It contains a front-door Worker and one
SQLite-backed, hibernating `TargetRelay` Durable Object per target route.

The relay never parses Herdr or Noise messages and never persists traffic,
keys, invitations, or raw registration capabilities. Structured logs contain
only event categories and socket roles. Automatic invocation logs and traces
are disabled because route ids are carried in request paths.

## HTTP and authentication

- `GET /healthz`
- `GET /v1/targets/{route_id}` with `Upgrade: websocket` and
  `Authorization: Bearer <registration_capability>`
- `GET /v1/controllers/{route_id}` with `Upgrade: websocket`

Route ids and registration capabilities are independent unpadded base64url
encodings of 32 random bytes. The first successful target registration stores
only a random salt and:

```text
SHA-256(salt || route_id_bytes || registration_capability_bytes)
```

Subsequent target connections are checked against that verifier with a
constant-time comparison. Controllers are intentionally unauthenticated by
the relay; the end-to-end encrypted Herdr protocol authenticates them.

Controllers are accepted only while the target is connected. A duplicate live
target receives an HTTP 409 response and the existing target remains active.
Each route accepts at most 16 controller connection attempts per minute and 16
simultaneous controller sockets. The target closes controllers that do not
complete the end-to-end handshake within 10 seconds, so a holder of an old
route id cannot reserve those slots indefinitely. Authenticated target
reconnects use an independent rate budget.

## Relay protocol version 1

Controller WebSocket application messages are opaque binary payloads no larger
than 1 MiB. The relay wraps each controller frame in a target `data` envelope.
Target `data` payloads are unwrapped and sent to the selected controller
without interpretation.

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
SQLite stores the salted target verifier and bounded connection-attempt
counters only.

## Cloudflare backpressure limitation

The Hibernation WebSocket API exposes neither `bufferedAmount` nor an async
send-completion signal. Because the Rust-facing controller stream permits only
opaque binary data, the relay cannot add acknowledgement frames without
changing the contract. It therefore keeps no userland message queue, forwards
synchronously, and disconnects only the failed recipient when `WebSocket.send`
throws. The 1 MiB payload limit remains enforced, but a separate byte limit on
Cloudflare's internal socket buffer is not observable.

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
