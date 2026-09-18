import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  parseMonthToDateEgressBytes,
  TurnAnalyticsError,
} from "../src/analytics";
import { encodeBase64Url } from "../src/base64";
import {
  DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES,
  TURN_CREDENTIAL_TTL_SECONDS,
  TURN_QUOTA_MAX_STALENESS_MS,
} from "../src/config";
import {
  decideTurnQuota,
  TURN_QUOTA_SINGLETON,
  turnQuotaThresholdBytes,
  type QuotaRow,
} from "../src/quota";

interface RouteCredentials {
  route: string;
  capability: string;
}

const THRESHOLD = turnQuotaThresholdBytes(
  DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES,
);

const originalFetch = globalThis.fetch;
const mutableEnv = env as unknown as Record<string, string | undefined>;
const savedEnv: Record<string, string | undefined> = {};

const TURN_VARS = [
  "TURN_KEY_ID",
  "TURN_KEY_API_TOKEN",
  "CF_ACCOUNT_ID",
  "TURN_ANALYTICS_API_TOKEN",
] as const;

interface FetchLog {
  turnCalls: Array<Record<string, unknown>>;
  analyticsCalls: number;
}

/**
 * Routes outbound calls to the Cloudflare TURN broker and the GraphQL
 * analytics API, recording what the relay actually sent.
 */
function stubFetch(options: {
  egressBytes?: number;
  analyticsFails?: boolean;
}): FetchLog {
  const log: FetchLog = { turnCalls: [], analyticsCalls: 0 };

  globalThis.fetch = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const body = typeof init?.body === "string" ? init.body : "{}";

    if (url.includes("rtc.live.cloudflare.com")) {
      log.turnCalls.push(
        JSON.parse(body) as Record<string, unknown>,
      );
      return Response.json({
        iceServers: [
          { urls: ["stun:stun.cloudflare.com:3478"] },
          {
            urls: ["turn:turn.cloudflare.com:3478?transport=udp"],
            username: "temp-user",
            credential: "temp-pass",
          },
        ],
      });
    }

    if (url.includes("api.cloudflare.com/client/v4/graphql")) {
      log.analyticsCalls += 1;
      if (options.analyticsFails === true) {
        return new Response("upstream failure", { status: 503 });
      }
      return Response.json({
        data: {
          viewer: {
            accounts: [
              {
                callsTurnUsageAdaptiveGroups: [
                  { sum: { egressBytes: options.egressBytes ?? 0 } },
                ],
              },
            ],
          },
        },
        errors: null,
      });
    }

    // The test harness itself uses globalThis.fetch for Durable Object RPC,
    // so anything unrecognized must pass through rather than fail.
    return originalFetch(input, init);
  };

  return log;
}

function randomBase64Url32(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

function createRouteCredentials(): RouteCredentials {
  return { route: randomBase64Url32(), capability: randomBase64Url32() };
}

async function registerTarget(
  credentials: RouteCredentials,
): Promise<WebSocket> {
  const response = await exports.default.fetch(
    new Request(`https://relay.test/v1/targets/${credentials.route}`, {
      headers: {
        Authorization: `Bearer ${credentials.capability}`,
        Upgrade: "websocket",
      },
    }),
  );
  expect(response.status).toBe(101);
  const socket = response.webSocket;
  if (socket === null) {
    throw new Error("Expected a WebSocket on the target upgrade response.");
  }
  socket.accept();
  return socket;
}

async function requestTurn(
  credentials: RouteCredentials,
  capability = credentials.capability,
): Promise<Response> {
  return exports.default.fetch(
    new Request(
      `https://relay.test/v1/turn-credentials/${credentials.route}`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${capability}` },
      },
    ),
  );
}

async function resetQuota(): Promise<void> {
  await env.TURN_QUOTA.getByName(TURN_QUOTA_SINGLETON).resetForTest();
}

async function expectError(
  response: Response,
  status: number,
  code: string,
): Promise<void> {
  expect(response.status).toBe(status);
  await expect(response.json()).resolves.toMatchObject({ error: { code } });
}

beforeEach(async () => {
  // Reset the shared budget reading before the outbound fetch stub is in
  // place; the test harness routes Durable Object RPC through globalThis.fetch.
  await resetQuota();
  for (const name of TURN_VARS) {
    savedEnv[name] = mutableEnv[name];
  }
  mutableEnv.TURN_KEY_ID = "test-turn-key";
  mutableEnv.TURN_KEY_API_TOKEN = "test-turn-token";
  mutableEnv.CF_ACCOUNT_ID = "test-account";
  mutableEnv.TURN_ANALYTICS_API_TOKEN = "test-analytics-token";
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  for (const name of TURN_VARS) {
    if (savedEnv[name] === undefined) {
      delete mutableEnv[name];
    } else {
      mutableEnv[name] = savedEnv[name];
    }
  }
  // Each test uses a fresh random route, so per-route Durable Objects cannot
  // leak between tests. The one shared object is the budget singleton, which
  // beforeEach resets.
});

describe("TURN analytics response parsing", () => {
  it("reads a single summed egress value", () => {
    expect(
      parseMonthToDateEgressBytes({
        data: {
          viewer: {
            accounts: [
              {
                callsTurnUsageAdaptiveGroups: [
                  { sum: { egressBytes: 123_456 } },
                ],
              },
            ],
          },
        },
        errors: null,
      }),
    ).toBe(123_456);
  });

  it("treats a month with no TURN traffic as zero", () => {
    expect(
      parseMonthToDateEgressBytes({
        data: {
          viewer: {
            accounts: [{ callsTurnUsageAdaptiveGroups: [] }],
          },
        },
      }),
    ).toBe(0);
  });

  it("refuses to read a missing account as zero usage", () => {
    // An unknown or unauthorized account tag returns an empty accounts array.
    // Reading that as zero would silently disable the budget.
    expect(() =>
      parseMonthToDateEgressBytes({
        data: { viewer: { accounts: [] } },
      }),
    ).toThrow(TurnAnalyticsError);
  });

  it("rejects a GraphQL error payload delivered with HTTP 200", () => {
    expect(() =>
      parseMonthToDateEgressBytes({
        data: null,
        errors: [{ message: "unauthorized" }],
      }),
    ).toThrow(TurnAnalyticsError);
  });

  it("rejects malformed and negative egress values", () => {
    for (const egressBytes of ["12", -1, Number.NaN, null]) {
      expect(() =>
        parseMonthToDateEgressBytes({
          data: {
            viewer: {
              accounts: [
                { callsTurnUsageAdaptiveGroups: [{ sum: { egressBytes } }] },
              ],
            },
          },
        }),
      ).toThrow(TurnAnalyticsError);
    }
  });
});

describe("TURN budget decision", () => {
  const month = "2026-09";
  const now = Date.parse("2026-09-18T00:00:00Z");

  function row(overrides: Partial<QuotaRow> = {}): QuotaRow {
    return {
      month,
      egress_bytes: 1_000,
      observed_at: now,
      ...overrides,
    };
  }

  it("trips below the configured ceiling", () => {
    expect(turnQuotaThresholdBytes(1_000_000_000_000)).toBe(950_000_000_000);
  });

  it("allows usage under the threshold", () => {
    const decision = decideTurnQuota(
      row({ egress_bytes: THRESHOLD - 1 }),
      month,
      now,
      DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES,
      THRESHOLD,
    );
    expect(decision).toMatchObject({
      allowed: true,
      state: "within_budget",
      usedBytes: THRESHOLD - 1,
    });
  });

  it("denies usage at or above the threshold", () => {
    for (const used of [THRESHOLD, THRESHOLD + 1]) {
      expect(
        decideTurnQuota(
          row({ egress_bytes: used }),
          month,
          now,
          DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES,
          THRESHOLD,
        ),
      ).toMatchObject({ allowed: false, state: "exhausted" });
    }
  });

  it("fails closed with no reading at all", () => {
    expect(
      decideTurnQuota(
        null,
        month,
        now,
        DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES,
        THRESHOLD,
      ),
    ).toMatchObject({ allowed: false, state: "unknown", usedBytes: null });
  });

  it("fails closed on a stale reading", () => {
    expect(
      decideTurnQuota(
        row({ observed_at: now - TURN_QUOTA_MAX_STALENESS_MS - 1 }),
        month,
        now,
        DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES,
        THRESHOLD,
      ),
    ).toMatchObject({ allowed: false, state: "unknown" });
  });

  it("fails closed when the reading belongs to a previous month", () => {
    // Otherwise a spent budget would silently carry into the new month, or a
    // stale low reading would reopen a spent one.
    expect(
      decideTurnQuota(
        row({ month: "2026-08" }),
        month,
        now,
        DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES,
        THRESHOLD,
      ),
    ).toMatchObject({ allowed: false, state: "unknown", usedBytes: null });
  });
});

describe("TURN credential budget enforcement", () => {
  it("mints credentials while inside the budget", async () => {
    const log = stubFetch({ egressBytes: 1_000 });
    const credentials = createRouteCredentials();
    const socket = await registerTarget(credentials);

    const response = await requestTurn(credentials);
    expect(response.status).toBe(200);
    const body = await response.json<{
      allocations: Array<{ iceServers: unknown[] }>;
    }>();
    expect(body.allocations).toHaveLength(2);
    for (const allocation of body.allocations) {
      expect(allocation.iceServers.length).toBeGreaterThan(0);
    }

    expect(log.turnCalls).toHaveLength(2);
    for (const call of log.turnCalls) {
      expect(call.ttl).toBe(TURN_CREDENTIAL_TTL_SECONDS);
    }
    socket.close();
  });

  it("refuses to mint once measured egress reaches the threshold", async () => {
    const log = stubFetch({ egressBytes: THRESHOLD });
    const credentials = createRouteCredentials();
    const socket = await registerTarget(credentials);

    await expectError(
      await requestTurn(credentials),
      503,
      "turn_budget_exhausted",
    );
    // No credentials may be brokered once the budget is spent.
    expect(log.turnCalls).toHaveLength(0);
    socket.close();
  });

  it("fails closed when usage cannot be measured", async () => {
    const log = stubFetch({ analyticsFails: true });
    const credentials = createRouteCredentials();
    const socket = await registerTarget(credentials);

    await expectError(
      await requestTurn(credentials),
      503,
      "turn_budget_exhausted",
    );
    expect(log.analyticsCalls).toBeGreaterThan(0);
    expect(log.turnCalls).toHaveLength(0);
    socket.close();
  });

  it("reports missing usage accounting instead of minting blind", async () => {
    stubFetch({ egressBytes: 0 });
    delete mutableEnv.TURN_ANALYTICS_API_TOKEN;
    const credentials = createRouteCredentials();
    const socket = await registerTarget(credentials);

    await expectError(
      await requestTurn(credentials),
      501,
      "turn_not_configured",
    );
    socket.close();
  });

  it("coalesces concurrent budget refreshes into one analytics query", async () => {
    const log = stubFetch({ egressBytes: 1_000 });
    const credentials = createRouteCredentials();
    const socket = await registerTarget(credentials);

    const responses = await Promise.all([
      requestTurn(credentials),
      requestTurn(credentials),
      requestTurn(credentials),
    ]);
    for (const response of responses) {
      expect(response.status).toBe(200);
    }
    // A burst of TURN requests must not fan out into one query each.
    expect(log.analyticsCalls).toBe(1);
    socket.close();
  });

});
