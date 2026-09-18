import {
  TURN_QUOTA_ANALYTICS_TIMEOUT_MS,
  TURN_QUOTA_MAX_ANALYTICS_RESPONSE_BYTES,
} from "./config";

const GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";

// Cloudflare's TURN analytics applies adaptive sampling at collection and at
// query time. Their billing guidance is to ask one question and read one
// summed value, so this query requests no dimensions and no time buckets.
const MONTH_TO_DATE_EGRESS_QUERY = `
  query RelayTurnMonthToDateEgress(
    $accountId: String!
    $keyId: String!
    $dateFrom: Date!
    $dateTo: Date!
  ) {
    viewer {
      accounts(filter: { accountTag: $accountId }) {
        callsTurnUsageAdaptiveGroups(
          limit: 1
          filter: {
            date_geq: $dateFrom
            date_leq: $dateTo
            keyId: $keyId
          }
        ) {
          sum {
            egressBytes
          }
        }
      }
    }
  }
`;

export interface TurnAnalyticsRequest {
  accountId: string;
  analyticsToken: string;
  keyId: string;
  dateFrom: string;
  dateTo: string;
}

export class TurnAnalyticsError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "TurnAnalyticsError";
  }
}

export async function fetchMonthToDateEgressBytes(
  request: TurnAnalyticsRequest,
): Promise<number> {
  let response: Response;
  try {
    response = await fetch(GRAPHQL_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${request.analyticsToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: MONTH_TO_DATE_EGRESS_QUERY,
        variables: {
          accountId: request.accountId,
          keyId: request.keyId,
          dateFrom: request.dateFrom,
          dateTo: request.dateTo,
        },
      }),
      signal: AbortSignal.timeout(TURN_QUOTA_ANALYTICS_TIMEOUT_MS),
    });
  } catch (error) {
    throw new TurnAnalyticsError(
      "analytics_unreachable",
      error instanceof Error ? error.message : "Analytics request failed.",
    );
  }

  if (!response.ok) {
    throw new TurnAnalyticsError(
      "analytics_http_error",
      `Analytics API returned HTTP ${String(response.status)}.`,
    );
  }

  const contentLength = Number(response.headers.get("Content-Length") ?? "0");
  if (
    Number.isFinite(contentLength) &&
    contentLength > TURN_QUOTA_MAX_ANALYTICS_RESPONSE_BYTES
  ) {
    throw new TurnAnalyticsError(
      "analytics_response_too_large",
      "Analytics response exceeded the configured limit.",
    );
  }

  let body: unknown;
  try {
    body = await response.json<unknown>();
  } catch {
    throw new TurnAnalyticsError(
      "analytics_response_invalid",
      "Analytics response was not valid JSON.",
    );
  }

  return parseMonthToDateEgressBytes(body);
}

export function parseMonthToDateEgressBytes(body: unknown): number {
  if (!isRecord(body)) {
    throw new TurnAnalyticsError(
      "analytics_response_invalid",
      "Analytics response was not an object.",
    );
  }

  // GraphQL reports failures with HTTP 200 and a populated errors array.
  // The message is the only signal that separates a permissions problem from a
  // schema problem, so it has to survive into the caller's log.
  const errors = body.errors;
  if (Array.isArray(errors) && errors.length > 0) {
    throw new TurnAnalyticsError(
      "analytics_query_failed",
      `Analytics query returned errors: ${summarizeGraphqlErrors(errors)}`,
    );
  }

  const data = body.data;
  if (!isRecord(data)) {
    throw new TurnAnalyticsError(
      "analytics_response_invalid",
      "Analytics response had no data object.",
    );
  }
  const viewer = data.viewer;
  if (!isRecord(viewer) || !Array.isArray(viewer.accounts)) {
    throw new TurnAnalyticsError(
      "analytics_response_invalid",
      "Analytics response had no accounts array.",
    );
  }

  // An unknown or unauthorized account tag yields an empty accounts array.
  // Reading that as zero usage would silently disable the budget, so it is an
  // error rather than a permissive default.
  const accounts: unknown[] = viewer.accounts;
  const account = accounts[0];
  if (accounts.length === 0 || !isRecord(account)) {
    throw new TurnAnalyticsError(
      "analytics_account_not_found",
      "Analytics response contained no matching account.",
    );
  }

  const rawGroups = account.callsTurnUsageAdaptiveGroups;
  if (!Array.isArray(rawGroups)) {
    throw new TurnAnalyticsError(
      "analytics_response_invalid",
      "Analytics response had no TURN usage groups.",
    );
  }
  // A month with no TURN traffic legitimately returns no groups.
  const groups: unknown[] = rawGroups;
  if (groups.length === 0) {
    return 0;
  }

  const group = groups[0];
  if (!isRecord(group) || !isRecord(group.sum)) {
    throw new TurnAnalyticsError(
      "analytics_response_invalid",
      "Analytics usage group had no sum object.",
    );
  }

  const egressBytes = group.sum.egressBytes;
  if (
    typeof egressBytes !== "number" ||
    !Number.isFinite(egressBytes) ||
    egressBytes < 0
  ) {
    throw new TurnAnalyticsError(
      "analytics_response_invalid",
      "Analytics egressBytes was not a non-negative number.",
    );
  }

  return Math.floor(egressBytes);
}

export function monthStartDate(now: Date): string {
  return `${utcYearMonth(now)}-01`;
}

export function currentDate(now: Date): string {
  return now.toISOString().slice(0, 10);
}

export function utcYearMonth(now: Date): string {
  return now.toISOString().slice(0, 7);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** Joins GraphQL error messages, bounded so a large response cannot flood logs. */
function summarizeGraphqlErrors(errors: unknown[]): string {
  const messages = errors.slice(0, 3).map((entry) => {
    if (isRecord(entry) && typeof entry.message === "string") {
      return entry.message.slice(0, 200);
    }
    return "unrecognized error entry";
  });
  const suffix = errors.length > messages.length ? ` (+${String(errors.length - messages.length)} more)` : "";
  return `${messages.join("; ")}${suffix}`;
}
