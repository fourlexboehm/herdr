import { DurableObject } from "cloudflare:workers";

import {
  currentDate,
  fetchMonthToDateEgressBytes,
  monthStartDate,
  TurnAnalyticsError,
  utcYearMonth,
} from "./analytics";
import {
  DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES,
  TURN_QUOTA_MAX_STALENESS_MS,
  TURN_QUOTA_REFRESH_INTERVAL_MS,
  TURN_QUOTA_SAFETY_DENOMINATOR,
  TURN_QUOTA_SAFETY_NUMERATOR,
} from "./config";

export const TURN_QUOTA_SINGLETON = "global";

export type TurnQuotaState =
  "within_budget" | "exhausted" | "unknown" | "not_configured";

export interface TurnQuotaDecision {
  allowed: boolean;
  state: TurnQuotaState;
  usedBytes: number | null;
  thresholdBytes: number;
  limitBytes: number;
  observedAt: number | null;
}

export interface QuotaRow extends Record<string, SqlStorageValue> {
  month: string;
  egress_bytes: number;
  observed_at: number;
}

interface AnalyticsConfig {
  accountId: string;
  analyticsToken: string;
  keyId: string;
}

export class TurnQuota extends DurableObject<Env> {
  private pendingRefresh: Promise<void> | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);

    void this.ctx.blockConcurrencyWhile(() => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS turn_egress_usage (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          month TEXT NOT NULL,
          egress_bytes INTEGER NOT NULL CHECK (egress_bytes >= 0),
          observed_at INTEGER NOT NULL
        )
      `);
      return Promise.resolve();
    });
  }

  /**
   * Returns the current budget decision, refreshing the measured usage when
   * the cached reading is older than the refresh interval.
   *
   * Cloudflare exposes no native TURN data cap and the relay never sees TURN
   * traffic, so this is a measured circuit breaker rather than a hard limit.
   * When usage cannot be established the decision fails closed.
   */
  async evaluate(): Promise<TurnQuotaDecision> {
    const limitBytes = this.resolveLimitBytes();
    const thresholdBytes = turnQuotaThresholdBytes(limitBytes);

    const config = this.readAnalyticsConfig();
    if (config === null) {
      console.error({ event: "turn_quota_not_configured" });
      return {
        allowed: false,
        state: "not_configured",
        usedBytes: null,
        thresholdBytes,
        limitBytes,
        observedAt: null,
      };
    }

    const month = utcYearMonth(new Date());
    if (this.readingAge(month) >= TURN_QUOTA_REFRESH_INTERVAL_MS) {
      await this.refresh(config, month);
    }

    return decideTurnQuota(
      this.readUsage(),
      month,
      Date.now(),
      limitBytes,
      thresholdBytes,
    );
  }

  /** Test and operations helper: the last measured reading, if any. */
  async peek(): Promise<QuotaRow | null> {
    return Promise.resolve(this.readUsage());
  }

  /** Test helper: drop the measured reading so the next evaluate() refreshes. */
  async resetForTest(): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM turn_egress_usage");
    return Promise.resolve();
  }

  /** Test helper: seed a measured reading without calling the analytics API. */
  async seedForTest(
    month: string,
    egressBytes: number,
    observedAt: number,
  ): Promise<void> {
    this.writeUsage(month, egressBytes, observedAt);
    return Promise.resolve();
  }

  private async refresh(config: AnalyticsConfig, month: string): Promise<void> {
    // Coalesce concurrent refreshes so a burst of TURN requests produces one
    // analytics query rather than one per request.
    this.pendingRefresh ??= this.runRefresh(config, month).finally(() => {
      this.pendingRefresh = null;
    });
    await this.pendingRefresh;
  }

  private async runRefresh(
    config: AnalyticsConfig,
    month: string,
  ): Promise<void> {
    const now = new Date();
    try {
      const egressBytes = await fetchMonthToDateEgressBytes({
        accountId: config.accountId,
        analyticsToken: config.analyticsToken,
        keyId: config.keyId,
        dateFrom: monthStartDate(now),
        dateTo: currentDate(now),
      });
      this.writeUsage(month, egressBytes, Date.now());
    } catch (error) {
      // Keep the previous reading. It ages out into "unknown", which denies.
      // The code alone cannot distinguish a token permission problem from a
      // schema problem, so the message is recorded with it.
      // The account tag is not a secret (it appears in dashboard URLs and
      // `wrangler whoami`), and an authorization failure cannot be told apart
      // from a wrong tag without seeing which one was sent.
      console.error({
        event: "turn_quota_refresh_failed",
        error_code:
          error instanceof TurnAnalyticsError ? error.code : "unexpected",
        error_message:
          error instanceof Error ? error.message.slice(0, 500) : "unknown",
        account_id: config.accountId,
        key_id_length: config.keyId.length,
        analytics_token_length: config.analyticsToken.length,
      });
    }
  }

  private readingAge(month: string): number {
    const row = this.readUsage();
    if (row === null || row.month !== month) {
      return Number.POSITIVE_INFINITY;
    }
    return Math.max(0, Date.now() - row.observed_at);
  }

  private readUsage(): QuotaRow | null {
    const rows = this.ctx.storage.sql
      .exec<QuotaRow>(
        "SELECT month, egress_bytes, observed_at FROM turn_egress_usage WHERE id = 1",
      )
      .toArray();
    return rows[0] ?? null;
  }

  private writeUsage(
    month: string,
    egressBytes: number,
    observedAt: number,
  ): void {
    this.ctx.storage.sql.exec(
      `
        INSERT INTO turn_egress_usage (id, month, egress_bytes, observed_at)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          month = excluded.month,
          egress_bytes = excluded.egress_bytes,
          observed_at = excluded.observed_at
      `,
      month,
      egressBytes,
      observedAt,
    );
  }

  private resolveLimitBytes(): number {
    const configured = readStringVar(
      this.env,
      "TURN_MONTHLY_EGRESS_LIMIT_BYTES",
    );
    if (configured === null) {
      return DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES;
    }
    const parsed = Number(configured);
    if (
      !Number.isFinite(parsed) ||
      !Number.isSafeInteger(parsed) ||
      parsed <= 0
    ) {
      console.error({ event: "turn_quota_limit_invalid" });
      return DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES;
    }
    return parsed;
  }

  private readAnalyticsConfig(): AnalyticsConfig | null {
    const accountId = readStringVar(this.env, "CF_ACCOUNT_ID");
    const analyticsToken = readStringVar(this.env, "TURN_ANALYTICS_API_TOKEN");
    const keyId = readStringVar(this.env, "TURN_KEY_ID");
    if (accountId === null || analyticsToken === null || keyId === null) {
      return null;
    }
    return { accountId, analyticsToken, keyId };
  }
}

export function readStringVar(env: Env, name: string): string | null {
  const value = Reflect.get(env, name) as unknown;
  return typeof value === "string" && value !== "" ? value : null;
}

export function turnQuotaThresholdBytes(limitBytes: number): number {
  return Math.floor(
    (limitBytes * TURN_QUOTA_SAFETY_NUMERATOR) / TURN_QUOTA_SAFETY_DENOMINATOR,
  );
}

/**
 * Pure budget decision over the last measured reading.
 *
 * A reading from a previous month, a missing reading, or a reading older than
 * the staleness ceiling all resolve to "unknown", which denies. That is the
 * fail-closed rule: when the relay cannot establish how much egress has been
 * spent, it stops handing out credentials rather than risk unbounded spend.
 */
export function decideTurnQuota(
  row: QuotaRow | null,
  month: string,
  nowMs: number,
  limitBytes: number,
  thresholdBytes: number,
): TurnQuotaDecision {
  const current = row !== null && row.month === month ? row : null;
  const age =
    current === null
      ? Number.POSITIVE_INFINITY
      : Math.max(0, nowMs - current.observed_at);

  if (current === null || age > TURN_QUOTA_MAX_STALENESS_MS) {
    return {
      allowed: false,
      state: "unknown",
      usedBytes: current?.egress_bytes ?? null,
      thresholdBytes,
      limitBytes,
      observedAt: current?.observed_at ?? null,
    };
  }

  const exhausted = current.egress_bytes >= thresholdBytes;
  return {
    allowed: !exhausted,
    state: exhausted ? "exhausted" : "within_budget",
    usedBytes: current.egress_bytes,
    thresholdBytes,
    limitBytes,
    observedAt: current.observed_at,
  };
}
