export const RELAY_PROTOCOL_VERSION = 1;

export const ROUTE_BYTES = 32;
export const ROUTE_LENGTH = 43;
export const ROUTE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export const SYSTEM_CONNECTION_ID = 0;
export const MIN_CONNECTION_ID = 1;
export const MAX_CONNECTION_ID = 0xffff_ffff;

export const TARGET_ENVELOPE_HEADER_BYTES = 10;
export const MAX_PAYLOAD_BYTES = 1024 * 1024;
export const MAX_TARGET_FRAME_BYTES =
  TARGET_ENVELOPE_HEADER_BYTES + MAX_PAYLOAD_BYTES;
export const MAX_CONTROL_PAYLOAD_BYTES = 512;

export const MAX_CONTROLLERS = 16;
export const MAX_CONNECTION_ATTEMPTS_PER_MINUTE = 16;
export const MAX_TARGET_CONNECTION_ATTEMPTS_PER_MINUTE = 32;
export const MAX_TURN_CREDENTIAL_REQUESTS_PER_MINUTE = 16;
export const TURN_CREDENTIAL_TTL_SECONDS = 24 * 60 * 60;

export const CLOSE_CODE_PROTOCOL_ERROR = 4400;
export const CLOSE_CODE_TARGET_UNAVAILABLE = 4404;
export const CLOSE_CODE_DELIVERY_FAILED = 4408;
export const CLOSE_CODE_INTERNAL_ERROR = 4411;

// Monthly TURN egress ceiling. Cloudflare exposes no native TURN data cap and
// the relay is not on the TURN data path, so the ceiling is enforced by
// measuring usage through the GraphQL analytics API and refusing to mint new
// credentials once it is spent.
export const DEFAULT_TURN_MONTHLY_EGRESS_LIMIT_BYTES = 1_000_000_000_000;

// Trip below the ceiling: TURN analytics is adaptively sampled at collection
// and at query time, so the observed figure is an estimate.
export const TURN_QUOTA_SAFETY_NUMERATOR = 95;
export const TURN_QUOTA_SAFETY_DENOMINATOR = 100;

// A cached reading is reused for this long before a request refreshes it.
export const TURN_QUOTA_REFRESH_INTERVAL_MS = 5 * 60_000;

// Beyond this age the reading is treated as unknown and minting fails closed.
export const TURN_QUOTA_MAX_STALENESS_MS = 15 * 60_000;

export const TURN_QUOTA_ANALYTICS_TIMEOUT_MS = 5_000;
export const TURN_QUOTA_MAX_ANALYTICS_RESPONSE_BYTES = 64 * 1024;
