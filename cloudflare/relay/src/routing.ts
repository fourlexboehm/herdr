import { isValidRoute, parseTargetCapability } from "./auth";
import { errorResponse } from "./http";

export type RelayRole = "target" | "controller";

export interface RelayUpgrade {
  role: RelayRole;
  route: string;
}

export interface TurnCredentialsRequest {
  route: string;
}

export function parseTurnCredentialsRequest(
  request: Request,
): TurnCredentialsRequest | Response | null {
  const url = new URL(request.url);
  const match = /^\/v1\/turn-credentials\/([^/]+)$/u.exec(
    url.pathname,
  );
  if (match === null) {
    return url.pathname.startsWith("/v1/turn-credentials/")
      ? errorResponse(
          404,
          "not_found",
          "TURN credential endpoint not found.",
        )
      : null;
  }
  if (url.search !== "") {
    return errorResponse(
      400,
      "query_not_allowed",
      "The TURN credential endpoint does not accept query parameters.",
    );
  }
  if (request.method !== "POST") {
    return errorResponse(
      405,
      "method_not_allowed",
      "The TURN credential endpoint requires POST.",
      { Allow: "POST" },
    );
  }
  const route = match[1] ?? "";
  if (!isValidRoute(route)) {
    return errorResponse(
      400,
      "invalid_route",
      "The route id must be a 32-byte base64url value.",
    );
  }
  if (
    parseTargetCapability(request.headers.get("Authorization")) === null
  ) {
    return errorResponse(
      401,
      "target_capability_required",
      "The TURN credential endpoint requires a valid target capability.",
      { "WWW-Authenticate": "Bearer" },
    );
  }
  return { route };
}

export function parseRelayUpgrade(
  request: Request,
): RelayUpgrade | Response {
  const url = new URL(request.url);
  if (url.search !== "") {
    return errorResponse(
      400,
      "query_not_allowed",
      "Relay endpoints do not accept query parameters.",
    );
  }

  const path = parseRelayPath(url.pathname);
  if (path === null) {
    return errorResponse(404, "not_found", "Endpoint not found.");
  }
  if (request.method !== "GET") {
    return errorResponse(
      405,
      "method_not_allowed",
      "Relay WebSocket endpoints require GET.",
      { Allow: "GET" },
    );
  }
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return errorResponse(
      426,
      "websocket_upgrade_required",
      "Relay endpoints require a WebSocket upgrade.",
      { Upgrade: "websocket" },
    );
  }

  if (!isValidRoute(path.route)) {
    return errorResponse(
      400,
      "invalid_route",
      "The route id must be a 32-byte base64url value.",
    );
  }

  if (
    path.role === "target" &&
    parseTargetCapability(request.headers.get("Authorization")) === null
  ) {
    return errorResponse(
      401,
      "target_capability_required",
      "The target endpoint requires a valid bearer capability.",
      { "WWW-Authenticate": "Bearer" },
    );
  }

  return path;
}

function parseRelayPath(pathname: string): RelayUpgrade | null {
  const match = /^\/v1\/(targets|controllers)\/([^/]+)$/u.exec(pathname);
  if (match === null) {
    return null;
  }

  return {
    role: match[1] === "targets" ? "target" : "controller",
    route: match[2] ?? "",
  };
}
