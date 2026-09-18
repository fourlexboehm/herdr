import { errorResponse, jsonResponse } from "./http";
import {
  parseRelayUpgrade,
  parseTurnCredentialsRequest,
} from "./routing";

export { TargetRelay } from "./relay";
export { TurnQuota } from "./quota";

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") {
      if (url.search !== "") {
        return errorResponse(
          400,
          "query_not_allowed",
          "The health endpoint does not accept query parameters.",
        );
      }
      if (request.method !== "GET") {
        return errorResponse(
          405,
          "method_not_allowed",
          "The health endpoint requires GET.",
          { Allow: "GET" },
        );
      }
      return jsonResponse({
        service: "herdr-relay",
        status: "ok",
        relay_protocol: 1,
      });
    }

    const turn = parseTurnCredentialsRequest(request);
    if (turn instanceof Response) {
      return turn;
    }
    if (turn !== null) {
      const stub = env.TARGET_RELAY.getByName(turn.route);
      return stub.issueTurnCredentials(
        turn.route,
        request.headers.get("Authorization"),
      );
    }

    const upgrade = parseRelayUpgrade(request);
    if (upgrade instanceof Response) {
      return upgrade;
    }

    const stub = env.TARGET_RELAY.getByName(upgrade.route);
    return stub.fetch(request);
  },
} satisfies ExportedHandler<Env>;

export default worker;
