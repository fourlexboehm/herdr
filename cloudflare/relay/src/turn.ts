import { TURN_CREDENTIAL_TTL_SECONDS } from "./config";

const MAX_TURN_RESPONSE_BYTES = 32 * 1024;
const MAX_ICE_SERVERS = 8;
const MAX_ICE_URLS = 16;
const MAX_ICE_VALUE_BYTES = 2048;

export interface IceServer {
  urls: string[];
  username: string;
  credential: string;
}

export interface TurnAllocation {
  iceServers: IceServer[];
}

export async function generateTurnAllocation(
  keyId: string,
  apiToken: string,
): Promise<TurnAllocation> {
  const response = await fetch(
    `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(keyId)}/credentials/generate-ice-servers`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ttl: TURN_CREDENTIAL_TTL_SECONDS }),
    },
  );
  if (!response.ok) {
    console.error({
      event: "turn_credential_generation_failed",
      status: response.status,
    });
    throw new Error("Cloudflare TURN credential generation failed.");
  }
  const contentLength = Number(
    response.headers.get("Content-Length") ?? "0",
  );
  if (
    Number.isFinite(contentLength) &&
    contentLength > MAX_TURN_RESPONSE_BYTES
  ) {
    throw new Error("Cloudflare TURN credential response is too large.");
  }
  return normalizeTurnAllocation(await response.json<unknown>());
}

export function normalizeTurnAllocation(
  value: unknown,
): TurnAllocation {
  if (!isRecord(value) || !Array.isArray(value.iceServers)) {
    throw new Error("Cloudflare TURN credential response is invalid.");
  }
  if (
    value.iceServers.length === 0 ||
    value.iceServers.length > MAX_ICE_SERVERS
  ) {
    throw new Error(
      "Cloudflare TURN credential response has an invalid server count.",
    );
  }

  const iceServers = value.iceServers.map((server) => {
    if (!isRecord(server) || !Array.isArray(server.urls)) {
      throw new Error("Cloudflare TURN ICE server is invalid.");
    }
    const urls = server.urls.filter(
      (url): url is string =>
        typeof url === "string" &&
        !/^turns?:[^/]+:53(?:\?|$)/u.test(url),
    );
    if (
      urls.length === 0 ||
      urls.length > MAX_ICE_URLS ||
      urls.some(
        (url) =>
          url.length > MAX_ICE_VALUE_BYTES ||
          !/^(?:stun|turn|turns):/u.test(url),
      )
    ) {
      throw new Error("Cloudflare TURN ICE server URLs are invalid.");
    }
    const username =
      typeof server.username === "string" ? server.username : "";
    const credential =
      typeof server.credential === "string"
        ? server.credential
        : "";
    if (
      username.length > MAX_ICE_VALUE_BYTES ||
      credential.length > MAX_ICE_VALUE_BYTES
    ) {
      throw new Error(
        "Cloudflare TURN ICE server credentials are invalid.",
      );
    }
    const hasTurn = urls.some(
      (url) => url.startsWith("turn:") || url.startsWith("turns:"),
    );
    if (hasTurn && (username === "" || credential === "")) {
      throw new Error(
        "Cloudflare TURN ICE server credentials are missing.",
      );
    }
    return { urls, username, credential };
  });
  return { iceServers };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
