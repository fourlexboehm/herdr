import { env, exports } from "cloudflare:workers";
import {
  evictAllDurableObjects,
  evictDurableObject,
  runInDurableObject,
} from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { encodeBase64Url } from "../src/base64";
import {
  MAX_CONNECTION_ATTEMPTS_PER_MINUTE,
  MAX_CONTROLLERS,
  MAX_PAYLOAD_BYTES,
  RELAY_PROTOCOL_VERSION,
  SYSTEM_CONNECTION_ID,
  TARGET_ENVELOPE_HEADER_BYTES,
} from "../src/config";
import {
  decodeTargetEnvelope,
  encodeClose,
  encodeData,
  RelayFrameKind,
  type TargetEnvelope,
} from "../src/protocol";
import { reconstructSocketState } from "../src/relay";
import type { TargetRelay } from "../src/relay";
import { normalizeTurnAllocation } from "../src/turn";

interface RouteCredentials {
  route: string;
  capability: string;
}

interface ConnectedSocket {
  response: Response;
  inbox: SocketInbox;
}

class SocketInbox {
  readonly socket: WebSocket;
  private readonly messages: Array<ArrayBuffer | string> = [];
  private readonly messageWaiters: Array<{
    resolve: (value: ArrayBuffer | string) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];
  private closeEvent: CloseEvent | null = null;
  private readonly closeWaiters: Array<(event: CloseEvent) => void> = [];

  constructor(socket: WebSocket) {
    this.socket = socket;
    this.socket.binaryType = "arraybuffer";
    this.socket.addEventListener("message", (event) => {
      const data = event.data as ArrayBuffer | string;
      const waiter = this.messageWaiters.shift();
      if (waiter === undefined) {
        this.messages.push(data);
        return;
      }
      clearTimeout(waiter.timer);
      waiter.resolve(data);
    });
    this.socket.addEventListener("close", (event) => {
      this.closeEvent = event;
      for (const resolve of this.closeWaiters.splice(0)) {
        resolve(event);
      }
    });
    this.socket.accept();
  }

  send(frame: Uint8Array | string): void {
    this.socket.send(frame);
  }

  close(code = 1000, reason = "test_done"): void {
    if (this.socket.readyState === WebSocket.OPEN) {
      this.socket.close(code, reason);
    }
  }

  async nextEnvelope(timeoutMs = 1_000): Promise<TargetEnvelope> {
    return decodeTargetEnvelope(await this.nextBinary(timeoutMs));
  }

  async nextBinary(timeoutMs = 1_000): Promise<ArrayBuffer> {
    const message = await this.nextMessage(timeoutMs);
    if (typeof message === "string") {
      throw new Error("Expected a binary WebSocket message.");
    }
    return message;
  }

  async nextClose(timeoutMs = 1_000): Promise<CloseEvent> {
    if (this.closeEvent !== null) {
      return this.closeEvent;
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.closeWaiters.indexOf(resolve);
        if (index >= 0) {
          this.closeWaiters.splice(index, 1);
        }
        reject(new Error("Timed out waiting for WebSocket close."));
      }, timeoutMs);
      this.closeWaiters.push((event) => {
        clearTimeout(timer);
        resolve(event);
      });
    });
  }

  private async nextMessage(timeoutMs: number): Promise<ArrayBuffer | string> {
    const queued = this.messages.shift();
    if (queued !== undefined) {
      return queued;
    }

    return new Promise((resolve, reject) => {
      const waiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const index = this.messageWaiters.indexOf(waiter);
          if (index >= 0) {
            this.messageWaiters.splice(index, 1);
          }
          reject(new Error("Timed out waiting for WebSocket message."));
        }, timeoutMs),
      };
      this.messageWaiters.push(waiter);
    });
  }
}

afterEach(async () => {
  await evictAllDurableObjects({ webSockets: "close" });
});

describe("Cloudflare relay", () => {
  it("validates health, versioned paths, methods, upgrades, and routes", async () => {
    const health = await exports.default.fetch("https://relay.test/healthz");
    expect(health.status).toBe(200);
    await expect(health.json()).resolves.toEqual({
      service: "herdr-relay",
      status: "ok",
      relay_protocol: 1,
    });

    await expectError(
      await exports.default.fetch("https://relay.test/nope"),
      404,
      "not_found",
    );
    await expectError(
      await exports.default.fetch(
        new Request(
          `https://relay.test/v1/controllers/${randomBase64Url32()}`,
          { method: "POST" },
        ),
      ),
      405,
      "method_not_allowed",
    );
    await expectError(
      await exports.default.fetch(
        `https://relay.test/v1/controllers/${randomBase64Url32()}`,
      ),
      426,
      "websocket_upgrade_required",
    );
    await expectError(
      await upgrade("/v1/controllers/not-a-route"),
      400,
      "invalid_route",
    );
    await expectError(
      await upgrade(`/v1/controllers/${randomBase64Url32()}?unexpected=true`),
      400,
      "query_not_allowed",
    );
    await expectError(
      await exports.default.fetch(
        `https://relay.test/v1/turn-credentials/${randomBase64Url32()}`,
      ),
      405,
      "method_not_allowed",
    );
    await expectError(
      await exports.default.fetch(
        new Request(
          `https://relay.test/v1/turn-credentials/${randomBase64Url32()}`,
          { method: "POST" },
        ),
      ),
      401,
      "target_capability_required",
    );
  });

  it("authenticates TURN credentials and reports optional configuration", async () => {
    const unregistered = createRouteCredentials();
    await expectError(
      await exports.default.fetch(
        new Request(
          `https://relay.test/v1/turn-credentials/${unregistered.route}`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${unregistered.capability}`,
            },
          },
        ),
      ),
      403,
      "target_auth_failed",
    );

    const credentials = createRouteCredentials();
    const target = await connectTarget(credentials);
    await target.inbox.nextEnvelope();

    await expectError(
      await exports.default.fetch(
        new Request(
          `https://relay.test/v1/turn-credentials/${credentials.route}`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${randomBase64Url32()}`,
            },
          },
        ),
      ),
      403,
      "target_auth_failed",
    );
    await expectError(
      await exports.default.fetch(
        new Request(
          `https://relay.test/v1/turn-credentials/${credentials.route}`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${credentials.capability}`,
            },
          },
        ),
      ),
      501,
      "turn_not_configured",
    );
    target.inbox.close();
  });

  it("normalizes TURN allocations and removes the timeout-prone port", () => {
    expect(
      normalizeTurnAllocation({
        iceServers: [
          { urls: ["stun:stun.cloudflare.com:3478"] },
          {
            urls: [
              "turn:turn.cloudflare.com:53?transport=udp",
              "turn:turn.cloudflare.com:3478?transport=udp",
              "turns:turn.cloudflare.com:443?transport=tcp",
            ],
            username: "temporary-user",
            credential: "temporary-password",
          },
        ],
      }),
    ).toEqual({
      iceServers: [
        {
          urls: ["stun:stun.cloudflare.com:3478"],
          username: "",
          credential: "",
        },
        {
          urls: [
            "turn:turn.cloudflare.com:3478?transport=udp",
            "turns:turn.cloudflare.com:443?transport=tcp",
          ],
          username: "temporary-user",
          credential: "temporary-password",
        },
      ],
    });
  });

  it("persists only a salted target verifier and authenticates reconnects", async () => {
    const credentials = createRouteCredentials();
    await expectError(
      await upgrade(`/v1/targets/${credentials.route}`),
      401,
      "target_capability_required",
    );

    const target = await connectTarget(credentials);
    expect(await target.inbox.nextEnvelope()).toEqual({
      version: RELAY_PROTOCOL_VERSION,
      kind: RelayFrameKind.Notice,
      connectionId: SYSTEM_CONNECTION_ID,
      message: "target_ready",
    });

    const stub = env.TARGET_RELAY.getByName(credentials.route);
    await runInDurableObject(
      stub,
      (_instance: TargetRelay, state: DurableObjectState) => {
        const registration = state.storage.sql
          .exec<{ salt: string; verifier: string }>(
            "SELECT salt, verifier FROM target_registration WHERE id = 1",
          )
          .one();
        expect(registration.salt).not.toBe(credentials.capability);
        expect(registration.verifier).not.toBe(credentials.capability);
        expect(registration.salt).toMatch(/^[A-Za-z0-9_-]{43}$/u);
        expect(registration.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      },
    );

    target.inbox.close();
    await runInDurableObject(stub, () => undefined);

    const wrong = createRouteCredentials();
    await expectError(
      await upgrade(`/v1/targets/${credentials.route}`, {
        Authorization: `Bearer ${wrong.capability}`,
      }),
      403,
      "target_auth_failed",
    );

    const reconnected = await connectTarget(credentials);
    const ready = await reconnected.inbox.nextEnvelope();
    expect(ready.kind).toBe(RelayFrameKind.Notice);
    if (ready.kind !== RelayFrameKind.Notice) {
      throw new Error("Reconnected target did not receive a notice.");
    }
    expect(ready.message).toBe("target_ready");
    reconnected.inbox.close();
  });

  it("attaches a controller and emits an exact target open envelope", async () => {
    const pair = await connectPair();
    expect(pair.connectionId).toBeGreaterThan(0);
    await expect(pair.controller.nextBinary(75)).rejects.toThrow(
      "Timed out waiting for WebSocket message.",
    );

    const stub = env.TARGET_RELAY.getByName(pair.credentials.route);
    await runInDurableObject(
      stub,
      (_instance: TargetRelay, state: DurableObjectState) => {
        const reconstructed = reconstructSocketState(state.getWebSockets());
        expect(reconstructed.target).not.toBeNull();
        expect([...reconstructed.controllers.keys()]).toEqual([
          pair.connectionId,
        ]);
        expect(reconstructed.invalid).toHaveLength(0);
      },
    );

    pair.target.close();
    pair.controller.close();
  });

  it("uses the fixed Rust-facing v1 envelope header", () => {
    const frame = encodeData(0x1020_3040, Uint8Array.from([9, 8, 7]));
    const view = new DataView(frame.buffer);
    expect(frame.byteLength).toBe(TARGET_ENVELOPE_HEADER_BYTES + 3);
    expect(view.getUint8(0)).toBe(1);
    expect(view.getUint8(1)).toBe(RelayFrameKind.Data);
    expect(view.getUint32(2, false)).toBe(0x1020_3040);
    expect(view.getUint32(6, false)).toBe(3);
    expect([...frame.slice(TARGET_ENVELOPE_HEADER_BYTES)]).toEqual([9, 8, 7]);
  });

  it("wraps controller bytes and unwraps target data without inspection", async () => {
    const pair = await connectPair();
    const controllerPayload = Uint8Array.from([0, 255, 1, 254, 128, 13, 10]);
    pair.controller.send(controllerPayload);

    const targetData = await pair.target.nextEnvelope();
    expect(targetData.kind).toBe(RelayFrameKind.Data);
    if (targetData.kind !== RelayFrameKind.Data) {
      throw new Error("Expected data at target.");
    }
    expect(targetData.connectionId).toBe(pair.connectionId);
    expect([...targetData.payload]).toEqual([...controllerPayload]);

    const targetPayload = Uint8Array.from([9, 8, 7, 0, 6, 5]);
    pair.target.send(encodeData(pair.connectionId, targetPayload));
    expect([...new Uint8Array(await pair.controller.nextBinary())]).toEqual([
      ...targetPayload,
    ]);

    pair.target.close();
    pair.controller.close();
  });

  it("reconstructs routing from socket attachments after hibernation", async () => {
    const pair = await connectPair();
    const stub = env.TARGET_RELAY.getByName(pair.credentials.route);

    await evictDurableObject(stub, { webSockets: "hibernate" });

    const controllerPayload = Uint8Array.from([4, 3, 2, 1]);
    pair.controller.send(controllerPayload);
    const targetData = await pair.target.nextEnvelope();
    expect(targetData.kind).toBe(RelayFrameKind.Data);
    if (targetData.kind !== RelayFrameKind.Data) {
      throw new Error("Expected controller data after eviction.");
    }
    expect([...targetData.payload]).toEqual([...controllerPayload]);

    const targetPayload = Uint8Array.from([1, 2, 3, 4]);
    pair.target.send(encodeData(pair.connectionId, targetPayload));
    expect([...new Uint8Array(await pair.controller.nextBinary())]).toEqual([
      ...targetPayload,
    ]);

    pair.target.close();
    pair.controller.close();
  });

  it("replaces a live target so a half-open socket cannot wedge the route", async () => {
    const credentials = createRouteCredentials();
    const first = await connectTarget(credentials);
    await first.inbox.nextEnvelope();

    // A target that dies without a clean close still reads as open. Refusing
    // the reconnect would lock the only authorized target out of its own
    // route, so an authenticated reconnect has to win.
    const controller = await connectController(credentials.route);
    expect((await first.inbox.nextEnvelope()).kind).toBe(RelayFrameKind.Open);

    const second = await connectTarget(credentials);
    expect((await second.inbox.nextEnvelope()).kind).toBe(
      RelayFrameKind.Notice,
    );
    // The controller survives the handover and is reopened on the new socket.
    expect((await second.inbox.nextEnvelope()).kind).toBe(RelayFrameKind.Open);

    controller.inbox.send(Uint8Array.from([44]));
    expect((await second.inbox.nextEnvelope()).kind).toBe(RelayFrameKind.Data);

    second.inbox.close();
    controller.inbox.close();
  });

  it("rejects controllers while the target is unavailable", async () => {
    const credentials = createRouteCredentials();
    await expectError(
      await upgrade(`/v1/controllers/${credentials.route}`),
      503,
      "target_unavailable",
    );
  });

  it("keeps controller floods out of the target reconnect budget", async () => {
    const credentials = createRouteCredentials();
    const target = await connectTarget(credentials);
    await target.inbox.nextEnvelope();
    for (
      let attempt = 0;
      attempt < MAX_CONNECTION_ATTEMPTS_PER_MINUTE;
      attempt += 1
    ) {
      const controller = await connectController(credentials.route);
      const open = await target.inbox.nextEnvelope();
      expect(open.kind).toBe(RelayFrameKind.Open);
      controller.inbox.close();
      expect((await target.inbox.nextEnvelope()).kind).toBe(
        RelayFrameKind.Close,
      );
    }
    await expectError(
      await upgrade(`/v1/controllers/${credentials.route}`),
      429,
      "connection_rate_limited",
    );

    target.inbox.close();
    const stub = env.TARGET_RELAY.getByName(credentials.route);
    await runInDurableObject(stub, () => undefined);
    const reconnected = await connectTarget(credentials);
    expect((await reconnected.inbox.nextEnvelope()).kind).toBe(
      RelayFrameKind.Notice,
    );
    reconnected.inbox.close();
  });

  it("propagates controller and target closes", async () => {
    const first = await connectPair();
    first.controller.close(1000, "controller_done");
    expect(await first.target.nextEnvelope()).toEqual({
      version: RELAY_PROTOCOL_VERSION,
      kind: RelayFrameKind.Close,
      connectionId: first.connectionId,
      message: "controller_done",
    });
    first.target.close();

    const second = await connectPair();
    second.target.send(encodeClose(second.connectionId, "target_done"));
    const controllerClose = await second.controller.nextClose();
    expect(controllerClose.code).toBe(1000);
    expect(controllerClose.reason).toBe("target_done");
    second.target.close();
  });

  it("rejects nonbinary and oversized controller data", async () => {
    const textPair = await connectPair();
    textPair.controller.send("not-binary");
    expect((await textPair.controller.nextClose()).code).toBe(1003);
    expect(await textPair.target.nextEnvelope()).toMatchObject({
      kind: RelayFrameKind.Close,
      connectionId: textPair.connectionId,
      message: "binary_required",
    });
    textPair.target.close();

    const oversizedPair = await connectPair();
    oversizedPair.controller.send(new Uint8Array(MAX_PAYLOAD_BYTES + 1));
    expect((await oversizedPair.controller.nextClose()).code).toBe(1009);
    expect(await oversizedPair.target.nextEnvelope()).toMatchObject({
      kind: RelayFrameKind.Close,
      connectionId: oversizedPair.connectionId,
      message: "payload_too_large",
    });
    oversizedPair.target.close();
  });

  it("rejects malformed or oversized target envelopes", async () => {
    const malformed = await connectPair();
    malformed.target.send(Uint8Array.from([1, RelayFrameKind.Data]));
    expect(await malformed.target.nextEnvelope()).toMatchObject({
      kind: RelayFrameKind.Notice,
      connectionId: SYSTEM_CONNECTION_ID,
      message: "truncated_frame",
    });
    expect((await malformed.target.nextClose()).code).toBe(4400);
    expect((await malformed.controller.nextClose()).code).toBe(4404);

    const oversized = await connectPair();
    oversized.target.send(
      new Uint8Array(TARGET_ENVELOPE_HEADER_BYTES + MAX_PAYLOAD_BYTES + 1),
    );
    expect(await oversized.target.nextEnvelope()).toMatchObject({
      kind: RelayFrameKind.Notice,
      message: "frame_too_large",
    });
    expect((await oversized.target.nextClose()).code).toBe(1009);
    expect((await oversized.controller.nextClose()).code).toBe(4404);
  });

  it("enforces the per-target controller limit", async () => {
    const credentials = createRouteCredentials();
    const target = await connectTarget(credentials);
    await target.inbox.nextEnvelope();
    const controllers: SocketInbox[] = [];

    for (let index = 0; index < MAX_CONTROLLERS; index += 1) {
      const controller = await connectController(credentials.route);
      controllers.push(controller.inbox);
      expect((await target.inbox.nextEnvelope()).kind).toBe(
        RelayFrameKind.Open,
      );
    }

    await expectError(
      await upgrade(`/v1/controllers/${credentials.route}`),
      429,
      "controller_limit_reached",
    );

    target.inbox.close();
    for (const controller of controllers) {
      controller.close();
    }
  });

  it("isolates traffic between target routes", async () => {
    const first = await connectPair();
    const second = await connectPair();

    first.controller.send(Uint8Array.from([91, 92, 93]));
    const firstData = await first.target.nextEnvelope();
    expect(firstData.kind).toBe(RelayFrameKind.Data);
    await expect(second.target.nextEnvelope(75)).rejects.toThrow(
      "Timed out waiting for WebSocket message.",
    );

    second.controller.send(Uint8Array.from([12]));
    expect((await second.target.nextEnvelope()).kind).toBe(RelayFrameKind.Data);

    first.target.close();
    first.controller.close();
    second.target.close();
    second.controller.close();
  });
});

async function connectPair(): Promise<{
  credentials: RouteCredentials;
  target: SocketInbox;
  controller: SocketInbox;
  connectionId: number;
}> {
  const credentials = createRouteCredentials();
  const target = await connectTarget(credentials);
  expect(await target.inbox.nextEnvelope()).toEqual({
    version: RELAY_PROTOCOL_VERSION,
    kind: RelayFrameKind.Notice,
    connectionId: SYSTEM_CONNECTION_ID,
    message: "target_ready",
  });

  const controller = await connectController(credentials.route);
  const open = await target.inbox.nextEnvelope();
  if (open.kind !== RelayFrameKind.Open) {
    throw new Error("Target did not receive a controller open envelope.");
  }

  return {
    credentials,
    target: target.inbox,
    controller: controller.inbox,
    connectionId: open.connectionId,
  };
}

async function connectTarget(
  credentials: RouteCredentials,
): Promise<ConnectedSocket> {
  return connect(`/v1/targets/${credentials.route}`, {
    Authorization: `Bearer ${credentials.capability}`,
  });
}

async function connectController(route: string): Promise<ConnectedSocket> {
  return connect(`/v1/controllers/${route}`);
}

async function connect(
  path: string,
  headers: Record<string, string> = {},
): Promise<ConnectedSocket> {
  const response = await upgrade(path, headers);
  expect(response.status).toBe(101);
  if (response.webSocket === null) {
    throw new Error("Upgrade response did not include a WebSocket.");
  }

  return {
    response,
    inbox: new SocketInbox(response.webSocket),
  };
}

async function upgrade(
  path: string,
  headers: Record<string, string> = {},
): Promise<Response> {
  return exports.default.fetch(
    new Request(`https://relay.test${path}`, {
      headers: {
        ...headers,
        Upgrade: "websocket",
      },
    }),
  );
}

function createRouteCredentials(): RouteCredentials {
  return {
    route: randomBase64Url32(),
    capability: randomBase64Url32(),
  };
}

function randomBase64Url32(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function expectError(
  response: Response,
  status: number,
  code: string,
): Promise<void> {
  expect(response.status).toBe(status);
  await expect(response.json()).resolves.toMatchObject({
    error: { code },
  });
}
