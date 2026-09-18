import { DurableObject } from "cloudflare:workers";

import {
  createRegistrationVerifier,
  parseTargetCapability,
  verifyRegistrationCapability,
  type RegistrationVerifier,
} from "./auth";
import {
  CLOSE_CODE_DELIVERY_FAILED,
  CLOSE_CODE_INTERNAL_ERROR,
  CLOSE_CODE_PROTOCOL_ERROR,
  CLOSE_CODE_TARGET_UNAVAILABLE,
  MAX_CONNECTION_ATTEMPTS_PER_MINUTE,
  MAX_CONNECTION_ID,
  MAX_CONTROLLERS,
  MAX_PAYLOAD_BYTES,
  MAX_TARGET_CONNECTION_ATTEMPTS_PER_MINUTE,
  MAX_TARGET_FRAME_BYTES,
  MAX_TURN_CREDENTIAL_REQUESTS_PER_MINUTE,
  MIN_CONNECTION_ID,
  RELAY_PROTOCOL_VERSION,
  SYSTEM_CONNECTION_ID,
} from "./config";
import { errorResponse } from "./http";
import {
  decodeTargetEnvelope,
  encodeClose,
  encodeData,
  encodeNotice,
  encodeOpen,
  isValidConnectionId,
  RelayFrameKind,
  RelayProtocolError,
  type TargetEnvelope,
} from "./protocol";
import { TURN_QUOTA_SINGLETON } from "./quota";
import { parseRelayUpgrade, type RelayRole } from "./routing";
import { generateTurnAllocation } from "./turn";

interface SocketAttachment {
  version: typeof RELAY_PROTOCOL_VERSION;
  role: RelayRole;
  connectionId: number;
}

interface TargetRegistrationRow
  extends Record<string, SqlStorageValue> {
  salt: string;
  verifier: string;
}

type AuthorizationResult = "authorized" | "denied" | "invalid_metadata";

export interface ReconstructedSocketState {
  target: WebSocket | null;
  controllers: Map<number, WebSocket>;
  invalid: WebSocket[];
}

export class TargetRelay extends DurableObject<Env> {
  private target: WebSocket | null;
  private readonly controllers: Map<number, WebSocket>;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);

    const reconstructed = reconstructSocketState(this.ctx.getWebSockets());
    this.target = reconstructed.target;
    this.controllers = reconstructed.controllers;
    for (const socket of reconstructed.invalid) {
      closeSocket(socket, CLOSE_CODE_INTERNAL_ERROR, "invalid_attachment");
    }

    void this.ctx.blockConcurrencyWhile(() => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS target_registration (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          salt TEXT NOT NULL,
          verifier TEXT NOT NULL
        )
      `);
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS relay_connection_attempts (
          window_start INTEGER PRIMARY KEY,
          count INTEGER NOT NULL CHECK (count > 0)
        )
      `);
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS relay_target_connection_attempts (
          window_start INTEGER PRIMARY KEY,
          count INTEGER NOT NULL CHECK (count > 0)
        )
      `);
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS relay_turn_credential_requests (
          window_start INTEGER PRIMARY KEY,
          count INTEGER NOT NULL CHECK (count > 0)
        )
      `);
      return Promise.resolve();
    });
  }

  override async fetch(request: Request): Promise<Response> {
    const upgrade = parseRelayUpgrade(request);
    if (upgrade instanceof Response) {
      return upgrade;
    }

    if (upgrade.role === "target") {
      return this.connectTarget(request, upgrade.route);
    }
    return this.connectController();
  }

  async issueTurnCredentials(
    route: string,
    authorization: string | null,
  ): Promise<Response> {
    const capability = parseTargetCapability(authorization);
    if (capability === null) {
      return errorResponse(
        401,
        "target_capability_required",
        "The TURN credential endpoint requires a valid target capability.",
        { "WWW-Authenticate": "Bearer" },
      );
    }
    const authorizationResult = await this.authorizeExistingTarget(
      route,
      capability,
    );
    if (authorizationResult === "invalid_metadata") {
      console.error({ event: "relay_target_verifier_invalid" });
      return errorResponse(
        500,
        "target_verifier_invalid",
        "The target registration verifier is invalid.",
      );
    }
    if (authorizationResult === "denied") {
      return errorResponse(
        403,
        "target_auth_failed",
        "The target registration capability does not match this route.",
      );
    }
    if (!this.recordTurnCredentialRequest()) {
      return errorResponse(
        429,
        "turn_credential_rate_limited",
        "This target route requested too many TURN credentials.",
        { "Retry-After": "60" },
      );
    }

    const keyId = Reflect.get(this.env, "TURN_KEY_ID") as unknown;
    const apiToken = Reflect.get(
      this.env,
      "TURN_KEY_API_TOKEN",
    ) as unknown;
    if (
      typeof keyId !== "string" ||
      keyId === "" ||
      typeof apiToken !== "string" ||
      apiToken === ""
    ) {
      return errorResponse(
        501,
        "turn_not_configured",
        "This relay does not have Cloudflare TURN configured.",
      );
    }

    // Monthly TURN egress ceiling. The relay never sees TURN traffic, so this
    // is a circuit breaker over measured analytics rather than a hard byte cap.
    const quota = await this.env.TURN_QUOTA.getByName(
      TURN_QUOTA_SINGLETON,
    ).evaluate();
    if (!quota.allowed) {
      console.error({
        event: "turn_credential_budget_denied",
        quota_state: quota.state,
      });
      if (quota.state === "not_configured") {
        return errorResponse(
          501,
          "turn_not_configured",
          "This relay does not have TURN usage accounting configured.",
        );
      }
      return errorResponse(
        503,
        "turn_budget_exhausted",
        "The relay TURN egress budget is unavailable or spent.",
        { "Retry-After": "900" },
      );
    }

    try {
      const allocations = await Promise.all([
        generateTurnAllocation(keyId, apiToken),
        generateTurnAllocation(keyId, apiToken),
      ]);
      return Response.json(
        { allocations },
        {
          headers: {
            "Cache-Control": "no-store",
          },
        },
      );
    } catch (error) {
      console.error({
        event: "turn_credential_broker_failed",
        error_type:
          error instanceof Error ? error.name : typeof error,
      });
      return errorResponse(
        502,
        "turn_credential_generation_failed",
        "The relay could not generate temporary TURN credentials.",
      );
    }
  }

  override webSocketMessage(
    ws: WebSocket,
    message: ArrayBuffer | string,
  ): void {
    const attachment = parseSocketAttachment(ws.deserializeAttachment());
    if (attachment === null) {
      closeSocket(ws, CLOSE_CODE_INTERNAL_ERROR, "invalid_attachment");
      return;
    }

    if (attachment.role === "controller") {
      this.handleControllerMessage(ws, attachment, message);
    } else {
      this.handleTargetMessage(ws, message);
    }
  }

  override webSocketClose(
    ws: WebSocket,
    _code: number,
    reason: string,
  ): void {
    const attachment = parseSocketAttachment(ws.deserializeAttachment());
    if (attachment === null) {
      return;
    }

    if (attachment.role === "target") {
      this.removeTarget(ws, false);
    } else {
      this.removeController(
        attachment.connectionId,
        ws,
        false,
        true,
        reason,
      );
    }
  }

  override webSocketError(ws: WebSocket, error: unknown): void {
    const attachment = parseSocketAttachment(ws.deserializeAttachment());
    console.error({
      event: "relay_websocket_error",
      role: attachment?.role ?? "unknown",
      error_type: error instanceof Error ? error.name : typeof error,
    });

    if (attachment === null) {
      return;
    }
    if (attachment.role === "target") {
      this.removeTarget(ws, false);
    } else {
      this.removeController(
        attachment.connectionId,
        ws,
        false,
        true,
        "socket_error",
      );
    }
  }

  private async connectTarget(
    request: Request,
    route: string,
  ): Promise<Response> {
    const capability = parseTargetCapability(
      request.headers.get("Authorization"),
    );
    if (capability === null) {
      return errorResponse(
        401,
        "target_capability_required",
        "The target endpoint requires a valid bearer capability.",
        { "WWW-Authenticate": "Bearer" },
      );
    }

    const authorization = await this.authorizeTarget(route, capability);
    if (authorization === "invalid_metadata") {
      console.error({ event: "relay_target_verifier_invalid" });
      return errorResponse(
        500,
        "target_verifier_invalid",
        "The target registration verifier is invalid.",
      );
    }
    if (authorization === "denied") {
      return errorResponse(
        403,
        "target_auth_failed",
        "The target registration capability does not match this route.",
      );
    }
    if (!this.recordTargetConnectionAttempt()) {
      return errorResponse(
        429,
        "target_connection_rate_limited",
        "This target route has too many authenticated target connection attempts.",
        { "Retry-After": "60" },
      );
    }

    const currentTarget = this.getOpenTarget();
    if (currentTarget !== null) {
      return errorResponse(
        409,
        "target_already_connected",
        "A target is already connected for this route.",
      );
    }

    const { client, server } = createSocketPair();
    const attachment = createSocketAttachment(
      "target",
      SYSTEM_CONNECTION_ID,
    );
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment(attachment);
    this.target = server;

    if (
      !this.sendFrame(
        server,
        encodeNotice(SYSTEM_CONNECTION_ID, "target_ready"),
        "target",
      )
    ) {
      this.removeTarget(server, true);
      return websocketResponse(client);
    }

    for (const connectionId of this.controllers.keys()) {
      if (
        !this.sendFrame(server, encodeOpen(connectionId), "target")
      ) {
        this.removeTarget(server, true);
        break;
      }
    }

    return websocketResponse(client);
  }

  private connectController(): Response {
    const target = this.getOpenTarget();
    if (target === null) {
      return errorResponse(
        503,
        "target_unavailable",
        "The target is not connected.",
        { "Retry-After": "1" },
      );
    }

    this.pruneClosedControllers();
    if (this.controllers.size >= MAX_CONTROLLERS) {
      return errorResponse(
        429,
        "controller_limit_reached",
        "This target route has reached its controller limit.",
      );
    }
    if (!this.recordControllerConnectionAttempt()) {
      return errorResponse(
        429,
        "connection_rate_limited",
        "This target route has too many controller connection attempts.",
        { "Retry-After": "60" },
      );
    }

    const { client, server } = createSocketPair();
    const connectionId = this.createConnectionId();
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment(
      createSocketAttachment("controller", connectionId),
    );
    this.controllers.set(connectionId, server);

    if (!this.sendFrame(target, encodeOpen(connectionId), "target")) {
      this.removeTarget(target, true);
      this.removeController(
        connectionId,
        server,
        true,
        false,
        "target_unavailable",
      );
    }

    return websocketResponse(client);
  }

  private handleControllerMessage(
    ws: WebSocket,
    attachment: SocketAttachment,
    message: ArrayBuffer | string,
  ): void {
    if (typeof message === "string") {
      this.rejectController(
        ws,
        attachment.connectionId,
        1003,
        "binary_required",
      );
      return;
    }
    if (message.byteLength > MAX_PAYLOAD_BYTES) {
      this.rejectController(
        ws,
        attachment.connectionId,
        1009,
        "payload_too_large",
      );
      return;
    }

    const target = this.getOpenTarget();
    if (target === null) {
      this.removeController(
        attachment.connectionId,
        ws,
        true,
        false,
        "target_unavailable",
        CLOSE_CODE_TARGET_UNAVAILABLE,
      );
      return;
    }

    const payload = new Uint8Array(message);
    if (
      !this.sendFrame(
        target,
        encodeData(attachment.connectionId, payload),
        "target",
      )
    ) {
      this.removeTarget(target, true);
    }
  }

  private handleTargetMessage(
    ws: WebSocket,
    message: ArrayBuffer | string,
  ): void {
    if (typeof message === "string") {
      this.rejectTarget(ws, "binary_required", 1003);
      return;
    }
    if (message.byteLength > MAX_TARGET_FRAME_BYTES) {
      this.rejectTarget(ws, "frame_too_large", 1009);
      return;
    }

    let envelope: TargetEnvelope;
    try {
      envelope = decodeTargetEnvelope(message);
    } catch (error) {
      if (error instanceof RelayProtocolError) {
        this.rejectTarget(ws, error.code, CLOSE_CODE_PROTOCOL_ERROR);
        return;
      }
      throw error;
    }

    if (
      envelope.kind !== RelayFrameKind.Data &&
      envelope.kind !== RelayFrameKind.Close
    ) {
      this.rejectTarget(
        ws,
        "frame_kind_not_allowed",
        CLOSE_CODE_PROTOCOL_ERROR,
      );
      return;
    }
    if (envelope.connectionId === SYSTEM_CONNECTION_ID) {
      this.rejectTarget(
        ws,
        "invalid_connection_id",
        CLOSE_CODE_PROTOCOL_ERROR,
      );
      return;
    }

    const controller = this.controllers.get(envelope.connectionId);
    if (controller === undefined || !isOpen(controller)) {
      if (controller !== undefined) {
        this.controllers.delete(envelope.connectionId);
      }
      this.notifyTarget(
        envelope.connectionId,
        "controller_not_found",
      );
      return;
    }

    if (envelope.kind === RelayFrameKind.Data) {
      if (!this.sendFrame(controller, envelope.payload, "controller")) {
        this.removeController(
          envelope.connectionId,
          controller,
          true,
          true,
          "delivery_failed",
          CLOSE_CODE_DELIVERY_FAILED,
        );
      }
      return;
    }

    this.removeController(
      envelope.connectionId,
      controller,
      true,
      false,
      envelope.message,
    );
  }

  private rejectController(
    socket: WebSocket,
    connectionId: number,
    closeCode: number,
    reason: string,
  ): void {
    this.removeController(
      connectionId,
      socket,
      true,
      true,
      reason,
      closeCode,
    );
  }

  private rejectTarget(
    socket: WebSocket,
    reason: string,
    closeCode: number,
  ): void {
    this.sendFrame(
      socket,
      encodeNotice(SYSTEM_CONNECTION_ID, reason),
      "target",
    );
    this.removeTarget(socket, true, closeCode, reason);
  }

  private notifyTarget(connectionId: number, message: string): void {
    const target = this.getOpenTarget();
    if (
      target !== null &&
      !this.sendFrame(
        target,
        encodeNotice(connectionId, message),
        "target",
      )
    ) {
      this.removeTarget(target, true);
    }
  }

  private sendFrame(
    socket: WebSocket,
    frame: ArrayBuffer | Uint8Array,
    role: RelayRole,
  ): boolean {
    if (!isOpen(socket)) {
      return false;
    }

    try {
      socket.send(frame);
      return true;
    } catch (error) {
      console.error({
        event: "relay_websocket_send_failed",
        role,
        error_type: error instanceof Error ? error.name : typeof error,
      });
      return false;
    }
  }

  private removeTarget(
    socket: WebSocket,
    close: boolean,
    closeCode = CLOSE_CODE_DELIVERY_FAILED,
    reason = "target_unavailable",
  ): void {
    if (this.target !== socket) {
      return;
    }

    this.target = null;
    if (close) {
      closeSocket(socket, closeCode, reason);
    }

    for (const [connectionId, controller] of [
      ...this.controllers.entries(),
    ]) {
      this.removeController(
        connectionId,
        controller,
        true,
        false,
        "target_unavailable",
        CLOSE_CODE_TARGET_UNAVAILABLE,
      );
    }
  }

  private removeController(
    connectionId: number,
    socket: WebSocket,
    close: boolean,
    notifyTarget: boolean,
    reason: string,
    closeCode = 1000,
  ): void {
    if (this.controllers.get(connectionId) !== socket) {
      return;
    }

    this.controllers.delete(connectionId);
    if (close) {
      closeSocket(socket, closeCode, reason);
    }

    if (notifyTarget) {
      const target = this.getOpenTarget();
      if (
        target !== null &&
        !this.sendFrame(
          target,
          encodeClose(connectionId, reason),
          "target",
        )
      ) {
        this.removeTarget(target, true);
      }
    }
  }

  private getOpenTarget(): WebSocket | null {
    if (this.target !== null && !isOpen(this.target)) {
      this.target = null;
    }
    return this.target;
  }

  private pruneClosedControllers(): void {
    for (const [connectionId, socket] of this.controllers) {
      if (!isOpen(socket)) {
        this.controllers.delete(connectionId);
      }
    }
  }

  private createConnectionId(): number {
    for (;;) {
      const values = crypto.getRandomValues(new Uint32Array(1));
      const connectionId = values[0] ?? SYSTEM_CONNECTION_ID;
      if (
        connectionId >= MIN_CONNECTION_ID &&
        connectionId <= MAX_CONNECTION_ID &&
        !this.controllers.has(connectionId)
      ) {
        return connectionId;
      }
    }
  }

  private async authorizeTarget(
    route: string,
    capability: string,
  ): Promise<AuthorizationResult> {
    let registration = this.readTargetRegistration();
    if (registration === null) {
      const candidate = await createRegistrationVerifier(
        route,
        capability,
      );
      if (candidate === null) {
        return "denied";
      }
      this.ctx.storage.sql.exec(
        `
          INSERT OR IGNORE INTO target_registration (id, salt, verifier)
          VALUES (1, ?, ?)
        `,
        candidate.salt,
        candidate.verifier,
      );
      registration = this.readTargetRegistration();
      if (registration === null) {
        return "invalid_metadata";
      }
    }

    const verified = await verifyRegistrationCapability(
      route,
      capability,
      registration,
    );
    if (verified === null) {
      return "invalid_metadata";
    }
    return verified ? "authorized" : "denied";
  }

  private async authorizeExistingTarget(
    route: string,
    capability: string,
  ): Promise<AuthorizationResult> {
    const registration = this.readTargetRegistration();
    if (registration === null) {
      return "denied";
    }
    const verified = await verifyRegistrationCapability(
      route,
      capability,
      registration,
    );
    if (verified === null) {
      return "invalid_metadata";
    }
    return verified ? "authorized" : "denied";
  }

  private readTargetRegistration(): RegistrationVerifier | null {
    const rows = this.ctx.storage.sql
      .exec<TargetRegistrationRow>(
        "SELECT salt, verifier FROM target_registration WHERE id = 1",
      )
      .toArray();
    return rows[0] ?? null;
  }

  private recordControllerConnectionAttempt(): boolean {
    const windowStart = Math.floor(Date.now() / 60_000);
    this.ctx.storage.sql.exec(
      "DELETE FROM relay_connection_attempts WHERE window_start < ?",
      windowStart - 1,
    );
    const row = this.ctx.storage.sql
      .exec<{ count: number }>(
        `
          INSERT INTO relay_connection_attempts (window_start, count)
          VALUES (?, 1)
          ON CONFLICT(window_start) DO UPDATE SET count = count + 1
          RETURNING count
        `,
        windowStart,
      )
      .one();
    return row.count <= MAX_CONNECTION_ATTEMPTS_PER_MINUTE;
  }

  private recordTargetConnectionAttempt(): boolean {
    const windowStart = Math.floor(Date.now() / 60_000);
    this.ctx.storage.sql.exec(
      "DELETE FROM relay_target_connection_attempts WHERE window_start < ?",
      windowStart - 1,
    );
    const row = this.ctx.storage.sql
      .exec<{ count: number }>(
        `
          INSERT INTO relay_target_connection_attempts (window_start, count)
          VALUES (?, 1)
          ON CONFLICT(window_start) DO UPDATE SET count = count + 1
          RETURNING count
        `,
        windowStart,
      )
      .one();
    return row.count <= MAX_TARGET_CONNECTION_ATTEMPTS_PER_MINUTE;
  }

  private recordTurnCredentialRequest(): boolean {
    const windowStart = Math.floor(Date.now() / 60_000);
    this.ctx.storage.sql.exec(
      "DELETE FROM relay_turn_credential_requests WHERE window_start < ?",
      windowStart - 1,
    );
    const row = this.ctx.storage.sql
      .exec<{ count: number }>(
        `
          INSERT INTO relay_turn_credential_requests (window_start, count)
          VALUES (?, 1)
          ON CONFLICT(window_start) DO UPDATE SET count = count + 1
          RETURNING count
        `,
        windowStart,
      )
      .one();
    return row.count <= MAX_TURN_CREDENTIAL_REQUESTS_PER_MINUTE;
  }
}

export function reconstructSocketState(
  sockets: WebSocket[],
): ReconstructedSocketState {
  let target: WebSocket | null = null;
  const controllers = new Map<number, WebSocket>();
  const invalid: WebSocket[] = [];

  for (const socket of sockets) {
    const attachment = parseSocketAttachment(socket.deserializeAttachment());
    if (attachment === null) {
      invalid.push(socket);
      continue;
    }
    if (attachment.role === "target") {
      if (target === null) {
        target = socket;
      } else {
        invalid.push(socket);
      }
      continue;
    }
    if (controllers.has(attachment.connectionId)) {
      invalid.push(socket);
      continue;
    }
    controllers.set(attachment.connectionId, socket);
  }

  return { target, controllers, invalid };
}

export function parseSocketAttachment(
  value: unknown,
): SocketAttachment | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }

  const record = value as Record<string, unknown>;
  if (
    record.version !== RELAY_PROTOCOL_VERSION ||
    (record.role !== "target" && record.role !== "controller") ||
    typeof record.connectionId !== "number" ||
    !isValidConnectionId(record.connectionId) ||
    (record.role === "target" &&
      record.connectionId !== SYSTEM_CONNECTION_ID) ||
    (record.role === "controller" &&
      record.connectionId < MIN_CONNECTION_ID)
  ) {
    return null;
  }

  return {
    version: RELAY_PROTOCOL_VERSION,
    role: record.role,
    connectionId: record.connectionId,
  };
}

function createSocketAttachment(
  role: RelayRole,
  connectionId: number,
): SocketAttachment {
  return {
    version: RELAY_PROTOCOL_VERSION,
    role,
    connectionId,
  };
}

function createSocketPair(): { client: WebSocket; server: WebSocket } {
  const pair = new WebSocketPair();
  return {
    client: pair[0],
    server: pair[1],
  };
}

function websocketResponse(webSocket: WebSocket): Response {
  return new Response(null, {
    status: 101,
    webSocket,
  });
}

function isOpen(socket: WebSocket): boolean {
  return socket.readyState === WebSocket.OPEN;
}

function closeSocket(socket: WebSocket, code: number, reason: string): void {
  if (socket.readyState !== WebSocket.OPEN) {
    return;
  }

  try {
    socket.close(sanitizeWebSocketCloseCode(code), truncateCloseReason(reason));
  } catch (error) {
    console.error({
      event: "relay_websocket_close_failed",
      error_type: error instanceof Error ? error.name : typeof error,
    });
  }
}

function sanitizeWebSocketCloseCode(code: number): number {
  return (
    code >= 1000 &&
    code <= 4999 &&
    code !== 1004 &&
    code !== 1005 &&
    code !== 1006 &&
    code !== 1015
  )
    ? code
    : CLOSE_CODE_INTERNAL_ERROR;
}

function truncateCloseReason(reason: string): string {
  let result = reason;
  const encoder = new TextEncoder();
  while (encoder.encode(result).byteLength > 123) {
    result = result.slice(0, -1);
  }
  return result;
}
