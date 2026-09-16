import {
  MAX_CONNECTION_ID,
  MAX_CONTROL_PAYLOAD_BYTES,
  MAX_PAYLOAD_BYTES,
  MAX_TARGET_FRAME_BYTES,
  RELAY_PROTOCOL_VERSION,
  TARGET_ENVELOPE_HEADER_BYTES,
} from "./config";

export enum RelayFrameKind {
  Open = 1,
  Data = 2,
  Close = 3,
  Notice = 4,
}

export interface OpenEnvelope {
  version: typeof RELAY_PROTOCOL_VERSION;
  kind: RelayFrameKind.Open;
  connectionId: number;
}

export interface DataEnvelope {
  version: typeof RELAY_PROTOCOL_VERSION;
  kind: RelayFrameKind.Data;
  connectionId: number;
  payload: Uint8Array;
}

export interface CloseEnvelope {
  version: typeof RELAY_PROTOCOL_VERSION;
  kind: RelayFrameKind.Close;
  connectionId: number;
  message: string;
}

export interface NoticeEnvelope {
  version: typeof RELAY_PROTOCOL_VERSION;
  kind: RelayFrameKind.Notice;
  connectionId: number;
  message: string;
}

export type TargetEnvelope =
  | OpenEnvelope
  | DataEnvelope
  | CloseEnvelope
  | NoticeEnvelope;

export class RelayProtocolError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "RelayProtocolError";
  }
}

export function encodeOpen(connectionId: number): Uint8Array {
  return buildEnvelope(RelayFrameKind.Open, connectionId, new Uint8Array());
}

export function encodeData(
  connectionId: number,
  payload: Uint8Array,
): Uint8Array {
  return buildEnvelope(RelayFrameKind.Data, connectionId, payload);
}

export function encodeClose(
  connectionId: number,
  message: string,
): Uint8Array {
  return buildControlEnvelope(RelayFrameKind.Close, connectionId, message);
}

export function encodeNotice(
  connectionId: number,
  message: string,
): Uint8Array {
  return buildControlEnvelope(RelayFrameKind.Notice, connectionId, message);
}

export function decodeTargetEnvelope(frame: ArrayBuffer): TargetEnvelope {
  if (frame.byteLength < TARGET_ENVELOPE_HEADER_BYTES) {
    throw new RelayProtocolError(
      "truncated_frame",
      "Target envelope is shorter than its fixed header.",
    );
  }
  if (frame.byteLength > MAX_TARGET_FRAME_BYTES) {
    throw new RelayProtocolError(
      "frame_too_large",
      "Target envelope exceeds the configured limit.",
    );
  }

  const view = new DataView(frame);
  const version = view.getUint8(0);
  if (version !== RELAY_PROTOCOL_VERSION) {
    throw new RelayProtocolError(
      "unsupported_version",
      "Relay protocol version is not supported.",
    );
  }

  const kind = view.getUint8(1);
  const connectionId = view.getUint32(2, false);
  const payloadLength = view.getUint32(6, false);
  const actualPayloadLength =
    frame.byteLength - TARGET_ENVELOPE_HEADER_BYTES;
  if (payloadLength !== actualPayloadLength) {
    throw new RelayProtocolError(
      "payload_length_mismatch",
      "Target envelope payload length does not match its header.",
    );
  }
  if (payloadLength > MAX_PAYLOAD_BYTES) {
    throw new RelayProtocolError(
      "payload_too_large",
      "Target envelope payload exceeds the configured limit.",
    );
  }

  const payload = new Uint8Array(
    frame.slice(TARGET_ENVELOPE_HEADER_BYTES),
  );
  switch (kind) {
    case 1:
      if (payloadLength !== 0) {
        throw new RelayProtocolError(
          "invalid_open",
          "Open envelopes must have an empty payload.",
        );
      }
      return {
        version: RELAY_PROTOCOL_VERSION,
        kind: RelayFrameKind.Open,
        connectionId,
      };
    case 2:
      return {
        version: RELAY_PROTOCOL_VERSION,
        kind: RelayFrameKind.Data,
        connectionId,
        payload,
      };
    case 3:
      return {
        version: RELAY_PROTOCOL_VERSION,
        kind: RelayFrameKind.Close,
        connectionId,
        message: decodeControlPayload(payload),
      };
    case 4:
      return {
        version: RELAY_PROTOCOL_VERSION,
        kind: RelayFrameKind.Notice,
        connectionId,
        message: decodeControlPayload(payload),
      };
    default:
      throw new RelayProtocolError(
        "unknown_frame_kind",
        "Target envelope kind is not supported.",
      );
  }
}

export function isValidConnectionId(value: number): boolean {
  return (
    Number.isInteger(value) &&
    value >= 0 &&
    value <= MAX_CONNECTION_ID
  );
}

function buildControlEnvelope(
  kind: RelayFrameKind.Close | RelayFrameKind.Notice,
  connectionId: number,
  message: string,
): Uint8Array {
  const payload = new TextEncoder().encode(message);
  if (payload.byteLength > MAX_CONTROL_PAYLOAD_BYTES) {
    throw new RelayProtocolError(
      "control_payload_too_large",
      "Control envelope exceeds the configured limit.",
    );
  }
  return buildEnvelope(kind, connectionId, payload);
}

function buildEnvelope(
  kind: RelayFrameKind,
  connectionId: number,
  payload: Uint8Array,
): Uint8Array {
  if (!isValidConnectionId(connectionId)) {
    throw new RelayProtocolError(
      "invalid_connection_id",
      "Connection id is outside the u32 range.",
    );
  }
  if (payload.byteLength > MAX_PAYLOAD_BYTES) {
    throw new RelayProtocolError(
      "payload_too_large",
      "Target envelope payload exceeds the configured limit.",
    );
  }

  const frame = new Uint8Array(
    TARGET_ENVELOPE_HEADER_BYTES + payload.byteLength,
  );
  const view = new DataView(frame.buffer);
  view.setUint8(0, RELAY_PROTOCOL_VERSION);
  view.setUint8(1, kind);
  view.setUint32(2, connectionId, false);
  view.setUint32(6, payload.byteLength, false);
  frame.set(payload, TARGET_ENVELOPE_HEADER_BYTES);
  return frame;
}

function decodeControlPayload(payload: Uint8Array): string {
  if (payload.byteLength > MAX_CONTROL_PAYLOAD_BYTES) {
    throw new RelayProtocolError(
      "control_payload_too_large",
      "Control envelope exceeds the configured limit.",
    );
  }

  try {
    return new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: false,
    }).decode(payload);
  } catch (error) {
    if (error instanceof TypeError) {
      throw new RelayProtocolError(
        "invalid_control_encoding",
        "Control envelope must contain valid UTF-8.",
      );
    }
    throw error;
  }
}
