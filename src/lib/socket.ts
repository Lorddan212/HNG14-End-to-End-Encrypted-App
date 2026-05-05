import { API_BASE_URL } from "./api";
import type { EncryptedPayload, MessageResponse } from "../types";

export type SocketStatus = "idle" | "connecting" | "open" | "closed" | "error";

export function websocketUrl(accessToken: string): string {
  const url = new URL(API_BASE_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws";
  url.search = "";
  url.searchParams.set("token", accessToken);
  return url.toString();
}

export function buildSendFrame(to: string, payload: EncryptedPayload): string {
  return JSON.stringify({
    type: "message.send",
    to,
    payload
  });
}

export function extractMessageFromFrame(raw: MessageEvent<string>): MessageResponse | null {
  let frame: unknown;

  try {
    frame = JSON.parse(raw.data);
  } catch {
    return null;
  }

  if (!frame || typeof frame !== "object") {
    return null;
  }

  const record = frame as Record<string, unknown>;
  const candidates = [
    record.message,
    record.data,
    record.payload,
    record
  ];

  for (const candidate of candidates) {
    if (isMessageResponse(candidate)) {
      return candidate;
    }
  }

  return null;
}

function isMessageResponse(value: unknown): value is MessageResponse {
  if (!value || typeof value !== "object") {
    return false;
  }

  const message = value as Record<string, unknown>;
  return (
    typeof message.id === "string" &&
    typeof message.from_user_id === "string" &&
    typeof message.to_user_id === "string" &&
    typeof message.created_at === "string" &&
    typeof message.delivered === "boolean" &&
    typeof message.payload === "object" &&
    message.payload !== null
  );
}
