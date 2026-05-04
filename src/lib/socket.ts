import { API_BASE_URL } from "./api";
import type { EncryptedPayload, MessageResponse } from "../types";

export type SocketStatus = "connecting" | "open" | "closed" | "error";

interface SocketHandlers {
  accessToken: string;
  onStatus: (status: SocketStatus) => void;
  onMessage: (message: MessageResponse) => void;
  onError: (message: string) => void;
}

export interface WhisperSocket {
  sendEncryptedMessage: (to: string, payload: EncryptedPayload) => boolean;
  close: () => void;
}

export function connectWhisperSocket({
  accessToken,
  onStatus,
  onMessage,
  onError,
}: SocketHandlers): WhisperSocket {
  const ws = new WebSocket(buildSocketUrl(accessToken));

  onStatus("connecting");

  ws.onopen = () => onStatus("open");
  ws.onclose = () => onStatus("closed");
  ws.onerror = () => {
    onStatus("error");
    onError("Real-time channel unavailable. REST fallback will be used.");
  };
  ws.onmessage = (event) => {
    try {
      const frame = JSON.parse(event.data as string) as unknown;
      const message = extractMessage(frame);

      if (message) {
        onMessage(message);
      }
    } catch {
      onError("Received an unreadable WebSocket frame.");
    }
  };

  return {
    sendEncryptedMessage(to, payload) {
      if (ws.readyState !== WebSocket.OPEN) {
        return false;
      }

      ws.send(JSON.stringify({ type: "message.send", to, payload }));
      return true;
    },
    close() {
      ws.close();
    },
  };
}

function buildSocketUrl(accessToken: string): string {
  const url = new URL(API_BASE_URL);

  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws";
  url.search = "";
  url.searchParams.set("token", accessToken);

  return url.toString();
}

function extractMessage(frame: unknown): MessageResponse | null {
  if (isMessageResponse(frame)) {
    return frame;
  }
  if (!frame || typeof frame !== "object") {
    return null;
  }

  const value = frame as Record<string, unknown>;
  const candidates = [
    value.message,
    value.data,
    value.payload,
    value.type === "message.receive" ? value.message : null,
  ];

  for (const candidate of candidates) {
    if (isMessageResponse(candidate)) {
      return candidate;
    }
  }

  return null;
}

function isMessageResponse(value: unknown): value is MessageResponse {
  return Boolean(
    value &&
      typeof value === "object" &&
      "id" in value &&
      "from_user_id" in value &&
      "to_user_id" in value &&
      "payload" in value,
  );
}
