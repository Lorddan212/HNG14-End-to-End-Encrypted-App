import type {
  AuthResponse,
  ConversationSummary,
  EncryptedPayload,
  MessageResponse,
  SessionTokens,
  TokenResponse,
  UserProfile,
  UserPublicInfo,
  UserPublicKey,
} from "../types";

export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ?? "https://whisperbox.koyeb.app"
).replace(/\/$/, "");

interface RegisterPayload {
  username: string;
  display_name: string;
  password: string;
  public_key: string;
  wrapped_private_key: string;
  pbkdf2_salt: string;
}

interface RequestOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  auth?: boolean;
  retryOnAuth?: boolean;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class WhisperApi {
  private tokens: SessionTokens | null = null;

  constructor(private readonly onTokensChanged?: (tokens: SessionTokens) => void) {}

  setTokens(tokens: SessionTokens | null) {
    this.tokens = tokens;
  }

  async register(payload: RegisterPayload): Promise<AuthResponse> {
    return this.request<AuthResponse>("/auth/register", {
      method: "POST",
      body: payload,
      auth: false,
    });
  }

  async login(username: string, password: string): Promise<AuthResponse> {
    return this.request<AuthResponse>("/auth/login", {
      method: "POST",
      body: { username, password },
      auth: false,
    });
  }

  async me(): Promise<UserProfile> {
    return this.request<UserProfile>("/auth/me");
  }

  async logout(refreshToken: string): Promise<void> {
    await this.request("/auth/logout", {
      method: "POST",
      body: { refresh_token: refreshToken },
    });
  }

  async searchUsers(query: string): Promise<UserPublicInfo[]> {
    return this.request<UserPublicInfo[]>(
      `/users/search?q=${encodeURIComponent(query)}`,
    );
  }

  async getPublicKey(userId: string): Promise<string> {
    const response = await this.request<UserPublicKey>(
      `/users/${encodeURIComponent(userId)}/public-key`,
    );

    return response.public_key;
  }

  async listConversations(): Promise<ConversationSummary[]> {
    return this.request<ConversationSummary[]>("/conversations");
  }

  async getMessages(userId: string, limit = 50): Promise<MessageResponse[]> {
    return this.request<MessageResponse[]>(
      `/conversations/${encodeURIComponent(userId)}/messages?limit=${limit}`,
    );
  }

  async sendMessage(to: string, payload: EncryptedPayload): Promise<MessageResponse> {
    return this.request<MessageResponse>("/messages", {
      method: "POST",
      body: { to, payload },
    });
  }

  private async request<T = unknown>(
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    const headers = new Headers(options.headers);
    const needsAuth = options.auth !== false;

    if (options.body !== undefined && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    if (needsAuth && this.tokens?.accessToken) {
      headers.set("Authorization", `Bearer ${this.tokens.accessToken}`);
    }

    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
      body:
        options.body === undefined || typeof options.body === "string"
          ? (options.body as BodyInit | undefined)
          : JSON.stringify(options.body),
    });

    if (
      response.status === 401 &&
      needsAuth &&
      options.retryOnAuth !== false &&
      this.tokens?.refreshToken
    ) {
      await this.refreshAccessToken();

      return this.request<T>(path, { ...options, retryOnAuth: false });
    }

    if (!response.ok) {
      throw await toApiError(response);
    }

    if (response.status === 204) {
      return undefined as T;
    }

    return parseResponse<T>(response);
  }

  private async refreshAccessToken() {
    if (!this.tokens?.refreshToken) {
      throw new ApiError("Session expired. Please sign in again.", 401);
    }

    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: this.tokens.refreshToken }),
    });

    if (!response.ok) {
      throw await toApiError(response);
    }

    const payload = await parseResponse<TokenResponse>(response);
    const tokens: SessionTokens = {
      accessToken: payload.access_token,
      refreshToken: this.tokens.refreshToken,
      expiresAt: Date.now() + payload.expires_in * 1000,
    };

    this.tokens = tokens;
    this.onTokensChanged?.(tokens);
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type") ?? "";

  if (contentType.includes("application/json")) {
    return response.json() as Promise<T>;
  }

  return (await response.text()) as T;
}

async function toApiError(response: Response): Promise<ApiError> {
  const payload = await parseResponse<unknown>(response).catch(() => null);
  let message = `Request failed with ${response.status}`;

  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail?: unknown }).detail;

    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail)) {
      message = detail
        .map((item) =>
          item && typeof item === "object" && "msg" in item
            ? String((item as { msg: unknown }).msg)
            : "Validation error",
        )
        .join(", ");
    }
  }

  return new ApiError(message, response.status, payload);
}
