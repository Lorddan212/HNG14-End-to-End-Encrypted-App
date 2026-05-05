import type {
  AuthResponse,
  ConversationSummary,
  EncryptedPayload,
  MessageResponse,
  SessionSnapshot,
  TokenResponse,
  UserProfile,
  UserPublicInfo,
  UserPublicKey
} from "../types";

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "https://whisperbox.koyeb.app";

type SessionReader = () => SessionSnapshot | null;
type SessionWriter = (session: SessionSnapshot) => void;
type SessionClearer = () => void;

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class WhisperApi {
  private refreshPromise: Promise<TokenResponse> | null = null;

  constructor(
    private readonly readSession: SessionReader,
    private readonly writeSession: SessionWriter,
    private readonly clearSession: SessionClearer
  ) {}

  async register(input: {
    username: string;
    display_name: string;
    password: string;
    public_key: string;
    wrapped_private_key: string;
    pbkdf2_salt: string;
  }): Promise<AuthResponse> {
    return this.publicRequest<AuthResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  async login(input: {
    username: string;
    password: string;
  }): Promise<AuthResponse> {
    return this.publicRequest<AuthResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  async me(): Promise<UserProfile> {
    return this.request<UserProfile>("/auth/me");
  }

  async searchUsers(query: string): Promise<UserPublicInfo[]> {
    return this.request<UserPublicInfo[]>(
      `/users/search?q=${encodeURIComponent(query)}`
    );
  }

  async getUserPublicKey(userId: string): Promise<UserPublicKey> {
    return this.request<UserPublicKey>(
      `/users/${encodeURIComponent(userId)}/public-key`
    );
  }

  async listConversations(): Promise<ConversationSummary[]> {
    return this.request<ConversationSummary[]>("/conversations");
  }

  async getMessages(
    userId: string,
    limit = 50,
    before?: string
  ): Promise<MessageResponse[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (before) {
      params.set("before", before);
    }

    return this.request<MessageResponse[]>(
      `/conversations/${encodeURIComponent(userId)}/messages?${params}`
    );
  }

  async sendMessage(
    to: string,
    payload: EncryptedPayload
  ): Promise<MessageResponse> {
    return this.request<MessageResponse>("/messages", {
      method: "POST",
      body: JSON.stringify({ to, payload })
    });
  }

  async logout(refreshToken: string): Promise<void> {
    await this.request<Record<string, unknown>>("/auth/logout", {
      method: "POST",
      body: JSON.stringify({ refresh_token: refreshToken })
    });
  }

  private async publicRequest<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    return this.fetchJson<T>(path, options);
  }

  private async request<T>(
    path: string,
    options: RequestInit = {},
    retryOnUnauthorized = true
  ): Promise<T> {
    const session = this.readSession();
    const response = await this.fetchRaw(path, {
      ...options,
      headers: {
        ...this.defaultHeaders(),
        ...(options.headers ?? {}),
        ...(session ? { Authorization: `Bearer ${session.accessToken}` } : {})
      }
    });

    if (response.status === 401 && retryOnUnauthorized && session?.refreshToken) {
      try {
        const tokenResponse = await this.refreshAccessToken(session.refreshToken);
        this.writeSession({
          ...session,
          accessToken: tokenResponse.access_token,
          expiresAt: Date.now() + tokenResponse.expires_in * 1000
        });
        return this.request<T>(path, options, false);
      } catch (error) {
        this.clearSession();
        throw error;
      }
    }

    return this.parseResponse<T>(response);
  }

  private async refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
    if (!this.refreshPromise) {
      this.refreshPromise = this.publicRequest<TokenResponse>("/auth/refresh", {
        method: "POST",
        body: JSON.stringify({ refresh_token: refreshToken })
      }).finally(() => {
        this.refreshPromise = null;
      });
    }

    return this.refreshPromise;
  }

  private async fetchJson<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const response = await this.fetchRaw(path, {
      ...options,
      headers: {
        ...this.defaultHeaders(),
        ...(options.headers ?? {})
      }
    });
    return this.parseResponse<T>(response);
  }

  private fetchRaw(path: string, options: RequestInit): Promise<Response> {
    return fetch(`${API_BASE_URL}${path}`, options);
  }

  private defaultHeaders(): HeadersInit {
    return {
      "Content-Type": "application/json",
      Accept: "application/json"
    };
  }

  private async parseResponse<T>(response: Response): Promise<T> {
    if (response.status === 204) {
      return undefined as T;
    }

    const text = await response.text();
    const data = text ? safeJsonParse(text) : null;

    if (!response.ok) {
      throw new ApiError(
        extractErrorMessage(data) ?? response.statusText,
        response.status,
        data
      );
    }

    return data as T;
  }
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function extractErrorMessage(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  const data = payload as Record<string, unknown>;
  if (typeof data.detail === "string") {
    return data.detail;
  }

  if (Array.isArray(data.detail) && data.detail.length > 0) {
    const first = data.detail[0] as Record<string, unknown>;
    if (typeof first.msg === "string") {
      return first.msg;
    }
  }

  return null;
}
