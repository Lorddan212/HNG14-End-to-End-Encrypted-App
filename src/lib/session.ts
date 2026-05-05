import type { AuthResponse, SessionSnapshot, TokenResponse, UserProfile } from "../types";

const SESSION_KEY = "whisperbox.session.v1";

export function authResponseToSession(response: AuthResponse): SessionSnapshot {
  return {
    accessToken: response.access_token,
    refreshToken: response.refresh_token,
    expiresAt: Date.now() + response.expires_in * 1000,
    user: response.user
  };
}

export function applyTokenRefresh(
  session: SessionSnapshot,
  response: TokenResponse
): SessionSnapshot {
  return {
    ...session,
    accessToken: response.access_token,
    expiresAt: Date.now() + response.expires_in * 1000
  };
}

export function saveSession(session: SessionSnapshot): void {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function loadSession(): SessionSnapshot | null {
  const raw = sessionStorage.getItem(SESSION_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as SessionSnapshot;
    if (
      typeof parsed.accessToken !== "string" ||
      typeof parsed.refreshToken !== "string" ||
      typeof parsed.expiresAt !== "number" ||
      !isUserProfile(parsed.user)
    ) {
      clearSession();
      return null;
    }

    return parsed;
  } catch {
    clearSession();
    return null;
  }
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY);
}

function isUserProfile(value: unknown): value is UserProfile {
  if (!value || typeof value !== "object") {
    return false;
  }

  const user = value as Record<string, unknown>;
  return (
    typeof user.id === "string" &&
    typeof user.username === "string" &&
    typeof user.display_name === "string" &&
    typeof user.public_key === "string" &&
    typeof user.wrapped_private_key === "string" &&
    typeof user.pbkdf2_salt === "string"
  );
}
