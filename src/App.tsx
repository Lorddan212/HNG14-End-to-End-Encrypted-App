import { useCallback, useMemo, useRef, useState } from "react";
import AuthScreen from "./components/AuthScreen";
import ChatApp from "./components/ChatApp";
import UnlockScreen from "./components/UnlockScreen";
import { WhisperApi } from "./lib/api";
import { generateUserKeyMaterial, unlockUserCryptoState } from "./lib/crypto";
import {
  authResponseToSession,
  clearSession,
  loadSession,
  saveSession
} from "./lib/session";
import { getWrappedPrivateKey, saveWrappedPrivateKey } from "./lib/vault";
import type { CryptoState, SessionSnapshot } from "./types";

export default function App() {
  const initialSession = loadSession();
  const [session, setSession] = useState<SessionSnapshot | null>(initialSession);
  const [cryptoState, setCryptoState] = useState<CryptoState | null>(null);
  const sessionRef = useRef<SessionSnapshot | null>(initialSession);

  const commitSession = useCallback((nextSession: SessionSnapshot) => {
    sessionRef.current = nextSession;
    setSession(nextSession);
    saveSession(nextSession);
    void saveWrappedPrivateKey(nextSession.user);
  }, []);

  const clearAuthenticatedState = useCallback(() => {
    sessionRef.current = null;
    setSession(null);
    setCryptoState(null);
    clearSession();
  }, []);

  const api = useMemo(
    () => new WhisperApi(() => sessionRef.current, commitSession, clearAuthenticatedState),
    [clearAuthenticatedState, commitSession]
  );

  const handleRegister = useCallback(
    async (input: {
      username: string;
      displayName: string;
      password: string;
    }) => {
      const keyMaterial = await generateUserKeyMaterial(input.password);
      const response = await api.register({
        username: input.username.trim(),
        display_name: input.displayName.trim(),
        password: input.password,
        public_key: keyMaterial.publicKeyBase64,
        wrapped_private_key: keyMaterial.wrappedPrivateKeyBase64,
        pbkdf2_salt: keyMaterial.pbkdf2SaltBase64
      });
      const nextSession = authResponseToSession(response);

      commitSession(nextSession);
      setCryptoState({
        userId: response.user.id,
        privateKey: keyMaterial.privateKey,
        publicKey: keyMaterial.publicKey,
        publicKeyBase64: keyMaterial.publicKeyBase64
      });
    },
    [api, commitSession]
  );

  const handleLogin = useCallback(
    async (input: { username: string; password: string }) => {
      const response = await api.login({
        username: input.username.trim(),
        password: input.password
      });
      const nextCryptoState = await unlockUserCryptoState(
        response.user.id,
        response.user.public_key,
        response.user.wrapped_private_key,
        response.user.pbkdf2_salt,
        input.password
      );

      commitSession(authResponseToSession(response));
      setCryptoState(nextCryptoState);
    },
    [api, commitSession]
  );

  const handleUnlock = useCallback(
    async (password: string) => {
      const currentSession = sessionRef.current;
      if (!currentSession) {
        throw new Error("Your session expired. Please sign in again.");
      }

      const cachedKey = await getWrappedPrivateKey(currentSession.user.id);
      const nextCryptoState = await unlockUserCryptoState(
        currentSession.user.id,
        cachedKey?.publicKey ?? currentSession.user.public_key,
        cachedKey?.wrappedPrivateKey ?? currentSession.user.wrapped_private_key,
        cachedKey?.pbkdf2Salt ?? currentSession.user.pbkdf2_salt,
        password
      );

      setCryptoState(nextCryptoState);
    },
    []
  );

  const handleLogout = useCallback(async () => {
    const currentSession = sessionRef.current;
    clearAuthenticatedState();

    if (currentSession?.refreshToken) {
      try {
        await api.logout(currentSession.refreshToken);
      } catch {
        // Local logout must succeed even if the token is already expired.
      }
    }
  }, [api, clearAuthenticatedState]);

  if (!session) {
    return <AuthScreen onLogin={handleLogin} onRegister={handleRegister} />;
  }

  if (!cryptoState) {
    return (
      <UnlockScreen
        displayName={session.user.display_name}
        username={session.user.username}
        onLogout={handleLogout}
        onUnlock={handleUnlock}
      />
    );
  }

  return (
    <ChatApp
      api={api}
      cryptoState={cryptoState}
      onLogout={handleLogout}
      session={session}
    />
  );
}
