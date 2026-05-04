import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  KeyRound,
  Loader2,
  Lock,
  LogOut,
  MessageSquarePlus,
  Search,
  Send,
  ShieldCheck,
  Sparkles,
  UserRound,
  Wifi,
  WifiOff,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, WhisperApi } from "./lib/api";
import {
  assertCryptoAvailable,
  decryptMessagePayload,
  encryptMessage,
  fingerprintPublicKey,
  generateUserKeyMaterial,
  unwrapPrivateKey,
} from "./lib/crypto";
import {
  clearTokens,
  loadTokens,
  saveKeyset,
  saveTokens,
} from "./lib/storage";
import {
  connectWhisperSocket,
  SocketStatus,
  WhisperSocket,
} from "./lib/socket";
import type {
  AuthResponse,
  ChatPartner,
  ConversationSummary,
  DecryptedMessage,
  MessageResponse,
  SessionTokens,
  UserProfile,
  UserPublicInfo,
} from "./types";

const MESSAGE_LIMIT = 50;
const MAX_MESSAGE_LENGTH = 4000;

type AuthMode = "login" | "register";

export function App() {
  const [tokens, setTokens] = useState<SessionTokens | null>(() => loadTokens());
  const [user, setUser] = useState<UserProfile | null>(null);
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const [booting, setBooting] = useState(true);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [unlockBusy, setUnlockBusy] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [conversationsLoading, setConversationsLoading] = useState(false);
  const [selectedPartner, setSelectedPartner] = useState<ChatPartner | null>(null);
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [composerValue, setComposerValue] = useState("");
  const [sending, setSending] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UserPublicInfo[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [socketStatus, setSocketStatus] = useState<SocketStatus>("closed");
  const [notice, setNotice] = useState<string | null>(null);
  const [shellError, setShellError] = useState<string | null>(null);
  const [currentFingerprint, setCurrentFingerprint] = useState<string | null>(null);
  const [partnerFingerprint, setPartnerFingerprint] = useState<string | null>(null);
  const [partnerKeyLoading, setPartnerKeyLoading] = useState(false);

  const publicKeyCacheRef = useRef(new Map<string, string>());
  const socketRef = useRef<WhisperSocket | null>(null);
  const nonceIndexRef = useRef(new Map<string, string>());
  const incomingRef = useRef<(message: MessageResponse) => void>(() => undefined);
  const apiRef = useRef<WhisperApi>();

  if (!apiRef.current) {
    apiRef.current = new WhisperApi((nextTokens) => {
      saveTokens(nextTokens);
      setTokens(nextTokens);
    });
  }

  const api = apiRef.current;

  useEffect(() => {
    api.setTokens(tokens);
  }, [api, tokens]);

  const persistAuth = useCallback(
    async (auth: AuthResponse, activePrivateKey: CryptoKey) => {
      const nextTokens: SessionTokens = {
        accessToken: auth.access_token,
        refreshToken: auth.refresh_token,
        expiresAt: Date.now() + auth.expires_in * 1000,
      };

      saveTokens(nextTokens);
      api.setTokens(nextTokens);
      setTokens(nextTokens);
      await saveKeyset(auth.user);
      setUser(auth.user);
      setPrivateKey(activePrivateKey);
      setAuthError(null);
      setUnlockError(null);
      setNotice("Private key unlocked for this session.");
    },
    [api],
  );

  const refreshConversations = useCallback(async () => {
    if (!tokens?.accessToken) {
      return;
    }

    setConversationsLoading(true);
    try {
      setConversations(await api.listConversations());
    } catch (error) {
      setShellError(toFriendlyError(error));
    } finally {
      setConversationsLoading(false);
    }
  }, [api, tokens?.accessToken]);

  useEffect(() => {
    let cancelled = false;

    async function boot() {
      const restored = loadTokens();

      if (!restored) {
        setBooting(false);
        return;
      }

      api.setTokens(restored);
      setTokens(restored);

      try {
        const profile = await api.me();

        if (cancelled) {
          return;
        }

        await saveKeyset(profile);
        setUser(profile);
        setPrivateKey(null);
      } catch (error) {
        clearTokens();
        setTokens(null);
        setAuthError(toFriendlyError(error));
      } finally {
        if (!cancelled) {
          setBooting(false);
        }
      }
    }

    void boot();

    return () => {
      cancelled = true;
    };
  }, [api]);

  useEffect(() => {
    if (user && tokens?.accessToken) {
      void refreshConversations();
    }
  }, [refreshConversations, tokens?.accessToken, user]);

  useEffect(() => {
    let cancelled = false;

    async function updateCurrentFingerprint() {
      if (!user) {
        setCurrentFingerprint(null);
        return;
      }

      try {
        const fingerprint = await fingerprintPublicKey(user.public_key);
        if (!cancelled) {
          setCurrentFingerprint(fingerprint);
        }
      } catch {
        if (!cancelled) {
          setCurrentFingerprint("Unavailable");
        }
      }
    }

    void updateCurrentFingerprint();

    return () => {
      cancelled = true;
    };
  }, [user]);

  const getPublicKey = useCallback(
    async (userId: string) => {
      const cached = publicKeyCacheRef.current.get(userId);
      if (cached) {
        return cached;
      }

      const publicKey = await api.getPublicKey(userId);
      publicKeyCacheRef.current.set(userId, publicKey);

      return publicKey;
    },
    [api],
  );

  useEffect(() => {
    let cancelled = false;

    async function updatePartnerFingerprint() {
      if (!selectedPartner) {
        setPartnerFingerprint(null);
        return;
      }

      setPartnerKeyLoading(true);
      try {
        const publicKey = await getPublicKey(selectedPartner.id);
        const fingerprint = await fingerprintPublicKey(publicKey);

        if (!cancelled) {
          setPartnerFingerprint(fingerprint);
        }
      } catch {
        if (!cancelled) {
          setPartnerFingerprint("Unavailable");
        }
      } finally {
        if (!cancelled) {
          setPartnerKeyLoading(false);
        }
      }
    }

    void updatePartnerFingerprint();

    return () => {
      cancelled = true;
    };
  }, [getPublicKey, selectedPartner]);

  const decryptOneMessage = useCallback(
    async (message: MessageResponse): Promise<DecryptedMessage> => {
      const isOwn = user?.id === message.from_user_id;

      if (!user) {
        return {
          ...message,
          isOwn,
          plaintext: null,
          decryptError: "No authenticated user.",
        };
      }
      if (!privateKey) {
        return {
          ...message,
          isOwn,
          plaintext: null,
          decryptError: "Private key locked.",
        };
      }

      try {
        const decrypted = await decryptMessagePayload(
          message.payload,
          privateKey,
          isOwn ? "self" : "recipient",
        );
        const nonceKey = decrypted.nonce
          ? `${message.from_user_id}:${decrypted.nonce}`
          : null;
        const possibleReplay = nonceKey
          ? Array.from(nonceIndexRef.current.entries()).some(
              ([messageId, knownNonce]) =>
                messageId !== message.id && knownNonce === nonceKey,
            )
          : false;

        if (nonceKey) {
          nonceIndexRef.current.set(message.id, nonceKey);
        }

        return {
          ...message,
          isOwn,
          plaintext: decrypted.plaintext,
          nonce: decrypted.nonce,
          possibleReplay,
        };
      } catch {
        return {
          ...message,
          isOwn,
          plaintext: null,
          decryptError: "Unable to decrypt on this device.",
        };
      }
    },
    [privateKey, user],
  );

  const loadMessages = useCallback(
    async (partner: ChatPartner) => {
      setSelectedPartner(partner);
      setMessagesLoading(true);
      setShellError(null);

      try {
        const history = await api.getMessages(partner.id, MESSAGE_LIMIT);
        const decrypted = await Promise.all(
          history
            .slice()
            .reverse()
            .map((message) => decryptOneMessage(message)),
        );

        setMessages(decrypted);
      } catch (error) {
        setMessages([]);
        setShellError(toFriendlyError(error));
      } finally {
        setMessagesLoading(false);
      }
    },
    [api, decryptOneMessage],
  );

  const processIncoming = useCallback(
    async (message: MessageResponse) => {
      if (!user) {
        return;
      }

      const partnerId =
        message.from_user_id === user.id ? message.to_user_id : message.from_user_id;
      const isCurrentThread = selectedPartner?.id === partnerId;

      void refreshConversations();

      if (!isCurrentThread) {
        setNotice("New encrypted message received.");
        return;
      }

      const decrypted = await decryptOneMessage(message);

      setMessages((current) => {
        if (current.some((item) => item.id === decrypted.id)) {
          return current;
        }

        return [...current, decrypted].sort(
          (a, b) =>
            new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
        );
      });
    },
    [decryptOneMessage, refreshConversations, selectedPartner?.id, user],
  );

  useEffect(() => {
    incomingRef.current = (message) => {
      void processIncoming(message);
    };
  }, [processIncoming]);

  useEffect(() => {
    if (!tokens?.accessToken || !user) {
      return undefined;
    }

    const socket = connectWhisperSocket({
      accessToken: tokens.accessToken,
      onStatus: setSocketStatus,
      onMessage: (message) => incomingRef.current(message),
      onError: setShellError,
    });

    socketRef.current = socket;

    return () => {
      socket.close();
      if (socketRef.current === socket) {
        socketRef.current = null;
      }
    };
  }, [tokens?.accessToken, user]);

  useEffect(() => {
    if (!user || searchQuery.trim().length === 0) {
      setSearchResults([]);
      setSearchLoading(false);
      return undefined;
    }

    let cancelled = false;
    const handle = window.setTimeout(async () => {
      setSearchLoading(true);
      try {
        const results = await api.searchUsers(searchQuery.trim());
        if (!cancelled) {
          setSearchResults(results);
        }
      } catch (error) {
        if (!cancelled) {
          setShellError(toFriendlyError(error));
        }
      } finally {
        if (!cancelled) {
          setSearchLoading(false);
        }
      }
    }, 260);

    return () => {
      cancelled = true;
      window.clearTimeout(handle);
    };
  }, [api, searchQuery, user]);

  const handleLogin = useCallback(
    async (username: string, password: string) => {
      setAuthBusy(true);
      setAuthError(null);

      try {
        assertCryptoAvailable();
        const auth = await api.login(username.trim(), password);
        const activePrivateKey = await unwrapPrivateKey(
          auth.user.wrapped_private_key,
          auth.user.pbkdf2_salt,
          password,
        );

        await persistAuth(auth, activePrivateKey);
      } catch (error) {
        setAuthError(toFriendlyError(error));
      } finally {
        setAuthBusy(false);
      }
    },
    [api, persistAuth],
  );

  const handleRegister = useCallback(
    async (displayName: string, username: string, password: string) => {
      setAuthBusy(true);
      setAuthError(null);

      try {
        assertCryptoAvailable();
        const keyMaterial = await generateUserKeyMaterial(password);
        const auth = await api.register({
          username: username.trim(),
          display_name: displayName.trim(),
          password,
          public_key: keyMaterial.public_key,
          wrapped_private_key: keyMaterial.wrapped_private_key,
          pbkdf2_salt: keyMaterial.pbkdf2_salt,
        });

        await persistAuth(auth, keyMaterial.privateKey);
      } catch (error) {
        setAuthError(toFriendlyError(error));
      } finally {
        setAuthBusy(false);
      }
    },
    [api, persistAuth],
  );

  const handleUnlock = useCallback(
    async (password: string) => {
      if (!user) {
        return;
      }

      setUnlockBusy(true);
      setUnlockError(null);

      try {
        const activePrivateKey = await unwrapPrivateKey(
          user.wrapped_private_key,
          user.pbkdf2_salt,
          password,
        );
        setPrivateKey(activePrivateKey);
        setNotice("Private key unlocked for this session.");

        if (selectedPartner) {
          void loadMessages(selectedPartner);
        }
      } catch {
        setUnlockError("Password could not unlock this private key.");
      } finally {
        setUnlockBusy(false);
      }
    },
    [loadMessages, selectedPartner, user],
  );

  const handleLogout = useCallback(async () => {
    const refreshToken = tokens?.refreshToken;

    socketRef.current?.close();
    socketRef.current = null;

    if (refreshToken) {
      await api.logout(refreshToken).catch(() => undefined);
    }

    clearTokens();
    api.setTokens(null);
    setTokens(null);
    setUser(null);
    setPrivateKey(null);
    setSelectedPartner(null);
    setMessages([]);
    setConversations([]);
    setSearchQuery("");
    setSearchResults([]);
    setNotice(null);
  }, [api, tokens?.refreshToken]);

  const handleSendMessage = useCallback(async () => {
    const text = composerValue.trim();

    if (!selectedPartner || !user) {
      return;
    }
    if (!privateKey) {
      setShellError("Unlock your private key before sending.");
      return;
    }
    if (!text) {
      return;
    }
    if (text.length > MAX_MESSAGE_LENGTH) {
      setShellError(`Message is too long. Keep it under ${MAX_MESSAGE_LENGTH} characters.`);
      return;
    }

    setSending(true);
    setShellError(null);

    try {
      const recipientPublicKey = await getPublicKey(selectedPartner.id);
      const payload = await encryptMessage(text, recipientPublicKey, user.public_key);
      const socketSent =
        socketRef.current?.sendEncryptedMessage(selectedPartner.id, payload) ?? false;
      const response: MessageResponse = socketSent
        ? {
            id: `local-${globalThis.crypto.randomUUID()}`,
            from_user_id: user.id,
            to_user_id: selectedPartner.id,
            payload,
            delivered: true,
            created_at: new Date().toISOString(),
          }
        : await api.sendMessage(selectedPartner.id, payload);
      const optimisticMessage: DecryptedMessage = {
        ...response,
        isOwn: true,
        plaintext: text,
        optimistic: socketSent,
      };

      setMessages((current) => [...current, optimisticMessage]);
      setComposerValue("");
      void refreshConversations();
    } catch (error) {
      setShellError(toFriendlyError(error));
    } finally {
      setSending(false);
    }
  }, [
    api,
    composerValue,
    getPublicKey,
    privateKey,
    refreshConversations,
    selectedPartner,
    user,
  ]);

  const secureContextWarning = useMemo(() => {
    if (globalThis.isSecureContext || location.hostname === "localhost") {
      return null;
    }

    return "Web Crypto requires HTTPS outside localhost.";
  }, []);

  if (booting) {
    return (
      <div className="boot-screen">
        <Loader2 className="spin" aria-hidden="true" />
        <span>Opening WhisperBox</span>
      </div>
    );
  }

  if (!user) {
    return (
      <AuthPanel
        busy={authBusy}
        error={authError ?? secureContextWarning}
        onLogin={handleLogin}
        onRegister={handleRegister}
      />
    );
  }

  return (
    <>
      <MessagingShell
        user={user}
        privateKeyReady={Boolean(privateKey)}
        conversations={conversations}
        conversationsLoading={conversationsLoading}
        selectedPartner={selectedPartner}
        messages={messages}
        messagesLoading={messagesLoading}
        composerValue={composerValue}
        sending={sending}
        searchQuery={searchQuery}
        searchResults={searchResults}
        searchLoading={searchLoading}
        socketStatus={socketStatus}
        notice={notice}
        error={shellError ?? secureContextWarning}
        currentFingerprint={currentFingerprint}
        partnerFingerprint={partnerFingerprint}
        partnerKeyLoading={partnerKeyLoading}
        onClearNotice={() => setNotice(null)}
        onSearchChange={setSearchQuery}
        onSelectPartner={(partner) => {
          setSearchQuery("");
          setNotice(null);
          void loadMessages(partner);
        }}
        onComposerChange={setComposerValue}
        onSend={handleSendMessage}
        onLogout={handleLogout}
      />
      {!privateKey && (
        <UnlockPanel
          user={user}
          busy={unlockBusy}
          error={unlockError}
          onUnlock={handleUnlock}
          onLogout={handleLogout}
        />
      )}
    </>
  );
}

function AuthPanel({
  busy,
  error,
  onLogin,
  onRegister,
}: {
  busy: boolean;
  error: string | null;
  onLogin: (username: string, password: string) => Promise<void>;
  onRegister: (
    displayName: string,
    username: string,
    password: string,
  ) => Promise<void>;
}) {
  const [mode, setMode] = useState<AuthMode>("login");
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (mode === "register") {
      await onRegister(displayName, username, password);
    } else {
      await onLogin(username, password);
    }
  }

  return (
    <main className="auth-screen">
      <section className="auth-panel" aria-labelledby="auth-heading">
        <div className="auth-brand">
          <span className="brand-mark">
            <ShieldCheck size={24} aria-hidden="true" />
          </span>
          <div>
            <h1 id="auth-heading">WhisperBox</h1>
            <p>Client-side encrypted messaging</p>
          </div>
        </div>

        <div className="auth-tabs" role="tablist" aria-label="Authentication mode">
          <button
            className={mode === "login" ? "active" : ""}
            type="button"
            onClick={() => setMode("login")}
          >
            Login
          </button>
          <button
            className={mode === "register" ? "active" : ""}
            type="button"
            onClick={() => setMode("register")}
          >
            Register
          </button>
        </div>

        <form className="auth-form" onSubmit={submit}>
          {mode === "register" && (
            <label>
              <span>Display name</span>
              <input
                autoComplete="name"
                minLength={1}
                maxLength={128}
                onChange={(event) => setDisplayName(event.target.value)}
                required
                value={displayName}
              />
            </label>
          )}
          <label>
            <span>Username</span>
            <input
              autoComplete="username"
              minLength={mode === "register" ? 3 : 1}
              maxLength={32}
              onChange={(event) => setUsername(event.target.value)}
              pattern={mode === "register" ? "[A-Za-z0-9_.-]{3,32}" : undefined}
              required
              value={username}
            />
          </label>
          <label>
            <span>Password</span>
            <input
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              minLength={mode === "register" ? 8 : 1}
              maxLength={128}
              onChange={(event) => setPassword(event.target.value)}
              required
              type="password"
              value={password}
            />
          </label>

          {error && (
            <p className="form-error" role="alert">
              <AlertTriangle size={16} aria-hidden="true" />
              {error}
            </p>
          )}

          <button className="primary-action" disabled={busy} type="submit">
            {busy ? <Loader2 className="spin" size={18} /> : <Lock size={18} />}
            {mode === "register" ? "Create secure account" : "Unlock session"}
          </button>
        </form>
      </section>
      <aside className="auth-proof" aria-label="Security summary">
        <div className="proof-line">
          <KeyRound aria-hidden="true" />
          <span>Private key never leaves this device in plaintext</span>
        </div>
        <div className="proof-line">
          <Lock aria-hidden="true" />
          <span>Messages are sealed before they reach the backend</span>
        </div>
      </aside>
    </main>
  );
}

function UnlockPanel({
  user,
  busy,
  error,
  onUnlock,
  onLogout,
}: {
  user: UserProfile;
  busy: boolean;
  error: string | null;
  onUnlock: (password: string) => Promise<void>;
  onLogout: () => Promise<void>;
}) {
  const [password, setPassword] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onUnlock(password);
  }

  return (
    <div className="unlock-overlay" role="dialog" aria-modal="true">
      <form className="unlock-card" onSubmit={submit}>
        <span className="brand-mark">
          <KeyRound size={24} aria-hidden="true" />
        </span>
        <h2>Private key locked</h2>
        <p>@{user.username}</p>
        <label>
          <span>Password</span>
          <input
            autoComplete="current-password"
            onChange={(event) => setPassword(event.target.value)}
            required
            type="password"
            value={password}
          />
        </label>
        {error && (
          <p className="form-error" role="alert">
            <AlertTriangle size={16} aria-hidden="true" />
            {error}
          </p>
        )}
        <button className="primary-action" disabled={busy} type="submit">
          {busy ? <Loader2 className="spin" size={18} /> : <Lock size={18} />}
          Unlock
        </button>
        <button className="text-action" type="button" onClick={() => void onLogout()}>
          Log out
        </button>
      </form>
    </div>
  );
}

function MessagingShell({
  user,
  privateKeyReady,
  conversations,
  conversationsLoading,
  selectedPartner,
  messages,
  messagesLoading,
  composerValue,
  sending,
  searchQuery,
  searchResults,
  searchLoading,
  socketStatus,
  notice,
  error,
  currentFingerprint,
  partnerFingerprint,
  partnerKeyLoading,
  onClearNotice,
  onSearchChange,
  onSelectPartner,
  onComposerChange,
  onSend,
  onLogout,
}: {
  user: UserProfile;
  privateKeyReady: boolean;
  conversations: ConversationSummary[];
  conversationsLoading: boolean;
  selectedPartner: ChatPartner | null;
  messages: DecryptedMessage[];
  messagesLoading: boolean;
  composerValue: string;
  sending: boolean;
  searchQuery: string;
  searchResults: UserPublicInfo[];
  searchLoading: boolean;
  socketStatus: SocketStatus;
  notice: string | null;
  error: string | null;
  currentFingerprint: string | null;
  partnerFingerprint: string | null;
  partnerKeyLoading: boolean;
  onClearNotice: () => void;
  onSearchChange: (value: string) => void;
  onSelectPartner: (partner: ChatPartner) => void;
  onComposerChange: (value: string) => void;
  onSend: () => Promise<void>;
  onLogout: () => Promise<void>;
}) {
  const searchInputRef = useRef<HTMLInputElement>(null);
  const listItems = searchQuery.trim()
    ? searchResults.map((result) => ({
        id: result.id,
        username: result.username,
        display_name: result.display_name,
      }))
    : conversations.map((conversation) => ({
        id: conversation.user_id,
        username: conversation.username,
        display_name: conversation.display_name,
        last_message_at: conversation.last_message_at,
      }));

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Conversations">
        <div className="brand-row">
          <span className="brand-mark">
            <ShieldCheck size={22} aria-hidden="true" />
          </span>
          <div>
            <strong>WhisperBox</strong>
            <SocketBadge status={socketStatus} />
          </div>
          <button
            className="icon-button"
            onClick={() => void onLogout()}
            title="Log out"
            type="button"
          >
            <LogOut size={18} aria-hidden="true" />
          </button>
        </div>

        <div className="search-field">
          <Search size={17} aria-hidden="true" />
          <input
            ref={searchInputRef}
            aria-label="Search people"
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder="Search people"
            value={searchQuery}
          />
        </div>

        <button
          className="new-message-button"
          onClick={() => searchInputRef.current?.focus()}
          type="button"
        >
          <MessageSquarePlus size={18} aria-hidden="true" />
          New message
        </button>

        <div className="list-header">
          <span>{searchQuery.trim() ? "People" : "Messages"}</span>
          {(searchLoading || conversationsLoading) && (
            <Loader2 className="spin" size={15} aria-hidden="true" />
          )}
        </div>

        <div className="conversation-list">
          {listItems.length === 0 && (
            <div className="empty-list">
              {searchQuery.trim() ? "No matching users" : "No conversations yet"}
            </div>
          )}
          {listItems.map((item) => (
            <ConversationRow
              key={item.id}
              active={selectedPartner?.id === item.id}
              partner={item}
              onSelect={() => onSelectPartner(item)}
            />
          ))}
        </div>

        <div className="profile-strip">
          <Avatar label={user.display_name} />
          <div>
            <strong>{user.display_name}</strong>
            <span>@{user.username}</span>
          </div>
        </div>
      </aside>

      <section className="chat-pane" aria-label="Chat thread">
        {notice && (
          <button className="notice-banner" type="button" onClick={onClearNotice}>
            <Sparkles size={16} aria-hidden="true" />
            {notice}
          </button>
        )}
        {error && (
          <div className="error-banner" role="alert">
            <AlertTriangle size={16} aria-hidden="true" />
            {error}
          </div>
        )}

        {selectedPartner ? (
          <>
            <header className="chat-header">
              <Avatar label={selectedPartner.display_name} />
              <div>
                <h2>{selectedPartner.display_name}</h2>
                <span>@{selectedPartner.username}</span>
              </div>
              <div className="encrypted-chip">
                <Lock size={15} aria-hidden="true" />
                Encrypted
              </div>
            </header>

            <div className="messages-scroll" aria-live="polite">
              {messagesLoading ? (
                <MessageSkeleton />
              ) : messages.length === 0 ? (
                <div className="empty-thread">
                  <Lock size={22} aria-hidden="true" />
                  <strong>No messages here yet</strong>
                  <span>Start with a sealed message.</span>
                </div>
              ) : (
                messages.map((message) => (
                  <MessageBubble key={message.id} message={message} />
                ))
              )}
            </div>

            <footer className="composer">
              <textarea
                aria-label="Message"
                disabled={!privateKeyReady || sending}
                maxLength={MAX_MESSAGE_LENGTH}
                onChange={(event) => onComposerChange(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void onSend();
                  }
                }}
                placeholder={
                  privateKeyReady ? "Message" : "Unlock private key to send"
                }
                rows={1}
                value={composerValue}
              />
              <button
                className="send-button"
                disabled={!privateKeyReady || sending || !composerValue.trim()}
                onClick={() => void onSend()}
                title="Send"
                type="button"
              >
                {sending ? (
                  <Loader2 className="spin" size={18} aria-hidden="true" />
                ) : (
                  <Send size={18} aria-hidden="true" />
                )}
                <span>Send</span>
              </button>
            </footer>
          </>
        ) : (
          <div className="thread-placeholder">
            <span className="brand-mark large">
              <Lock size={30} aria-hidden="true" />
            </span>
            <h2>Select a conversation</h2>
            <p>Search for a person or open an existing encrypted thread.</p>
          </div>
        )}
      </section>

      <aside className="security-panel" aria-label="Security">
        <div className="panel-title">
          <h2>Security</h2>
          <span className={privateKeyReady ? "status-dot ready" : "status-dot"} />
        </div>
        <SecurityRow
          icon={<Lock size={17} />}
          label="Encrypted"
          value={privateKeyReady ? "Ready" : "Locked"}
          tone={privateKeyReady ? "good" : "warn"}
        />
        <SecurityRow
          icon={<KeyRound size={17} />}
          label="Device key"
          value={currentFingerprint ?? "Loading"}
        />
        <SecurityRow
          icon={<UserRound size={17} />}
          label={selectedPartner ? "Peer key" : "Peer"}
          value={
            selectedPartner
              ? partnerKeyLoading
                ? "Loading"
                : partnerFingerprint ?? "Not loaded"
              : "Select chat"
          }
        />
        <div className="security-note">
          <CheckCircle2 size={17} aria-hidden="true" />
          <span>Server receives ciphertext blobs only.</span>
        </div>
        <div className="security-note">
          <Circle size={17} aria-hidden="true" />
          <span>Access tokens are kept in session storage.</span>
        </div>
      </aside>
    </main>
  );
}

function ConversationRow({
  partner,
  active,
  onSelect,
}: {
  partner: ChatPartner;
  active: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      className={`conversation-row ${active ? "active" : ""}`}
      onClick={onSelect}
      type="button"
    >
      <Avatar label={partner.display_name} />
      <span>
        <strong>{partner.display_name}</strong>
        <small>@{partner.username}</small>
      </span>
      {partner.last_message_at && <time>{formatShortTime(partner.last_message_at)}</time>}
    </button>
  );
}

function MessageBubble({ message }: { message: DecryptedMessage }) {
  return (
    <article className={`message-row ${message.isOwn ? "own" : ""}`}>
      <div className={`message-bubble ${message.decryptError ? "failed" : ""}`}>
        <p>{message.plaintext ?? message.decryptError}</p>
        <footer>
          <Lock size={12} aria-hidden="true" />
          <time>{formatShortTime(message.created_at)}</time>
          {message.optimistic && <span>Sending</span>}
          {message.possibleReplay && <span className="replay">Replay?</span>}
        </footer>
      </div>
    </article>
  );
}

function MessageSkeleton() {
  return (
    <div className="message-skeleton" aria-label="Loading messages">
      <span />
      <span />
      <span />
    </div>
  );
}

function SecurityRow({
  icon,
  label,
  value,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone?: "good" | "warn";
}) {
  return (
    <div className="security-row">
      <span className="security-icon">{icon}</span>
      <div>
        <span>{label}</span>
        <strong className={tone}>{value}</strong>
      </div>
    </div>
  );
}

function SocketBadge({ status }: { status: SocketStatus }) {
  const connected = status === "open";
  const label = connected ? "Online" : status === "connecting" ? "Connecting" : "Offline";

  return (
    <span className={`socket-badge ${connected ? "online" : ""}`}>
      {connected ? (
        <Wifi size={13} aria-hidden="true" />
      ) : (
        <WifiOff size={13} aria-hidden="true" />
      )}
      {label}
    </span>
  );
}

function Avatar({ label }: { label: string }) {
  const initials = label
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");

  return <span className="avatar">{initials || "W"}</span>;
}

function formatShortTime(value: string) {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "";
  }

  return new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function toFriendlyError(error: unknown) {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }

  return "Something went wrong. Please try again.";
}
