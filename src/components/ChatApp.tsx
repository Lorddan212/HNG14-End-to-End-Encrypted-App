import {
  FormEvent,
  KeyboardEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState
} from "react";
import {
  AlertTriangle,
  CheckCheck,
  Loader2,
  LockKeyhole,
  LogOut,
  MessageCircle,
  Search,
  Send,
  ShieldCheck,
  Wifi,
  WifiOff
} from "lucide-react";
import { WhisperApi } from "../lib/api";
import {
  decryptMessagePayload,
  encryptMessagePayload,
  isEncryptedPayload
} from "../lib/crypto";
import {
  buildSendFrame,
  extractMessageFromFrame,
  websocketUrl,
  type SocketStatus
} from "../lib/socket";
import type {
  ChatPartner,
  CryptoState,
  DecryptedMessage,
  MessageResponse,
  SessionSnapshot,
  UserPublicInfo
} from "../types";

type ChatAppProps = {
  api: WhisperApi;
  cryptoState: CryptoState;
  onLogout: () => Promise<void>;
  session: SessionSnapshot;
};

const INITIAL_THREAD_LIMIT = 25;
const SYNC_THREAD_LIMIT = 25;
const FALLBACK_SYNC_INTERVAL_MS = 3000;
const BACKGROUND_SYNC_INTERVAL_MS = 9000;
const MAX_RECONNECT_DELAY_MS = 10000;

export default function ChatApp({
  api,
  cryptoState,
  onLogout,
  session
}: ChatAppProps) {
  const [conversations, setConversations] = useState<ChatPartner[]>([]);
  const [selectedPartner, setSelectedPartner] = useState<ChatPartner | null>(null);
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<UserPublicInfo[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [isLoadingConversations, setIsLoadingConversations] = useState(false);
  const [isLoadingThread, setIsLoadingThread] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [socketStatus, setSocketStatus] = useState<SocketStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const selectedPartnerRef = useRef<ChatPartner | null>(selectedPartner);
  const messageIndexRef = useRef<{
    ids: Set<string>;
    payloadSignatures: Set<string>;
  }>({
    ids: new Set(),
    payloadSignatures: new Set()
  });

  useEffect(() => {
    selectedPartnerRef.current = selectedPartner;
  }, [selectedPartner]);

  useEffect(() => {
    messageIndexRef.current = {
      ids: new Set(messages.map((message) => message.id)),
      payloadSignatures: new Set(
        messages
          .map((message) => payloadSignature(message))
          .filter((signature): signature is string => Boolean(signature))
      )
    };
  }, [messages]);

  const decryptOne = useCallback(
    async (message: MessageResponse): Promise<DecryptedMessage> => {
      if (!isEncryptedPayload(message.payload)) {
        return {
          ...message,
          plaintext: null,
          decryptError: "Encrypted payload is malformed."
        };
      }

      try {
        const keySide =
          message.from_user_id === session.user.id ? "self" : "recipient";
        const plaintext = await decryptMessagePayload(
          message.payload,
          cryptoState.privateKey,
          keySide
        );

        return {
          ...message,
          payload: message.payload,
          plaintext
        };
      } catch {
        return {
          ...message,
          plaintext: null,
          decryptError: "Unable to decrypt on this device."
        };
      }
    },
    [cryptoState.privateKey, session.user.id]
  );

  const refreshConversations = useCallback(async () => {
    setIsLoadingConversations(true);
    try {
      const nextConversations = await api.listConversations();
      setConversations(nextConversations);
    } catch (conversationError) {
      setError(toFriendlyError(conversationError));
    } finally {
      setIsLoadingConversations(false);
    }
  }, [api]);

  useEffect(() => {
    void refreshConversations();
  }, [refreshConversations]);

  const syncLatestMessages = useCallback(
    async (partner: ChatPartner) => {
      try {
        const history = await api.getMessages(partner.user_id, SYNC_THREAD_LIMIT);
        const knownMessages = messageIndexRef.current;
        const unseenMessages = [...history]
          .reverse()
          .filter((message) => {
            if (knownMessages.ids.has(message.id)) {
              return false;
            }

            const signature = payloadSignature(message);
            return !signature || !knownMessages.payloadSignatures.has(signature);
          });

        if (unseenMessages.length === 0) {
          return;
        }

        const decryptedMessages = await Promise.all(unseenMessages.map(decryptOne));
        setMessages((currentMessages) =>
          mergeMessages(currentMessages, decryptedMessages)
        );
      } catch (syncError) {
        setError(toFriendlyError(syncError));
      }
    },
    [api, decryptOne]
  );

  useEffect(() => {
    let isDisposed = false;
    let reconnectAttempt = 0;
    let reconnectTimer: number | null = null;

    function scheduleReconnect() {
      if (isDisposed) {
        return;
      }

      const delay = Math.min(
        1000 * 2 ** reconnectAttempt,
        MAX_RECONNECT_DELAY_MS
      );
      reconnectAttempt += 1;
      reconnectTimer = window.setTimeout(connect, delay);
    }

    function connect() {
      if (isDisposed) {
        return;
      }

      setSocketStatus("connecting");
      const socket = new WebSocket(websocketUrl(session.accessToken));
      socketRef.current = socket;

      socket.onopen = () => {
        if (isDisposed) {
          return;
        }

        reconnectAttempt = 0;
        setSocketStatus("open");
        void refreshConversations();

        const selected = selectedPartnerRef.current;
        if (selected) {
          void syncLatestMessages(selected);
        }
      };

      socket.onerror = () => {
        if (socketRef.current === socket) {
          setSocketStatus("error");
        }
        socket.close();
      };

      socket.onclose = () => {
        if (socketRef.current === socket) {
          socketRef.current = null;
          setSocketStatus("closed");
          scheduleReconnect();
        }
      };

      socket.onmessage = (event) => {
        const apiMessage = extractMessageFromFrame(event);
        if (!apiMessage) {
          return;
        }

        void (async () => {
          const partnerId =
            apiMessage.from_user_id === session.user.id
              ? apiMessage.to_user_id
              : apiMessage.from_user_id;
          const decryptedMessage = await decryptOne(apiMessage);

          if (selectedPartnerRef.current?.user_id === partnerId) {
            setMessages((currentMessages) =>
              mergeMessages(currentMessages, [decryptedMessage])
            );
          }

          await refreshConversations();
        })();
      };
    }

    connect();

    return () => {
      isDisposed = true;
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
      }
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [
    decryptOne,
    refreshConversations,
    session.accessToken,
    session.user.id,
    syncLatestMessages
  ]);

  useEffect(() => {
    if (!selectedPartner) {
      return;
    }

    const interval = window.setInterval(
      () => {
        if (document.visibilityState === "visible") {
          void syncLatestMessages(selectedPartner);
        }
      },
      socketStatus === "open"
        ? BACKGROUND_SYNC_INTERVAL_MS
        : FALLBACK_SYNC_INTERVAL_MS
    );

    return () => window.clearInterval(interval);
  }, [selectedPartner, socketStatus, syncLatestMessages]);

  useEffect(() => {
    const trimmedQuery = searchQuery.trim();
    if (!trimmedQuery) {
      setSearchResults([]);
      setIsSearching(false);
      return;
    }

    setIsSearching(true);
    const timeout = window.setTimeout(() => {
      void (async () => {
        try {
          const results = await api.searchUsers(trimmedQuery);
          setSearchResults(results);
        } catch (searchError) {
          setError(toFriendlyError(searchError));
        } finally {
          setIsSearching(false);
        }
      })();
    }, 250);

    return () => window.clearTimeout(timeout);
  }, [api, searchQuery]);

  const selectedMessages = useMemo(() => messages, [messages]);

  async function openConversation(partner: ChatPartner) {
    setSelectedPartner(partner);
    setMessages([]);
    setError(null);
    setIsLoadingThread(true);

    try {
      const history = await api.getMessages(partner.user_id, INITIAL_THREAD_LIMIT);
      const decrypted = await Promise.all(
        [...history].reverse().map((message) => decryptOne(message))
      );
      setMessages(decrypted);
    } catch (threadError) {
      setError(toFriendlyError(threadError));
    } finally {
      setIsLoadingThread(false);
    }
  }

  async function startConversation(user: UserPublicInfo) {
    const partner: ChatPartner = {
      user_id: user.id,
      username: user.username,
      display_name: user.display_name,
      last_message_at: null
    };
    setSearchQuery("");
    setSearchResults([]);
    await openConversation(partner);
  }

  async function sendMessage(event?: FormEvent) {
    event?.preventDefault();
    const plaintext = draft.trim();

    if (!selectedPartner || !plaintext || isSending) {
      return;
    }

    setIsSending(true);
    setError(null);
    let tempId: string | null = null;

    try {
      const recipientKey = await api.getUserPublicKey(selectedPartner.user_id);
      const payload = await encryptMessagePayload(
        plaintext,
        recipientKey.public_key,
        session.user.public_key
      );
      tempId = `temp-${globalThis.crypto.randomUUID()}`;
      const optimisticMessage: DecryptedMessage = {
        id: tempId,
        from_user_id: session.user.id,
        to_user_id: selectedPartner.user_id,
        payload,
        delivered: socketStatus === "open",
        created_at: new Date().toISOString(),
        plaintext,
        pending: true
      };

      setMessages((currentMessages) => [...currentMessages, optimisticMessage]);
      setDraft("");

      if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send(buildSendFrame(selectedPartner.user_id, payload));
        setMessages((currentMessages) =>
          currentMessages.map((message) =>
            message.id === tempId
              ? { ...message, pending: false, delivered: true }
              : message
          )
        );
      } else {
        const storedMessage = await api.sendMessage(selectedPartner.user_id, payload);
        const decrypted = await decryptOne(storedMessage);
        setMessages((currentMessages) =>
          mergeMessages(
            currentMessages.filter((message) => message.id !== tempId),
            [decrypted]
          )
        );
      }

      await refreshConversations();
    } catch (sendError) {
      if (tempId) {
        setMessages((currentMessages) =>
          currentMessages.filter((message) => message.id !== tempId)
        );
      }
      setError(toFriendlyError(sendError));
    } finally {
      setIsSending(false);
    }
  }

  function handleComposerKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void sendMessage();
    }
  }

  return (
    <main className="chat-shell">
      <aside className="sidebar" aria-label="Conversations">
        <header className="profile-bar">
          <div className="avatar">{initials(session.user.display_name)}</div>
          <div>
            <strong>{session.user.display_name}</strong>
            <span>@{session.user.username}</span>
          </div>
          <button
            className="icon-button"
            onClick={onLogout}
            title="Sign out"
            type="button"
          >
            <LogOut size={18} />
          </button>
        </header>

        <div className="sidebar-status">
          <LockKeyhole size={16} />
          <span>Today: client-side encryption active</span>
        </div>

        <div className="search-box">
          <Search size={18} />
          <input
            aria-label="Search users"
            onChange={(event) => setSearchQuery(event.target.value)}
            placeholder="Search users"
            value={searchQuery}
          />
          {isSearching ? <Loader2 className="spin" size={16} /> : null}
        </div>

        {searchResults.length > 0 ? (
          <section className="sidebar-section" aria-label="Search results">
            <h2>Results</h2>
            <div className="conversation-list">
              {searchResults.map((user) => (
                <button
                  className="conversation-row"
                  key={user.id}
                  onClick={() => void startConversation(user)}
                  type="button"
                >
                  <span className="avatar avatar-small">
                    {initials(user.display_name)}
                  </span>
                  <span>
                    <strong>{user.display_name}</strong>
                    <small>@{user.username}</small>
                  </span>
                </button>
              ))}
            </div>
          </section>
        ) : null}

        <section className="sidebar-section" aria-label="Conversation list">
          <h2>
            Chats
            {isLoadingConversations ? <Loader2 className="spin" size={16} /> : null}
          </h2>
          <div className="conversation-list">
            {conversations.length === 0 && !isLoadingConversations ? (
              <div className="empty-list">
                <MessageCircle size={18} />
                <span>Search a teammate to start a private thread</span>
              </div>
            ) : null}
            {conversations.map((conversation) => (
              <button
                className={
                  selectedPartner?.user_id === conversation.user_id
                    ? "conversation-row is-active"
                    : "conversation-row"
                }
                key={conversation.user_id}
                onClick={() => void openConversation(conversation)}
                type="button"
              >
                <span className="avatar avatar-small">
                  {initials(conversation.display_name)}
                </span>
                <span>
                  <strong>{conversation.display_name}</strong>
                  <small>
                    {conversation.last_message_at
                      ? formatShortDate(conversation.last_message_at)
                      : `@${conversation.username}`}
                  </small>
                </span>
              </button>
            ))}
          </div>
        </section>
      </aside>

      <section className="thread" aria-label="Encrypted conversation">
        <header className="thread-header">
          {selectedPartner ? (
            <>
              <div className="thread-title">
                <div className="avatar avatar-small">
                  {initials(selectedPartner.display_name)}
                </div>
                <div>
                  <h1>{selectedPartner.display_name}</h1>
                  <span>@{selectedPartner.username}</span>
                </div>
              </div>
              <div className="status-cluster">
                <span className="secure-pill">
                  <LockKeyhole size={15} />
                  E2EE active
                </span>
                <span
                  className={
                    socketStatus === "open" ? "socket-pill is-online" : "socket-pill"
                  }
                >
                  {socketStatus === "open" ? <Wifi size={15} /> : <WifiOff size={15} />}
                  {socketStatus === "open" ? "Live" : "Fallback"}
                </span>
              </div>
            </>
          ) : (
            <div className="thread-title">
              <div className="avatar avatar-small">
                <ShieldCheck size={18} />
              </div>
              <div>
                <h1>WhisperBox</h1>
                <span>Secure inbox</span>
              </div>
            </div>
          )}
        </header>

        {error ? (
          <div className="alert" role="alert">
            <AlertTriangle size={17} />
            {error}
          </div>
        ) : null}

        <div className="message-pane">
          {!selectedPartner ? (
            <div className="empty-state">
              <LockKeyhole size={34} />
              <h2>Pick up where the room is quiet</h2>
              <p>Search for a teammate, open a thread, and decrypted messages will appear here.</p>
            </div>
          ) : isLoadingThread ? (
            <div className="empty-state">
              <Loader2 className="spin" size={34} />
              <h2>Decrypting messages</h2>
            </div>
          ) : (
            <div className="message-list">
              {selectedMessages.map((message) => {
                const fromSelf = message.from_user_id === session.user.id;
                return (
                  <article
                    className={fromSelf ? "message is-self" : "message"}
                    key={message.id}
                  >
                    <div className="bubble">
                      {message.decryptError ? (
                        <span className="decrypt-error">
                          <AlertTriangle size={15} />
                          {message.decryptError}
                        </span>
                      ) : (
                        message.plaintext
                      )}
                    </div>
                    <footer>
                      <span>{formatMessageTime(message.created_at)}</span>
                      {fromSelf ? (
                        <span className="delivery-state">
                          <CheckCheck size={14} />
                          {message.pending ? "Sending" : "Sent"}
                        </span>
                      ) : null}
                    </footer>
                  </article>
                );
              })}
            </div>
          )}
        </div>

        <form className="composer" onSubmit={(event) => void sendMessage(event)}>
          <textarea
            aria-label="Message"
            disabled={!selectedPartner || isSending}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={handleComposerKeyDown}
            placeholder={
              selectedPartner ? "Write an encrypted message" : "Choose a chat"
            }
            rows={1}
            value={draft}
          />
          <button
            className="send-button"
            disabled={!selectedPartner || !draft.trim() || isSending}
            title="Send message"
            type="submit"
          >
            {isSending ? <Loader2 className="spin" size={18} /> : <Send size={18} />}
          </button>
        </form>
      </section>
    </main>
  );
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

function formatShortDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric"
  }).format(new Date(value));
}

function formatMessageTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

function toFriendlyError(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Something went wrong. Please try again.";
}

function mergeMessages(
  currentMessages: DecryptedMessage[],
  incomingMessages: DecryptedMessage[]
): DecryptedMessage[] {
  const nextMessages = [...currentMessages];

  for (const incoming of incomingMessages) {
    const existingIndex = nextMessages.findIndex(
      (message) => message.id === incoming.id
    );

    if (existingIndex >= 0) {
      nextMessages[existingIndex] = incoming;
      continue;
    }

    const incomingSignature = payloadSignature(incoming);
    const optimisticIndex = incomingSignature
      ? nextMessages.findIndex(
          (message) =>
            message.id.startsWith("temp-") &&
            payloadSignature(message) === incomingSignature
        )
      : -1;

    if (optimisticIndex >= 0) {
      nextMessages[optimisticIndex] = incoming;
      continue;
    }

    nextMessages.push(incoming);
  }

  return nextMessages.sort(
    (left, right) =>
      new Date(left.created_at).getTime() - new Date(right.created_at).getTime()
  );
}

function payloadSignature(message: MessageResponse): string | null {
  if (!isEncryptedPayload(message.payload)) {
    return null;
  }

  return [
    message.from_user_id,
    message.to_user_id,
    message.payload.ciphertext,
    message.payload.iv
  ].join(":");
}
