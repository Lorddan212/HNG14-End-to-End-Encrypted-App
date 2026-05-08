import { FormEvent, useMemo, useState } from "react";
import { KeyRound, LockKeyhole, MessagesSquare, ShieldCheck } from "lucide-react";

type AuthMode = "login" | "register";

type AuthScreenProps = {
  onLogin: (input: { username: string; password: string }) => Promise<void>;
  onRegister: (input: {
    username: string;
    displayName: string;
    password: string;
  }) => Promise<void>;
};

export default function AuthScreen({ onLogin, onRegister }: AuthScreenProps) {
  const [mode, setMode] = useState<AuthMode>("login");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validationError = useMemo(() => {
    if (username.trim().length < (mode === "register" ? 3 : 1)) {
      return mode === "register"
        ? "Username must be at least 3 characters."
        : "Username is required.";
    }

    if (mode === "register" && displayName.trim().length < 1) {
      return "Display name is required.";
    }

    if (password.length < (mode === "register" ? 8 : 1)) {
      return mode === "register"
        ? "Password must be at least 8 characters."
        : "Password is required.";
    }

    return null;
  }, [displayName, mode, password, username]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);

    if (validationError) {
      setError(validationError);
      return;
    }

    setIsSubmitting(true);
    try {
      if (mode === "login") {
        await onLogin({ username, password });
      } else {
        await onRegister({ username, displayName, password });
      }
    } catch (submitError) {
      setError(toFriendlyError(submitError));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-copy" aria-label="WhisperBox security summary">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={28} />
          </div>
          <span>Private by design</span>
        </div>
        <h1>WhisperBox</h1>
        <p className="auth-lede">
          Confidential conversations for teams that discuss launches, finances,
          legal reviews, and customer issues before the rest of the world should
          know.
        </p>
        <div className="assurance-grid">
          <div>
            <LockKeyhole size={18} />
            <span>Device-held private keys</span>
          </div>
          <div>
            <KeyRound size={18} />
            <span>Per-message encryption</span>
          </div>
          <div>
            <ShieldCheck size={18} />
            <span>Ciphertext-only delivery</span>
          </div>
        </div>
      </section>

      <section className="auth-panel" aria-label="Authentication">
        <div className="auth-panel-heading">
          <div className="panel-glyph" aria-hidden="true">
            <MessagesSquare size={22} />
          </div>
          <div>
            <h2>Secure Access</h2>
            <p>Sign in to continue a protected conversation</p>
          </div>
        </div>

        <div className="segmented-control" role="tablist" aria-label="Auth mode">
          <button
            aria-selected={mode === "login"}
            className={mode === "login" ? "is-selected" : ""}
            onClick={() => {
              setMode("login");
              setError(null);
            }}
            role="tab"
            type="button"
          >
            Sign In
          </button>
          <button
            aria-selected={mode === "register"}
            className={mode === "register" ? "is-selected" : ""}
            onClick={() => {
              setMode("register");
              setError(null);
            }}
            role="tab"
            type="button"
          >
            Create Account
          </button>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            Username
            <input
              autoComplete="username"
              autoCapitalize="none"
              autoCorrect="off"
              maxLength={32}
              name="username"
              onChange={(event) => setUsername(event.target.value)}
              placeholder="maya_chen"
              spellCheck={false}
              value={username}
            />
          </label>

          {mode === "register" ? (
            <label>
              Display Name
              <input
                autoComplete="name"
                maxLength={128}
                name="name"
                onChange={(event) => setDisplayName(event.target.value)}
                placeholder="Maya Chen"
                value={displayName}
              />
            </label>
          ) : null}

          <label>
            Password
            <input
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              maxLength={128}
              name="password"
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
              type="password"
              value={password}
            />
          </label>

          {error ? <p className="form-error">{error}</p> : null}

          <button className="primary-action" disabled={isSubmitting} type="submit">
            {isSubmitting
              ? mode === "login"
                ? "Signing in..."
                : "Creating keys..."
              : mode === "login"
                ? "Sign In"
                : "Create Encrypted Account"}
          </button>
        </form>
      </section>
    </main>
  );
}

function toFriendlyError(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return "Something went wrong. Please try again.";
}
