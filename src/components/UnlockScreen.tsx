import { FormEvent, useState } from "react";
import { KeyRound, LogOut, ShieldCheck } from "lucide-react";

type UnlockScreenProps = {
  displayName: string;
  username: string;
  onUnlock: (password: string) => Promise<void>;
  onLogout: () => Promise<void>;
};

export default function UnlockScreen({
  displayName,
  username,
  onLogout,
  onUnlock
}: UnlockScreenProps) {
  const [password, setPassword] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);

    if (!password) {
      setError("Password is required.");
      return;
    }

    setIsUnlocking(true);
    try {
      await onUnlock(password);
    } catch {
      setError("Unable to unlock the private key with that password.");
    } finally {
      setIsUnlocking(false);
    }
  }

  return (
    <main className="unlock-page">
      <section className="unlock-panel">
        <div className="unlock-icon" aria-hidden="true">
          <KeyRound size={30} />
        </div>
        <p className="eyebrow">
          <ShieldCheck size={16} />
          Encrypted session
        </p>
        <h1>Unlock {displayName}</h1>
        <p className="muted">@{username} · private key required on this device</p>

        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            Password
            <input
              autoComplete="current-password"
              autoFocus
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
              type="password"
              value={password}
            />
          </label>

          {error ? <p className="form-error">{error}</p> : null}

          <button className="primary-action" disabled={isUnlocking} type="submit">
            {isUnlocking ? "Unlocking..." : "Unlock messages"}
          </button>
        </form>

        <button className="text-action" onClick={onLogout} type="button">
          <LogOut size={16} />
          Sign out
        </button>
      </section>
    </main>
  );
}
