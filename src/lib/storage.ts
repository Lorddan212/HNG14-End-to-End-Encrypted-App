import type { SessionTokens, StoredKeyset, UserProfile } from "../types";

const SESSION_KEY = "whisperbox.session.v1";
const DB_NAME = "whisperbox-client";
const DB_VERSION = 1;
const KEYSET_STORE = "keysets";

let dbPromise: Promise<IDBDatabase> | null = null;

export function saveTokens(tokens: SessionTokens) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(tokens));
}

export function loadTokens(): SessionTokens | null {
  const raw = sessionStorage.getItem(SESSION_KEY);
  if (!raw) {
    return null;
  }

  try {
    const tokens = JSON.parse(raw) as SessionTokens;
    if (!tokens.accessToken || !tokens.refreshToken) {
      return null;
    }

    return tokens;
  } catch {
    clearTokens();
    return null;
  }
}

export function clearTokens() {
  sessionStorage.removeItem(SESSION_KEY);
}

export async function saveKeyset(profile: UserProfile): Promise<void> {
  const db = await openDatabase();

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(KEYSET_STORE, "readwrite");
    const store = tx.objectStore(KEYSET_STORE);
    const value: StoredKeyset = {
      userId: profile.id,
      profile,
      savedAt: new Date().toISOString(),
    };

    store.put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("Unable to save keyset"));
  });
}

export async function getKeyset(userId: string): Promise<StoredKeyset | null> {
  const db = await openDatabase();

  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEYSET_STORE, "readonly");
    const request = tx.objectStore(KEYSET_STORE).get(userId);

    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () =>
      reject(request.error ?? new Error("Unable to read keyset"));
  });
}

export async function deleteKeyset(userId: string): Promise<void> {
  const db = await openDatabase();

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(KEYSET_STORE, "readwrite");

    tx.objectStore(KEYSET_STORE).delete(userId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("Unable to delete keyset"));
  });
}

function openDatabase(): Promise<IDBDatabase> {
  if (!("indexedDB" in globalThis)) {
    return Promise.reject(new Error("IndexedDB is unavailable in this browser."));
  }

  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = () => {
        const db = request.result;

        if (!db.objectStoreNames.contains(KEYSET_STORE)) {
          db.createObjectStore(KEYSET_STORE, { keyPath: "userId" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("Unable to open IndexedDB"));
    });
  }

  return dbPromise;
}
