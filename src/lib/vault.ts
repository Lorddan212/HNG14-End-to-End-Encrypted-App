import type { UserProfile } from "../types";

const DB_NAME = "whisperbox-key-vault";
const STORE_NAME = "wrapped-private-keys";
const DB_VERSION = 1;

export type VaultRecord = {
  userId: string;
  username: string;
  displayName: string;
  publicKey: string;
  wrappedPrivateKey: string;
  pbkdf2Salt: string;
  updatedAt: string;
};

function openVault(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) {
      reject(new Error("IndexedDB is not available in this browser."));
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "userId" });
      }
    };
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

export async function saveWrappedPrivateKey(user: UserProfile): Promise<void> {
  try {
    const db = await openVault();
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).put({
        userId: user.id,
        username: user.username,
        displayName: user.display_name,
        publicKey: user.public_key,
        wrappedPrivateKey: user.wrapped_private_key,
        pbkdf2Salt: user.pbkdf2_salt,
        updatedAt: new Date().toISOString()
      } satisfies VaultRecord);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
    db.close();
  } catch {
    // The app can still operate without IndexedDB; the server also stores the wrapped key.
  }
}

export async function getWrappedPrivateKey(
  userId: string
): Promise<VaultRecord | null> {
  try {
    const db = await openVault();
    const record = await new Promise<VaultRecord | null>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).get(userId);
      request.onsuccess = () => resolve((request.result as VaultRecord) ?? null);
      request.onerror = () => reject(request.error);
    });
    db.close();
    return record;
  } catch {
    return null;
  }
}
