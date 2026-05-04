import type { EncryptedPayload } from "../types";

const RSA_ALGORITHM: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

const RSA_IMPORT_ALGORITHM: RsaHashedImportParams = {
  name: "RSA-OAEP",
  hash: "SHA-256",
};

const AES_GCM_ALGORITHM = "AES-GCM";
const AES_KW_ALGORITHM = "AES-KW";
const PBKDF2_ITERATIONS = 310_000;

interface PlaintextEnvelope {
  v: 1;
  kind: "whisperbox.message";
  body: string;
  sentAt: string;
  nonce: string;
}

export interface RegistrationKeyMaterial {
  public_key: string;
  wrapped_private_key: string;
  pbkdf2_salt: string;
  privateKey: CryptoKey;
}

export interface DecryptionResult {
  plaintext: string;
  nonce?: string;
  sentAt?: string;
}

export function assertCryptoAvailable() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable. Use HTTPS or localhost.");
  }
}

export function bytesToBase64(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }

  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
  const clean = base64.replace(/\s/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

export async function generateUserKeyMaterial(
  password: string,
): Promise<RegistrationKeyMaterial> {
  assertCryptoAvailable();

  const salt = randomBytes(16);
  const pair = await globalThis.crypto.subtle.generateKey(
    RSA_ALGORITHM,
    true,
    ["encrypt", "decrypt"],
  );
  const wrappingKey = await deriveWrappingKey(password, salt);
  const wrappedPrivateKey = await globalThis.crypto.subtle.wrapKey(
    "pkcs8",
    pair.privateKey,
    wrappingKey,
    AES_KW_ALGORITHM,
  );
  const publicKey = await globalThis.crypto.subtle.exportKey(
    "spki",
    pair.publicKey,
  );
  const wrappedPrivateKeyBase64 = bytesToBase64(wrappedPrivateKey);
  const saltBase64 = bytesToBase64(salt);

  return {
    public_key: bytesToBase64(publicKey),
    wrapped_private_key: wrappedPrivateKeyBase64,
    pbkdf2_salt: saltBase64,
    privateKey: await unwrapPrivateKey(
      wrappedPrivateKeyBase64,
      saltBase64,
      password,
    ),
  };
}

export async function unwrapPrivateKey(
  wrappedPrivateKey: string,
  saltBase64: string,
  password: string,
): Promise<CryptoKey> {
  assertCryptoAvailable();

  const wrappingKey = await deriveWrappingKey(
    password,
    base64ToBytes(saltBase64),
  );

  return globalThis.crypto.subtle.unwrapKey(
    "pkcs8",
    base64ToBytes(wrappedPrivateKey),
    wrappingKey,
    AES_KW_ALGORITHM,
    RSA_IMPORT_ALGORITHM,
    false,
    ["decrypt"],
  );
}

export async function importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
  assertCryptoAvailable();

  return globalThis.crypto.subtle.importKey(
    "spki",
    base64ToBytes(publicKeyBase64),
    RSA_IMPORT_ALGORITHM,
    false,
    ["encrypt"],
  );
}

export async function fingerprintPublicKey(publicKeyBase64: string): Promise<string> {
  assertCryptoAvailable();

  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    base64ToBytes(publicKeyBase64),
  );
  const bytes = Array.from(new Uint8Array(digest).slice(0, 12));

  return bytes
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .replace(/(.{4})/g, "$1 ")
    .trim();
}

export async function encryptMessage(
  plaintext: string,
  recipientPublicKeyBase64: string,
  senderPublicKeyBase64: string,
): Promise<EncryptedPayload> {
  assertCryptoAvailable();

  const aesKey = await globalThis.crypto.subtle.generateKey(
    { name: AES_GCM_ALGORITHM, length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const iv = randomBytes(12);
  const envelope: PlaintextEnvelope = {
    v: 1,
    kind: "whisperbox.message",
    body: plaintext,
    sentAt: new Date().toISOString(),
    nonce: bytesToBase64(randomBytes(16)),
  };
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: AES_GCM_ALGORITHM, iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify(envelope)),
  );
  const rawAesKey = await globalThis.crypto.subtle.exportKey("raw", aesKey);
  const [recipientPublicKey, senderPublicKey] = await Promise.all([
    importPublicKey(recipientPublicKeyBase64),
    importPublicKey(senderPublicKeyBase64),
  ]);
  const [encryptedKey, encryptedKeyForSelf] = await Promise.all([
    globalThis.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      recipientPublicKey,
      rawAesKey,
    ),
    globalThis.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      senderPublicKey,
      rawAesKey,
    ),
  ]);

  return {
    ciphertext: bytesToBase64(ciphertext),
    iv: bytesToBase64(iv),
    encryptedKey: bytesToBase64(encryptedKey),
    encryptedKeyForSelf: bytesToBase64(encryptedKeyForSelf),
  };
}

export async function decryptMessagePayload(
  payload: EncryptedPayload,
  privateKey: CryptoKey,
  keySlot: "recipient" | "self",
): Promise<DecryptionResult> {
  assertCryptoAvailable();

  const encryptedKey =
    keySlot === "self" ? payload.encryptedKeyForSelf : payload.encryptedKey;
  const rawAesKey = await globalThis.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    base64ToBytes(encryptedKey),
  );
  const aesKey = await globalThis.crypto.subtle.importKey(
    "raw",
    rawAesKey,
    AES_GCM_ALGORITHM,
    false,
    ["decrypt"],
  );
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: AES_GCM_ALGORITHM, iv: base64ToBytes(payload.iv) },
    aesKey,
    base64ToBytes(payload.ciphertext),
  );
  const decoded = new TextDecoder().decode(plaintext);

  try {
    const envelope = JSON.parse(decoded) as Partial<PlaintextEnvelope>;
    if (
      envelope.v === 1 &&
      envelope.kind === "whisperbox.message" &&
      typeof envelope.body === "string"
    ) {
      return {
        plaintext: envelope.body,
        nonce: typeof envelope.nonce === "string" ? envelope.nonce : undefined,
        sentAt: typeof envelope.sentAt === "string" ? envelope.sentAt : undefined,
      };
    }
  } catch {
    // Messages from another compliant client may be plain UTF-8 instead.
  }

  return { plaintext: decoded };
}

async function deriveWrappingKey(
  password: string,
  salt: BufferSource,
): Promise<CryptoKey> {
  const passwordKey = await globalThis.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password.normalize("NFKC")),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return globalThis.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    passwordKey,
    { name: AES_KW_ALGORITHM, length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(length));
  globalThis.crypto.getRandomValues(bytes);

  return bytes;
}
