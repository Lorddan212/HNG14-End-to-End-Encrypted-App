import type { CryptoState, EncryptedPayload } from "../types";

const RSA_PARAMS: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256"
};

const RSA_IMPORT_PARAMS: RsaHashedImportParams = {
  name: "RSA-OAEP",
  hash: "SHA-256"
};

const AES_GCM_PARAMS: AesKeyGenParams = {
  name: "AES-GCM",
  length: 256
};

const AES_KW_PARAMS: AesKeyAlgorithm = {
  name: "AES-KW",
  length: 256
};

const OPAQUE_KEY_PARAMS: HmacImportParams = {
  name: "HMAC",
  hash: "SHA-256"
};

const PRIVATE_KEY_WRAP_MAGIC = [0x57, 0x42, 0x4b, 0x31]; // WBK1
const PRIVATE_KEY_WRAP_HEADER_BYTES = 8;
const PBKDF2_ITERATIONS = 310_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function webCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is not available in this browser.");
  }
  return globalThis.crypto;
}

export function bytesToBase64(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function deriveWrappingKey(
  password: string,
  salt: Uint8Array,
  usages: KeyUsage[]
): Promise<CryptoKey> {
  const subtle = webCrypto().subtle;
  const passwordMaterial = await subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: bytesToArrayBuffer(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    passwordMaterial,
    AES_KW_PARAMS,
    false,
    usages
  );
}

export type GeneratedKeyMaterial = {
  publicKeyBase64: string;
  wrappedPrivateKeyBase64: string;
  pbkdf2SaltBase64: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
};

export async function generateUserKeyMaterial(
  password: string
): Promise<GeneratedKeyMaterial> {
  const subtle = webCrypto().subtle;
  const salt = webCrypto().getRandomValues(new Uint8Array(16));
  const keyPair = (await subtle.generateKey(RSA_PARAMS, true, [
    "encrypt",
    "decrypt"
  ])) as CryptoKeyPair;
  const publicKeyBuffer = await subtle.exportKey("spki", keyPair.publicKey);
  const wrappingKey = await deriveWrappingKey(password, salt, ["wrapKey"]);
  const wrappedPrivateKeyBuffer = await wrapPrivateKeyBytes(
    keyPair.privateKey,
    wrappingKey
  );

  const publicKeyBase64 = bytesToBase64(publicKeyBuffer);
  const wrappedPrivateKeyBase64 = bytesToBase64(wrappedPrivateKeyBuffer);
  const pbkdf2SaltBase64 = bytesToBase64(salt);
  const privateKey = await unwrapPrivateKey(
    password,
    wrappedPrivateKeyBase64,
    pbkdf2SaltBase64
  );

  return {
    publicKeyBase64,
    wrappedPrivateKeyBase64,
    pbkdf2SaltBase64,
    privateKey,
    publicKey: await importPublicKey(publicKeyBase64)
  };
}

export async function importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
  return webCrypto().subtle.importKey(
    "spki",
    bytesToArrayBuffer(base64ToBytes(publicKeyBase64)),
    RSA_IMPORT_PARAMS,
    false,
    ["encrypt"]
  );
}

export async function unwrapPrivateKey(
  password: string,
  wrappedPrivateKeyBase64: string,
  pbkdf2SaltBase64: string
): Promise<CryptoKey> {
  const subtle = webCrypto().subtle;
  const wrappingKey = await deriveWrappingKey(
    password,
    base64ToBytes(pbkdf2SaltBase64),
    ["unwrapKey"]
  );
  const opaquePrivateKey = await subtle.unwrapKey(
    "raw",
    bytesToArrayBuffer(base64ToBytes(wrappedPrivateKeyBase64)),
    wrappingKey,
    "AES-KW",
    OPAQUE_KEY_PARAMS,
    true,
    ["sign"]
  );
  const packedPrivateKey = await subtle.exportKey("raw", opaquePrivateKey);
  const privateKeyPkcs8 = unpackPrivateKeyBytes(packedPrivateKey);

  return subtle.importKey(
    "pkcs8",
    privateKeyPkcs8,
    RSA_IMPORT_PARAMS,
    false,
    ["decrypt"]
  );
}

async function wrapPrivateKeyBytes(
  privateKey: CryptoKey,
  wrappingKey: CryptoKey
): Promise<ArrayBuffer> {
  const subtle = webCrypto().subtle;
  const privateKeyPkcs8 = await subtle.exportKey("pkcs8", privateKey);
  const packedPrivateKey = packPrivateKeyBytes(privateKeyPkcs8);
  const opaquePrivateKey = await subtle.importKey(
    "raw",
    packedPrivateKey,
    OPAQUE_KEY_PARAMS,
    true,
    ["sign"]
  );

  return subtle.wrapKey("raw", opaquePrivateKey, wrappingKey, "AES-KW");
}

function packPrivateKeyBytes(privateKeyPkcs8: ArrayBuffer): ArrayBuffer {
  const privateKeyBytes = new Uint8Array(privateKeyPkcs8);
  const packedLength =
    Math.ceil((PRIVATE_KEY_WRAP_HEADER_BYTES + privateKeyBytes.byteLength) / 8) *
    8;
  const packed = new Uint8Array(packedLength);
  packed.set(PRIVATE_KEY_WRAP_MAGIC, 0);
  new DataView(packed.buffer).setUint32(4, privateKeyBytes.byteLength, false);
  packed.set(privateKeyBytes, PRIVATE_KEY_WRAP_HEADER_BYTES);
  return packed.buffer;
}

function unpackPrivateKeyBytes(packedPrivateKey: ArrayBuffer): ArrayBuffer {
  const packed = new Uint8Array(packedPrivateKey);
  const hasMagic = PRIVATE_KEY_WRAP_MAGIC.every(
    (byte, index) => packed[index] === byte
  );

  if (!hasMagic) {
    return packedPrivateKey;
  }

  const privateKeyLength = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength
  ).getUint32(4, false);
  return bytesToArrayBuffer(
    packed.subarray(
      PRIVATE_KEY_WRAP_HEADER_BYTES,
      PRIVATE_KEY_WRAP_HEADER_BYTES + privateKeyLength
    )
  );
}

export async function buildCryptoState(
  userId: string,
  publicKeyBase64: string,
  privateKey: CryptoKey
): Promise<CryptoState> {
  return {
    userId,
    privateKey,
    publicKey: await importPublicKey(publicKeyBase64),
    publicKeyBase64
  };
}

export async function unlockUserCryptoState(
  userId: string,
  publicKeyBase64: string,
  wrappedPrivateKeyBase64: string,
  pbkdf2SaltBase64: string,
  password: string
): Promise<CryptoState> {
  const privateKey = await unwrapPrivateKey(
    password,
    wrappedPrivateKeyBase64,
    pbkdf2SaltBase64
  );

  return buildCryptoState(userId, publicKeyBase64, privateKey);
}

export function isEncryptedPayload(
  payload: MessageResponsePayload
): payload is EncryptedPayload {
  if (!payload || typeof payload !== "object") {
    return false;
  }

  const candidate = payload as Record<string, unknown>;
  return (
    typeof candidate.ciphertext === "string" &&
    typeof candidate.iv === "string" &&
    typeof candidate.encryptedKey === "string" &&
    typeof candidate.encryptedKeyForSelf === "string"
  );
}

type MessageResponsePayload = EncryptedPayload | Record<string, unknown> | null;

export async function encryptMessagePayload(
  plaintext: string,
  recipientPublicKeyBase64: string,
  senderPublicKeyBase64: string
): Promise<EncryptedPayload> {
  const subtle = webCrypto().subtle;
  const aesKey = await subtle.generateKey(AES_GCM_PARAMS, true, [
    "encrypt",
    "decrypt"
  ]);
  const iv = webCrypto().getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    aesKey,
    encoder.encode(plaintext)
  );
  const rawAesKey = await subtle.exportKey("raw", aesKey);
  const recipientPublicKey = await importPublicKey(recipientPublicKeyBase64);
  const senderPublicKey = await importPublicKey(senderPublicKeyBase64);
  const encryptedKey = await subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    rawAesKey
  );
  const encryptedKeyForSelf = await subtle.encrypt(
    { name: "RSA-OAEP" },
    senderPublicKey,
    rawAesKey
  );

  return {
    ciphertext: bytesToBase64(ciphertext),
    iv: bytesToBase64(iv),
    encryptedKey: bytesToBase64(encryptedKey),
    encryptedKeyForSelf: bytesToBase64(encryptedKeyForSelf)
  };
}

export async function decryptMessagePayload(
  payload: EncryptedPayload,
  privateKey: CryptoKey,
  keySide: "recipient" | "self"
): Promise<string> {
  const subtle = webCrypto().subtle;
  const wrappedAesKey =
    keySide === "self" ? payload.encryptedKeyForSelf : payload.encryptedKey;
  const rawAesKey = await subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    bytesToArrayBuffer(base64ToBytes(wrappedAesKey))
  );
  const aesKey = await subtle.importKey(
    "raw",
    rawAesKey,
    AES_GCM_PARAMS,
    false,
    ["decrypt"]
  );
  const plaintext = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytesToArrayBuffer(base64ToBytes(payload.iv))
    },
    aesKey,
    bytesToArrayBuffer(base64ToBytes(payload.ciphertext))
  );

  return decoder.decode(plaintext);
}
