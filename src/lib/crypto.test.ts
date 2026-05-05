import { describe, expect, it } from "vitest";
import {
  decryptMessagePayload,
  encryptMessagePayload,
  generateUserKeyMaterial,
  unwrapPrivateKey
} from "./crypto";

describe("WhisperBox crypto protocol", () => {
  it("wraps private keys and decrypts recipient and sender copies", async () => {
    const alice = await generateUserKeyMaterial("Correct horse battery staple 1!");
    const bob = await generateUserKeyMaterial("Correct horse battery staple 2!");
    const bobPrivateKey = await unwrapPrivateKey(
      "Correct horse battery staple 2!",
      bob.wrappedPrivateKeyBase64,
      bob.pbkdf2SaltBase64
    );
    const payload = await encryptMessagePayload(
      "Meet at 09:30.",
      bob.publicKeyBase64,
      alice.publicKeyBase64
    );

    await expect(
      decryptMessagePayload(payload, bobPrivateKey, "recipient")
    ).resolves.toBe("Meet at 09:30.");
    await expect(
      decryptMessagePayload(payload, alice.privateKey, "self")
    ).resolves.toBe("Meet at 09:30.");
  });
});
