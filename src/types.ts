export type UserProfile = {
  id: string;
  username: string;
  display_name: string;
  public_key: string;
  wrapped_private_key: string;
  pbkdf2_salt: string;
  created_at: string;
};

export type AuthResponse = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserProfile;
};

export type TokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
};

export type UserPublicInfo = {
  id: string;
  username: string;
  display_name: string;
};

export type UserPublicKey = {
  public_key: string;
};

export type ConversationSummary = {
  user_id: string;
  display_name: string;
  username: string;
  last_message_at: string | null;
};

export type ChatPartner = ConversationSummary;

export type EncryptedPayload = {
  ciphertext: string;
  iv: string;
  encryptedKey: string;
  encryptedKeyForSelf: string;
};

export type MessageResponse = {
  id: string;
  from_user_id: string;
  to_user_id: string;
  payload: EncryptedPayload | Record<string, unknown>;
  delivered: boolean;
  created_at: string;
};

export type DecryptedMessage = MessageResponse & {
  plaintext: string | null;
  decryptError?: string;
  pending?: boolean;
};

export type SessionSnapshot = {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  user: UserProfile;
};

export type CryptoState = {
  userId: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBase64: string;
};
