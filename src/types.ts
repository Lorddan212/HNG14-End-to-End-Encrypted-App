export interface UserProfile {
  id: string;
  username: string;
  display_name: string;
  public_key: string;
  wrapped_private_key: string;
  pbkdf2_salt: string;
  created_at: string;
}

export interface UserPublicInfo {
  id: string;
  username: string;
  display_name: string;
}

export interface UserPublicKey {
  public_key: string;
}

export interface ConversationSummary {
  user_id: string;
  display_name: string;
  username: string;
  last_message_at: string | null;
}

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  encryptedKey: string;
  encryptedKeyForSelf: string;
}

export interface MessageResponse {
  id: string;
  from_user_id: string;
  to_user_id: string;
  payload: EncryptedPayload;
  delivered: boolean;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserProfile;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface SessionTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

export interface ChatPartner {
  id: string;
  username: string;
  display_name: string;
  last_message_at?: string | null;
}

export interface DecryptedMessage extends MessageResponse {
  isOwn: boolean;
  plaintext: string | null;
  decryptError?: string;
  nonce?: string;
  possibleReplay?: boolean;
  optimistic?: boolean;
}

export interface StoredKeyset {
  userId: string;
  profile: UserProfile;
  savedAt: string;
}
