// ===== BioBridge Crypto Module =====
// AES-256-GCM encryption/decryption using Web Crypto API

/**
 * Generate a random salt (16 bytes)
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Generate a random IV (12 bytes for AES-GCM)
 */
export function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Import a raw 32-byte key for AES-256-GCM
 * @param {Uint8Array} rawKey - 32-byte key from WebAuthn PRF
 * @returns {Promise<CryptoKey>}
 */
export async function importKey(rawKey) {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt plaintext string with AES-256-GCM
 * @param {string} plaintext - Data to encrypt
 * @param {Uint8Array} rawKey - 32-byte encryption key
 * @returns {Promise<{ciphertext: string, iv: string, salt: string}>}
 */
export async function encrypt(plaintext, rawKey) {
  const iv = generateIV();
  const salt = generateSalt();
  const key = await importKey(rawKey);

  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoded
  );

  return {
    ciphertext: bufferToBase64(cipherBuffer),
    iv: bufferToBase64(iv),
    salt: bufferToBase64(salt),
  };
}

/**
 * Decrypt ciphertext with AES-256-GCM
 * @param {string} ciphertextB64 - Base64 encoded ciphertext
 * @param {string} ivB64 - Base64 encoded IV
 * @param {Uint8Array} rawKey - 32-byte encryption key
 * @returns {Promise<string>}
 */
export async function decrypt(ciphertextB64, ivB64, rawKey) {
  const key = await importKey(rawKey);
  const cipherBuffer = base64ToBuffer(ciphertextB64);
  const iv = base64ToBuffer(ivB64);

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    cipherBuffer
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Split a key into two halves (for recovery)
 * @param {Uint8Array} key - 32-byte key
 * @returns {{ halfA: Uint8Array, halfB: Uint8Array }}
 */
export function splitKey(key) {
  const mask = crypto.getRandomValues(new Uint8Array(key.length));
  const halfA = mask;
  const halfB = new Uint8Array(key.length);
  for (let i = 0; i < key.length; i++) {
    halfB[i] = key[i] ^ mask[i];
  }
  return { halfA, halfB };
}

/**
 * Combine two key halves back into the original key
 * @param {Uint8Array} halfA
 * @param {Uint8Array} halfB
 * @returns {Uint8Array}
 */
export function combineKey(halfA, halfB) {
  const key = new Uint8Array(halfA.length);
  for (let i = 0; i < halfA.length; i++) {
    key[i] = halfA[i] ^ halfB[i];
  }
  return key;
}

/**
 * Hash a string using SHA-256 (for OTP verification)
 * @param {string} input
 * @returns {Promise<string>} hex hash
 */
export async function sha256(input) {
  const encoded = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return bufferToHex(hashBuffer);
}

// ===== ENCODING HELPERS =====

export function bufferToBase64(buffer) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
