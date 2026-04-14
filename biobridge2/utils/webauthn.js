// ===== BioBridge WebAuthn PRF Module =====
// Handles biometric registration and authentication with PRF key derivation

import { bufferToBase64, base64ToBuffer } from './crypto.js';

const RELYING_PARTY = {
  name: 'BioBridge',
  id: 'localhost', // Will be the extension ID in production
};

// Fixed PRF salt for deterministic key derivation
const PRF_SALT = new TextEncoder().encode('biobridge-vault-key-v1');

/**
 * Check if WebAuthn PRF is available on this device
 * @returns {Promise<boolean>}
 */
export async function isPRFAvailable() {
  if (!window.PublicKeyCredential) return false;

  try {
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    return available;
  } catch {
    return false;
  }
}

/**
 * Register biometric credentials with PRF extension
 * @param {string} userId - Unique user identifier
 * @returns {Promise<{ credentialId: string, rawKey: Uint8Array }>}
 */
export async function register(userId = 'biobridge-user') {
  const userIdBytes = new TextEncoder().encode(userId);

  const publicKeyCredentialCreationOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: RELYING_PARTY,
    user: {
      id: userIdBytes,
      name: userId,
      displayName: 'BioBridge User',
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },   // ES256
      { alg: -257, type: 'public-key' },  // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'preferred',
    },
    timeout: 60000,
    extensions: {
      prf: {
        eval: {
          first: PRF_SALT,
        },
      },
    },
  };

  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions,
  });

  const prfResults = credential.getClientExtensionResults()?.prf;

  if (!prfResults?.enabled && !prfResults?.results?.first) {
    throw new Error('PRF extension not supported on this device');
  }

  const credentialId = bufferToBase64(credential.rawId);

  // If PRF returned a key during registration
  let rawKey = null;
  if (prfResults?.results?.first) {
    rawKey = new Uint8Array(prfResults.results.first);
  }

  return { credentialId, rawKey };
}

/**
 * Authenticate with biometrics and derive 32-byte key via PRF
 * @param {string} credentialIdB64 - Base64 encoded credential ID
 * @returns {Promise<Uint8Array>} 32-byte derived key
 */
export async function authenticate(credentialIdB64) {
  const credentialId = base64ToBuffer(credentialIdB64);

  const publicKeyCredentialRequestOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: RELYING_PARTY.id,
    allowCredentials: [
      {
        id: credentialId,
        type: 'public-key',
        transports: ['internal'],
      },
    ],
    userVerification: 'required',
    timeout: 60000,
    extensions: {
      prf: {
        eval: {
          first: PRF_SALT,
        },
      },
    },
  };

  const assertion = await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions,
  });

  const prfResults = assertion.getClientExtensionResults()?.prf;

  if (!prfResults?.results?.first) {
    throw new Error('PRF key derivation failed');
  }

  // The PRF output is the 32-byte key
  return new Uint8Array(prfResults.results.first);
}
