// ===== BioBridge Service Worker =====
// Hybrid approach: WebAuthn verifies identity in popup,
// VEK (Vault Encryption Key) stored encrypted in chrome.storage.local

// ===== IN-MEMORY STATE =====
let activeVEK = null; // 32-byte key, only in memory when unlocked

// ===== CRYPTO HELPERS (inline to avoid import issues in SW) =====

function generateIV() {
  return crypto.getRandomValues(new Uint8Array(12));
}

function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

async function importKey(rawKey) {
  return crypto.subtle.importKey(
    'raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
  );
}

async function encryptData(plaintext, rawKey) {
  const iv = generateIV();
  const salt = generateSalt();
  const key = await importKey(rawKey);
  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return {
    ciphertext: bufferToBase64(cipherBuffer),
    iv: bufferToBase64(iv),
    salt: bufferToBase64(salt),
  };
}

async function decryptData(ciphertextB64, ivB64, rawKey) {
  const key = await importKey(rawKey);
  const cipherBuffer = base64ToBuffer(ciphertextB64);
  const iv = base64ToBuffer(ivB64);
  const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBuffer);
  return new TextDecoder().decode(decryptedBuffer);
}

async function sha256(input) {
  const encoded = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return bufferToHex(hashBuffer);
}

/**
 * Derive a storage protection key from the credential ID
 * This key protects the VEK at rest in chrome.storage
 */
async function deriveStorageKey(credentialId) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(credentialId + '-biobridge-storage-key'),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode('biobridge-salt-v1'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

function splitKey(key) {
  const mask = crypto.getRandomValues(new Uint8Array(key.length));
  const halfB = new Uint8Array(key.length);
  for (let i = 0; i < key.length; i++) {
    halfB[i] = key[i] ^ mask[i];
  }
  return { halfA: mask, halfB };
}

function combineKey(halfA, halfB) {
  const key = new Uint8Array(halfA.length);
  for (let i = 0; i < halfA.length; i++) {
    key[i] = halfA[i] ^ halfB[i];
  }
  return key;
}

// ===== ENCODING HELPERS =====

function bufferToBase64(buffer) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===== STORAGE KEYS =====
const STORE = {
  VAULT: 'biobridge_vault',
  SETTINGS: 'biobridge_settings',
  RECOVERY: 'biobridge_recovery',
  VEK_ENCRYPTED: 'biobridge_vek_encrypted',
};

async function storageGet(key) {
  const result = await chrome.storage.local.get(key);
  return result[key] || null;
}

async function storageSet(key, value) {
  await chrome.storage.local.set({ [key]: value });
}

// ===== MESSAGE ROUTER =====
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch(err => {
      console.error('SW Error:', err);
      sendResponse({ success: false, error: err.message });
    });
  return true; // Keep channel open for async
});

async function handleMessage(msg) {
  switch (msg.type) {
    case 'FIRST_TIME_SETUP':   return handleFirstTimeSetup(msg);
    case 'UNLOCK_VAULT':       return handleUnlockVault();
    case 'LOCK_VAULT':         return handleLockVault();
    case 'SAVE_CREDENTIAL':    return handleSaveCredential(msg);
    case 'GET_CREDENTIAL':     return handleGetCredential(msg);
    case 'UPDATE_CREDENTIAL':  return handleUpdateCredential(msg);
    case 'DELETE_CREDENTIAL':  return handleDeleteCredential(msg);
    case 'GET_ALL_SITES':      return handleGetAllSites();
    case 'GET_SETTINGS':       return handleGetSettings();
    case 'SET_RECOVERY_EMAIL': return handleSetRecoveryEmail(msg);
    case 'START_RECOVERY':     return handleStartRecovery();
    case 'VERIFY_OTP':         return handleVerifyOTP(msg);
    case 'EXPORT_BACKUP':      return handleExportBackup();
    case 'IMPORT_BACKUP':      return handleImportBackup(msg);
    case 'CHECK_SITE':         return handleCheckSite(msg);
    case 'AUTOFILL_REQUEST':   return handleAutofillRequest(msg);
    case 'SAVE_FROM_CONTENT':  return handleSaveCredential(msg);
    default:                   return { success: false, error: 'Unknown message type' };
  }
}

// ===== FIRST TIME SETUP =====
// Popup registered biometrics → now we generate and store the VEK
async function handleFirstTimeSetup(msg) {
  try {
    const { credentialId } = msg;

    // Generate a random 32-byte Vault Encryption Key
    const vek = crypto.getRandomValues(new Uint8Array(32));

    // Derive a storage protection key from the credential ID
    const storageKey = await deriveStorageKey(credentialId);

    // Encrypt the VEK for storage
    const iv = generateIV();
    const encryptedVEK = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      storageKey,
      vek
    );

    // Store encrypted VEK
    await storageSet(STORE.VEK_ENCRYPTED, {
      ciphertext: bufferToBase64(encryptedVEK),
      iv: bufferToBase64(iv),
    });

    // Store credential ID in settings
    const settings = (await storageGet(STORE.SETTINGS)) || {};
    settings.credentialId = credentialId;
    settings.biometricRegistered = true;
    settings.setupDate = Date.now();
    await storageSet(STORE.SETTINGS, settings);

    // Split VEK for recovery
    const { halfA, halfB } = splitKey(vek);
    const recovery = (await storageGet(STORE.RECOVERY)) || {};
    recovery.keyHalfA = bufferToBase64(halfA);
    recovery.keyHalfB = bufferToBase64(halfB);
    await storageSet(STORE.RECOVERY, recovery);

    // Set VEK as active in memory
    activeVEK = vek;

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ===== UNLOCK VAULT =====
// Popup verified biometrics → now decrypt and load VEK into memory
async function handleUnlockVault() {
  try {
    const settings = (await storageGet(STORE.SETTINGS)) || {};
    if (!settings.credentialId) {
      return { success: false, error: 'No biometric registered' };
    }

    const encVEK = await storageGet(STORE.VEK_ENCRYPTED);
    if (!encVEK) {
      return { success: false, error: 'No encryption key found' };
    }

    // Derive storage key from credential ID
    const storageKey = await deriveStorageKey(settings.credentialId);

    // Decrypt the VEK
    const decryptedVEK = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuffer(encVEK.iv) },
      storageKey,
      base64ToBuffer(encVEK.ciphertext)
    );

    activeVEK = new Uint8Array(decryptedVEK);
    return { success: true };
  } catch (err) {
    console.error('Unlock error:', err);
    return { success: false, error: 'Failed to unlock vault' };
  }
}

// ===== LOCK VAULT =====
async function handleLockVault() {
  activeVEK = null;
  return { success: true };
}

// ===== CREDENTIAL HANDLERS =====

async function handleSaveCredential(msg) {
  if (!activeVEK) return { success: false, error: 'Vault is locked' };

  try {
    const { site, username, password } = msg;
    const encrypted = await encryptData(password, activeVEK);

    const vault = (await storageGet(STORE.VAULT)) || {};
    vault[site] = {
      username,
      encPassword: encrypted.ciphertext,
      iv: encrypted.iv,
      salt: encrypted.salt,
      createdAt: vault[site]?.createdAt || Date.now(),
      updatedAt: Date.now(),
    };
    await storageSet(STORE.VAULT, vault);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleGetCredential(msg) {
  if (!activeVEK) return { success: false, error: 'Vault is locked' };

  try {
    const vault = (await storageGet(STORE.VAULT)) || {};
    const cred = vault[msg.site];
    if (!cred) return { success: false, error: 'Not found' };

    const password = await decryptData(cred.encPassword, cred.iv, activeVEK);
    return { success: true, data: { username: cred.username, password } };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleUpdateCredential(msg) {
  return handleSaveCredential(msg);
}

async function handleDeleteCredential(msg) {
  try {
    const vault = (await storageGet(STORE.VAULT)) || {};
    delete vault[msg.site];
    await storageSet(STORE.VAULT, vault);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleGetAllSites() {
  try {
    const vault = (await storageGet(STORE.VAULT)) || {};
    const sites = {};
    for (const [site, data] of Object.entries(vault)) {
      sites[site] = {
        username: data.username || 'Encrypted',
        createdAt: data.createdAt,
        updatedAt: data.updatedAt,
      };
    }
    return { success: true, data: sites };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ===== SETTINGS =====

async function handleGetSettings() {
  try {
    const settings = (await storageGet(STORE.SETTINGS)) || {};
    const recovery = (await storageGet(STORE.RECOVERY)) || {};
    return {
      success: true,
      data: { ...settings, recoveryEmail: recovery.email || '' },
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleSetRecoveryEmail(msg) {
  try {
    const recovery = (await storageGet(STORE.RECOVERY)) || {};
    recovery.email = msg.email;
    await storageSet(STORE.RECOVERY, recovery);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ===== RECOVERY (OTP) =====

const OTP_EXPIRY_MS = 5 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 3;

const EMAILJS_CONFIG = {
  serviceId: 'YOUR_SERVICE_ID',
  templateId: 'YOUR_TEMPLATE_ID',
  publicKey: 'YOUR_PUBLIC_KEY',
};

function generateOTP() {
  const arr = crypto.getRandomValues(new Uint8Array(4));
  const num = ((arr[0] << 24) | (arr[1] << 16) | (arr[2] << 8) | arr[3]) >>> 0;
  return (num % 900000 + 100000).toString();
}

function maskEmail(email) {
  const [local, domain] = email.split('@');
  return `${local[0]}***${local.length > 1 ? local[local.length - 1] : ''}@${domain}`;
}

async function handleStartRecovery() {
  try {
    const recovery = (await storageGet(STORE.RECOVERY)) || {};
    if (!recovery.email) {
      return { success: false, error: 'No recovery email configured' };
    }

    const otp = generateOTP();
    const otpHash = await sha256(otp);

    recovery.otpHash = otpHash;
    recovery.otpExpiry = Date.now() + OTP_EXPIRY_MS;
    recovery.otpAttempts = 0;
    await storageSet(STORE.RECOVERY, recovery);

    // Send via EmailJS
    try {
      const resp = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_id: EMAILJS_CONFIG.serviceId,
          template_id: EMAILJS_CONFIG.templateId,
          user_id: EMAILJS_CONFIG.publicKey,
          template_params: {
            to_email: recovery.email,
            otp_code: otp,
            expiry_minutes: '5',
          },
        }),
      });
      if (!resp.ok) {
        return { success: false, error: 'Failed to send email' };
      }
    } catch {
      return { success: false, error: 'Email service unavailable' };
    }

    return { success: true, maskedEmail: maskEmail(recovery.email) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleVerifyOTP(msg) {
  try {
    const recovery = (await storageGet(STORE.RECOVERY)) || {};

    if (!recovery.otpHash) return { success: false, error: 'No recovery in progress' };
    if (Date.now() > recovery.otpExpiry) {
      recovery.otpHash = null;
      await storageSet(STORE.RECOVERY, recovery);
      return { success: false, error: 'OTP expired' };
    }
    if (recovery.otpAttempts >= MAX_OTP_ATTEMPTS) {
      recovery.otpHash = null;
      await storageSet(STORE.RECOVERY, recovery);
      return { success: false, error: 'Too many attempts', locked: true };
    }

    recovery.otpAttempts = (recovery.otpAttempts || 0) + 1;
    await storageSet(STORE.RECOVERY, recovery);

    const inputHash = await sha256(msg.otp);
    if (inputHash !== recovery.otpHash) {
      if (recovery.otpAttempts >= MAX_OTP_ATTEMPTS) {
        recovery.otpHash = null;
        await storageSet(STORE.RECOVERY, recovery);
        return { success: false, error: 'Too many attempts', attempts: recovery.otpAttempts, locked: true };
      }
      return { success: false, error: 'Invalid code', attempts: recovery.otpAttempts };
    }

    // OTP correct — reconstruct VEK from halves
    recovery.otpHash = null;
    recovery.otpExpiry = null;
    recovery.otpAttempts = 0;
    await storageSet(STORE.RECOVERY, recovery);

    if (recovery.keyHalfA && recovery.keyHalfB) {
      const halfA = base64ToBuffer(recovery.keyHalfA);
      const halfB = base64ToBuffer(recovery.keyHalfB);
      activeVEK = combineKey(halfA, halfB);
    }

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ===== BACKUP =====

async function handleExportBackup() {
  try {
    const vault = (await storageGet(STORE.VAULT)) || {};
    const settings = (await storageGet(STORE.SETTINGS)) || {};
    const recovery = (await storageGet(STORE.RECOVERY)) || {};
    const encVEK = (await storageGet(STORE.VEK_ENCRYPTED)) || {};

    const backup = {
      version: '1.0.0',
      exportedAt: new Date().toISOString(),
      vault,
      encVEK,
      settings: { credentialId: settings.credentialId },
      recovery: {
        email: recovery.email,
        keyHalfA: recovery.keyHalfA,
        keyHalfB: recovery.keyHalfB,
      },
    };

    return { success: true, data: JSON.stringify(backup, null, 2) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleImportBackup(msg) {
  try {
    const backup = JSON.parse(msg.data);
    if (!backup.version || !backup.vault) {
      return { success: false, error: 'Invalid backup file' };
    }

    await storageSet(STORE.VAULT, backup.vault);
    if (backup.encVEK) await storageSet(STORE.VEK_ENCRYPTED, backup.encVEK);
    if (backup.settings?.credentialId) {
      const settings = (await storageGet(STORE.SETTINGS)) || {};
      settings.credentialId = backup.settings.credentialId;
      await storageSet(STORE.SETTINGS, settings);
    }
    if (backup.recovery) {
      const recovery = (await storageGet(STORE.RECOVERY)) || {};
      if (backup.recovery.email) recovery.email = backup.recovery.email;
      if (backup.recovery.keyHalfA) recovery.keyHalfA = backup.recovery.keyHalfA;
      if (backup.recovery.keyHalfB) recovery.keyHalfB = backup.recovery.keyHalfB;
      await storageSet(STORE.RECOVERY, recovery);
    }

    return { success: true };
  } catch {
    return { success: false, error: 'Invalid backup file format' };
  }
}

// ===== CONTENT SCRIPT HANDLERS =====

async function handleCheckSite(msg) {
  try {
    const vault = (await storageGet(STORE.VAULT)) || {};
    return { success: true, hasCredential: !!vault[msg.site] };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleAutofillRequest(msg) {
  if (!activeVEK) return { success: false, error: 'Vault is locked' };

  try {
    const vault = (await storageGet(STORE.VAULT)) || {};
    const cred = vault[msg.site];
    if (!cred) return { success: false, error: 'No credential found' };

    const password = await decryptData(cred.encPassword, cred.iv, activeVEK);
    return { success: true, data: { username: cred.username, password } };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ===== AUTO-LOCK =====
chrome.idle.onStateChanged.addListener((state) => {
  if (state === 'locked' || state === 'idle') {
    activeVEK = null;
    console.log('BioBridge: Vault auto-locked');
  }
});
