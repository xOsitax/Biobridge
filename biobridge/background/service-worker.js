// ===== BioBridge Service Worker =====
// Core engine: handles crypto, storage, auth, and message routing

import * as cryptoUtils from '../utils/crypto.js';
import * as storage from '../utils/storage.js';
import * as recovery from '../utils/recovery.js';

// In-memory vault encryption key (cleared on lock/browser close)
let activeVEK = null;

// ===== MESSAGE ROUTER =====
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch(err => {
      console.error('Message handler error:', err);
      sendResponse({ success: false, error: err.message });
    });

  return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
  switch (message.type) {

    case 'AUTHENTICATE':
      return handleAuthenticate();

    case 'LOCK_VAULT':
      return handleLock();

    case 'SAVE_CREDENTIAL':
      return handleSaveCredential(message);

    case 'GET_CREDENTIAL':
      return handleGetCredential(message);

    case 'UPDATE_CREDENTIAL':
      return handleUpdateCredential(message);

    case 'DELETE_CREDENTIAL':
      return handleDeleteCredential(message);

    case 'GET_ALL_SITES':
      return handleGetAllSites();

    case 'GET_SETTINGS':
      return handleGetSettings();

    case 'SET_RECOVERY_EMAIL':
      return handleSetRecoveryEmail(message);

    case 'START_RECOVERY':
      return handleStartRecovery();

    case 'VERIFY_OTP':
      return handleVerifyOTP(message);

    case 'EXPORT_BACKUP':
      return handleExportBackup();

    case 'IMPORT_BACKUP':
      return handleImportBackup(message);

    // Content script messages
    case 'CHECK_SITE':
      return handleCheckSite(message);

    case 'AUTOFILL_REQUEST':
      return handleAutofillRequest(message);

    case 'SAVE_FROM_CONTENT':
      return handleSaveFromContent(message);

    default:
      return { success: false, error: 'Unknown message type' };
  }
}

// ===== AUTH HANDLERS =====

async function handleAuthenticate() {
  try {
    const settings = await storage.getSettings();

    if (!settings.credentialId) {
      // First time: register biometrics
      // WebAuthn must run in a page context, not service worker
      // So we'll use an offscreen document or popup context
      return { success: false, error: 'NEEDS_REGISTRATION', firstTime: true };
    }

    // Returning user: authenticate and derive key
    // Note: WebAuthn needs to run in popup context, 
    // the popup handles the actual WebAuthn call and sends the key
    return { success: false, error: 'AUTH_IN_POPUP' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Called by popup after successful WebAuthn authentication
 * Stores the derived key in memory
 */
async function handleSetVEK(rawKeyB64) {
  activeVEK = cryptoUtils.base64ToBuffer(rawKeyB64);
  return { success: true };
}

async function handleLock() {
  activeVEK = null;
  return { success: true };
}

// ===== CREDENTIAL HANDLERS =====

async function handleSaveCredential(message) {
  if (!activeVEK) {
    return { success: false, error: 'Vault is locked' };
  }

  const { site, username, password } = message;

  try {
    const encryptedPassword = await cryptoUtils.encrypt(password, activeVEK);

    await storage.saveCredential(site, {
      username: username,
      encPassword: encryptedPassword.ciphertext,
      iv: encryptedPassword.iv,
      salt: encryptedPassword.salt,
    });

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleGetCredential(message) {
  if (!activeVEK) {
    return { success: false, error: 'Vault is locked' };
  }

  const { site } = message;

  try {
    const credential = await storage.getCredential(site);
    if (!credential) {
      return { success: false, error: 'Credential not found' };
    }

    const password = await cryptoUtils.decrypt(
      credential.encPassword,
      credential.iv,
      activeVEK
    );

    return {
      success: true,
      data: {
        username: credential.username,
        password: password,
      },
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleUpdateCredential(message) {
  if (!activeVEK) {
    return { success: false, error: 'Vault is locked' };
  }

  const { site, username, password } = message;

  try {
    const encryptedPassword = await cryptoUtils.encrypt(password, activeVEK);

    await storage.saveCredential(site, {
      username: username,
      encPassword: encryptedPassword.ciphertext,
      iv: encryptedPassword.iv,
      salt: encryptedPassword.salt,
    });

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleDeleteCredential(message) {
  const { site } = message;

  try {
    await storage.deleteCredential(site);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleGetAllSites() {
  try {
    const sites = await storage.getAllSites();
    return { success: true, data: sites };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ===== SETTINGS HANDLERS =====

async function handleGetSettings() {
  try {
    const settings = await storage.getSettings();
    const recoveryData = await storage.getRecovery();
    return {
      success: true,
      data: {
        ...settings,
        recoveryEmail: recoveryData.email || '',
      },
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleSetRecoveryEmail(message) {
  try {
    await storage.saveRecovery({ email: message.email });
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ===== RECOVERY HANDLERS =====

async function handleStartRecovery() {
  try {
    return await recovery.startRecovery();
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleVerifyOTP(message) {
  try {
    const result = await recovery.verifyOTP(message.otp);

    if (result.success) {
      // On successful recovery, reconstruct the VEK from stored halves
      const recoveryData = await storage.getRecovery();
      if (recoveryData.keyHalfA && recoveryData.keyHalfB) {
        const halfA = cryptoUtils.base64ToBuffer(recoveryData.keyHalfA);
        const halfB = cryptoUtils.base64ToBuffer(recoveryData.keyHalfB);
        activeVEK = cryptoUtils.combineKey(halfA, halfB);
      }
    }

    return result;
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ===== BACKUP HANDLERS =====

async function handleExportBackup() {
  try {
    const vault = await storage.getVault();
    const settings = await storage.getSettings();
    const recoveryData = await storage.getRecovery();

    const backup = {
      version: '1.0.0',
      exportedAt: new Date().toISOString(),
      vault: vault,
      settings: {
        credentialId: settings.credentialId,
      },
      recovery: {
        email: recoveryData.email,
        keyHalfA: recoveryData.keyHalfA,
        keyHalfB: recoveryData.keyHalfB,
      },
    };

    return { success: true, data: JSON.stringify(backup, null, 2) };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleImportBackup(message) {
  try {
    const backup = JSON.parse(message.data);

    if (!backup.version || !backup.vault) {
      return { success: false, error: 'Invalid backup file' };
    }

    await storage.saveVault(backup.vault);

    if (backup.settings?.credentialId) {
      await storage.saveSettings({ credentialId: backup.settings.credentialId });
    }

    if (backup.recovery) {
      await storage.saveRecovery(backup.recovery);
    }

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Invalid backup file format' };
  }
}

// ===== CONTENT SCRIPT HANDLERS =====

async function handleCheckSite(message) {
  const { site } = message;
  try {
    const credential = await storage.getCredential(site);
    return { success: true, hasCredential: !!credential };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleAutofillRequest(message) {
  if (!activeVEK) {
    return { success: false, error: 'Vault is locked' };
  }

  const { site } = message;

  try {
    const credential = await storage.getCredential(site);
    if (!credential) {
      return { success: false, error: 'No credential found' };
    }

    const password = await cryptoUtils.decrypt(
      credential.encPassword,
      credential.iv,
      activeVEK
    );

    return {
      success: true,
      data: {
        username: credential.username,
        password: password,
      },
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function handleSaveFromContent(message) {
  if (!activeVEK) {
    return { success: false, error: 'Vault is locked' };
  }

  return handleSaveCredential(message);
}

// ===== AUTO-LOCK ON IDLE =====
chrome.idle.onStateChanged.addListener((state) => {
  if (state === 'locked' || state === 'idle') {
    activeVEK = null;
    console.log('BioBridge: Vault auto-locked due to inactivity');
  }
});
