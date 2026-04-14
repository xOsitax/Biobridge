// ===== SCREEN MANAGEMENT =====
const screens = {
  locked: document.getElementById('screen-locked'),
  unlocked: document.getElementById('screen-unlocked'),
  failed: document.getElementById('screen-failed'),
  recovery: document.getElementById('screen-recovery'),
  settings: document.getElementById('screen-settings'),
  edit: document.getElementById('screen-edit'),
  add: document.getElementById('screen-add'),
};

function showScreen(screenName) {
  Object.values(screens).forEach(s => s.classList.remove('active'));
  screens[screenName].classList.add('active');
}

// ===== TOAST NOTIFICATIONS =====
function showToast(message, type = 'success') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

// ===== OTP INPUT HANDLING =====
const otpBoxes = document.querySelectorAll('.otp-box');

otpBoxes.forEach((box, index) => {
  box.addEventListener('input', (e) => {
    e.target.value = e.target.value.replace(/[^0-9]/g, '');
    if (e.target.value && index < otpBoxes.length - 1) {
      otpBoxes[index + 1].focus();
    }
  });

  box.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && !box.value && index > 0) {
      otpBoxes[index - 1].focus();
    }
  });
});

function getOtpValue() {
  return Array.from(otpBoxes).map(b => b.value).join('');
}

function clearOtp() {
  otpBoxes.forEach(b => (b.value = ''));
  otpBoxes[0]?.focus();
}

// ===== OTP TIMER =====
let otpTimerInterval = null;

function startOtpTimer(seconds = 300) {
  clearInterval(otpTimerInterval);
  const timerEl = document.getElementById('otp-timer');
  let remaining = seconds;

  otpTimerInterval = setInterval(() => {
    remaining--;
    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    timerEl.textContent = `${mins}:${secs.toString().padStart(2, '0')}`;

    if (remaining <= 0) {
      clearInterval(otpTimerInterval);
      timerEl.textContent = 'Expired';
      showToast('OTP expired. Please try again.', 'error');
      setTimeout(() => showScreen('failed'), 1500);
    }
  }, 1000);
}

function stopOtpTimer() {
  clearInterval(otpTimerInterval);
}

// =========================================================
// ===== WEBAUTHN — Runs directly in popup context =====
// =========================================================

const RP_NAME = 'BioBridge';

/**
 * Check if platform authenticator (Touch ID / Windows Hello) is available
 */
async function isBiometricAvailable() {
  if (!window.PublicKeyCredential) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * Register biometric credential (first time setup)
 * Triggers Touch ID / Windows Hello enrollment
 * Returns credential ID as base64 string
 */
async function registerBiometric() {
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const createOptions = {
    publicKey: {
      challenge: challenge,
      rp: {
        name: RP_NAME,
        // Don't set rp.id — let the browser use the default (extension origin)
      },
      user: {
        id: userId,
        name: 'biobridge-user',
        displayName: 'BioBridge User',
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },    // ES256
        { alg: -257, type: 'public-key' },   // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',  // Use built-in sensor
        userVerification: 'required',         // Must verify identity
        residentKey: 'discouraged',
      },
      timeout: 120000,
    },
  };

  const credential = await navigator.credentials.create(createOptions);
  return bufferToBase64(credential.rawId);
}

/**
 * Authenticate with biometrics (returning user)
 * Triggers Touch ID / Windows Hello prompt
 * Returns true on success, throws on failure
 */
async function authenticateBiometric(credentialIdB64) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const getOptions = {
    publicKey: {
      challenge: challenge,
      allowCredentials: [
        {
          id: base64ToBuffer(credentialIdB64),
          type: 'public-key',
          transports: ['internal'],
        },
      ],
      userVerification: 'required',
      timeout: 120000,
    },
  };

  // This line triggers the actual biometric prompt
  await navigator.credentials.get(getOptions);
  return true;
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

// =========================================================
// ===== MAIN AUTHENTICATION FLOW =====
// =========================================================

document.getElementById('btn-authenticate').addEventListener('click', async () => {
  const btn = document.getElementById('btn-authenticate');
  btn.innerHTML = '⏳ Waiting for biometric...';
  btn.disabled = true;

  try {
    // Step 1: Check if biometrics are available on this device
    const available = await isBiometricAvailable();
    if (!available) {
      showToast('No biometric sensor found on this device', 'error');
      showScreen('failed');
      resetAuthButton();
      return;
    }

    // Step 2: Check if user has registered before
    const settingsResp = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    const credentialId = settingsResp?.data?.credentialId;

    if (!credentialId) {
      // ============================
      // FIRST TIME SETUP
      // ============================
      btn.innerHTML = '👆 Place finger on sensor...';

      // This triggers the biometric prompt (Touch ID / Windows Hello)
      const newCredentialId = await registerBiometric();

      // Tell background to generate encryption key and store credential ID
      const setupResult = await chrome.runtime.sendMessage({
        type: 'FIRST_TIME_SETUP',
        credentialId: newCredentialId,
      });

      if (setupResult?.success) {
        showToast('Biometric registered! Vault is ready.');
        await loadCredentials();
        showScreen('unlocked');
      } else {
        showToast('Setup failed: ' + (setupResult?.error || 'Unknown error'), 'error');
        showScreen('failed');
      }

    } else {
      // ============================
      // RETURNING USER — VERIFY
      // ============================
      btn.innerHTML = '👆 Place finger on sensor...';

      // This triggers the biometric prompt
      await authenticateBiometric(credentialId);

      // Biometric passed! Tell background to unlock the vault
      const unlockResult = await chrome.runtime.sendMessage({ type: 'UNLOCK_VAULT' });

      if (unlockResult?.success) {
        showToast('Authentication successful!');
        await loadCredentials();
        showScreen('unlocked');
      } else {
        showToast('Vault unlock failed', 'error');
        showScreen('failed');
      }
    }

  } catch (err) {
    console.error('Biometric error:', err);

    if (err.name === 'NotAllowedError') {
      showToast('Biometric was cancelled or denied', 'error');
    } else if (err.name === 'SecurityError') {
      showToast('Security error — try reloading the extension', 'error');
    } else if (err.name === 'InvalidStateError') {
      showToast('Biometric already registered. Try authenticating.', 'error');
    } else {
      showToast('Biometric failed: ' + (err.message || 'Unknown error'), 'error');
    }

    showScreen('failed');
  } finally {
    resetAuthButton();
  }
});

function resetAuthButton() {
  const btn = document.getElementById('btn-authenticate');
  btn.innerHTML = '<span class="btn-icon">👆</span> Use Fingerprint';
  btn.disabled = false;
}

// ===== CREDENTIAL RENDERING =====
function renderCredentials(credentials) {
  const list = document.getElementById('credentials-list');
  const emptyState = document.getElementById('empty-state');

  list.querySelectorAll('.credential-card').forEach(c => c.remove());

  if (!credentials || Object.keys(credentials).length === 0) {
    emptyState.classList.remove('hidden');
    return;
  }

  emptyState.classList.add('hidden');

  Object.entries(credentials).forEach(([site, data]) => {
    const card = document.createElement('div');
    card.className = 'credential-card';
    card.innerHTML = `
      <div class="credential-site">
        <img class="credential-site-icon"
             src="https://www.google.com/s2/favicons?domain=${site}&sz=32"
             alt="" onerror="this.style.display='none'">
        ${site}
      </div>
      <div class="credential-user">${data.username || 'No username'}</div>
      <div class="credential-actions">
        <button class="btn btn-secondary btn-small" data-action="edit" data-site="${site}">✏️ Edit</button>
        <button class="btn btn-danger btn-small" data-action="delete" data-site="${site}">🗑️ Delete</button>
      </div>
    `;
    list.insertBefore(card, emptyState);
  });
}

// ===== EVENT DELEGATION FOR CREDENTIAL ACTIONS =====
let currentEditSite = null;

document.getElementById('credentials-list').addEventListener('click', async (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;

  const action = btn.dataset.action;
  const site = btn.dataset.site;

  if (action === 'edit') {
    currentEditSite = site;
    document.getElementById('edit-site-name').textContent = site;

    const response = await chrome.runtime.sendMessage({
      type: 'GET_CREDENTIAL',
      site: site,
    });

    if (response?.success) {
      document.getElementById('edit-username').value = response.data.username || '';
      document.getElementById('edit-password').value = response.data.password || '';
      showScreen('edit');
    } else {
      showToast('Failed to load credential', 'error');
    }
  }

  if (action === 'delete') {
    if (confirm(`Delete credentials for ${site}?`)) {
      const response = await chrome.runtime.sendMessage({
        type: 'DELETE_CREDENTIAL',
        site: site,
      });

      if (response?.success) {
        showToast(`Deleted ${site}`);
        loadCredentials();
      } else {
        showToast('Failed to delete', 'error');
      }
    }
  }
});

// ===== LOAD CREDENTIALS FROM STORAGE =====
async function loadCredentials() {
  const response = await chrome.runtime.sendMessage({ type: 'GET_ALL_SITES' });
  if (response?.success) {
    renderCredentials(response.data);
  }
}

// ===== PASSWORD VISIBILITY TOGGLE =====
document.getElementById('btn-toggle-password').addEventListener('click', () => {
  const input = document.getElementById('edit-password');
  input.type = input.type === 'password' ? 'text' : 'password';
});

// ===== ALL OTHER BUTTON LISTENERS =====

// Failed → Try Again
document.getElementById('btn-retry').addEventListener('click', () => {
  showScreen('locked');
});

// Failed → Go to Recovery
document.getElementById('btn-goto-recovery').addEventListener('click', async () => {
  const response = await chrome.runtime.sendMessage({ type: 'START_RECOVERY' });
  if (response?.success) {
    document.getElementById('recovery-email-masked').textContent = response.maskedEmail;
    document.getElementById('otp-attempts').textContent = '0';
    clearOtp();
    startOtpTimer(300);
    showScreen('recovery');
  } else {
    showToast(response?.error || 'No recovery email set. Go to Settings first.', 'error');
  }
});

// Recovery → Verify OTP
document.getElementById('btn-verify-otp').addEventListener('click', async () => {
  const otp = getOtpValue();
  if (otp.length !== 6) {
    document.getElementById('otp-error').textContent = 'Please enter all 6 digits';
    document.getElementById('otp-error').classList.remove('hidden');
    return;
  }

  const response = await chrome.runtime.sendMessage({
    type: 'VERIFY_OTP',
    otp: otp,
  });

  if (response?.success) {
    stopOtpTimer();
    showToast('Recovery successful!');
    await loadCredentials();
    showScreen('unlocked');
  } else {
    document.getElementById('otp-attempts').textContent = response?.attempts || '?';
    document.getElementById('otp-error').textContent = response?.error || 'Invalid code';
    document.getElementById('otp-error').classList.remove('hidden');
    clearOtp();

    if (response?.locked) {
      stopOtpTimer();
      showToast('Too many attempts. Try again later.', 'error');
      setTimeout(() => showScreen('locked'), 2000);
    }
  }
});

// Recovery → Back
document.getElementById('btn-recovery-back').addEventListener('click', () => {
  stopOtpTimer();
  showScreen('failed');
});

// Unlocked → Lock
document.getElementById('btn-lock').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'LOCK_VAULT' });
  showToast('Vault locked');
  showScreen('locked');
});

// Unlocked → Settings
document.getElementById('btn-settings').addEventListener('click', async () => {
  const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
  if (response?.success && response.data?.recoveryEmail) {
    document.getElementById('input-recovery-email').value = response.data.recoveryEmail;
  }
  showScreen('settings');
});

// Unlocked → Add New
document.getElementById('btn-add-new').addEventListener('click', () => {
  document.getElementById('add-site').value = '';
  document.getElementById('add-username').value = '';
  document.getElementById('add-password').value = '';
  showScreen('add');
});

// Locked → Setup Recovery
document.getElementById('btn-goto-setup').addEventListener('click', () => {
  showScreen('settings');
});

// Settings → Save Email
document.getElementById('btn-save-email').addEventListener('click', async () => {
  const email = document.getElementById('input-recovery-email').value.trim();
  if (!email || !email.includes('@')) {
    showToast('Enter a valid email', 'error');
    return;
  }

  const response = await chrome.runtime.sendMessage({
    type: 'SET_RECOVERY_EMAIL',
    email: email,
  });

  if (response?.success) {
    showToast('Recovery email saved!');
  } else {
    showToast('Failed to save email', 'error');
  }
});

// Settings → Export
document.getElementById('btn-export').addEventListener('click', async () => {
  const response = await chrome.runtime.sendMessage({ type: 'EXPORT_BACKUP' });
  if (response?.success) {
    const blob = new Blob([response.data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `biobridge-backup-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Backup exported!');
  } else {
    showToast('Export failed', 'error');
  }
});

// Settings → Import
document.getElementById('btn-import').addEventListener('click', () => {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const text = await file.text();
    const response = await chrome.runtime.sendMessage({
      type: 'IMPORT_BACKUP',
      data: text,
    });

    if (response?.success) {
      showToast('Backup imported!');
      await loadCredentials();
    } else {
      showToast(response?.error || 'Import failed', 'error');
    }
  });
  input.click();
});

// Settings → Back
document.getElementById('btn-settings-back').addEventListener('click', () => {
  showScreen('unlocked');
});

// Edit → Save
document.getElementById('btn-save-edit').addEventListener('click', async () => {
  const username = document.getElementById('edit-username').value.trim();
  const password = document.getElementById('edit-password').value;

  if (!username || !password) {
    showToast('Both fields are required', 'error');
    return;
  }

  const response = await chrome.runtime.sendMessage({
    type: 'UPDATE_CREDENTIAL',
    site: currentEditSite,
    username: username,
    password: password,
  });

  if (response?.success) {
    showToast('Credential updated!');
    await loadCredentials();
    showScreen('unlocked');
  } else {
    showToast('Update failed', 'error');
  }
});

// Edit → Back
document.getElementById('btn-cancel-edit').addEventListener('click', () => {
  showScreen('unlocked');
});

// Add → Save
document.getElementById('btn-save-add').addEventListener('click', async () => {
  const site = document.getElementById('add-site').value.trim();
  const username = document.getElementById('add-username').value.trim();
  const password = document.getElementById('add-password').value;

  if (!site || !username || !password) {
    showToast('All fields are required', 'error');
    return;
  }

  const response = await chrome.runtime.sendMessage({
    type: 'SAVE_CREDENTIAL',
    site: site,
    username: username,
    password: password,
  });

  if (response?.success) {
    showToast('Credential saved!');
    await loadCredentials();
    showScreen('unlocked');
  } else {
    showToast(response?.error || 'Save failed', 'error');
  }
});

// Add → Back
document.getElementById('btn-cancel-add').addEventListener('click', () => {
  showScreen('unlocked');
});

// ===== INITIAL STATE =====
showScreen('locked');
