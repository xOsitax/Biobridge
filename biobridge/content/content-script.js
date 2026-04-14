// ===== BioBridge Content Script =====
// Detects login forms, shows BioBridge UI overlay, handles JIT injection

(function () {
  'use strict';

  const SITE = window.location.hostname;
  let biobridgeBanner = null;

  // ===== LOGIN FORM DETECTION =====

  /**
   * Find password fields on the page
   * @returns {HTMLInputElement[]}
   */
  function findPasswordFields() {
    return Array.from(document.querySelectorAll('input[type="password"]'));
  }

  /**
   * Find username field near a password field
   * @param {HTMLInputElement} passwordField
   * @returns {HTMLInputElement|null}
   */
  function findUsernameField(passwordField) {
    const form = passwordField.closest('form');
    const container = form || document.body;

    // Look for common username/email inputs
    const selectors = [
      'input[type="email"]',
      'input[type="text"][name*="user"]',
      'input[type="text"][name*="email"]',
      'input[type="text"][name*="login"]',
      'input[type="text"][autocomplete="username"]',
      'input[autocomplete="email"]',
      'input[type="text"][id*="user"]',
      'input[type="text"][id*="email"]',
      'input[type="text"][id*="login"]',
      'input[type="text"]',
    ];

    for (const selector of selectors) {
      const fields = container.querySelectorAll(selector);
      for (const field of fields) {
        if (field !== passwordField && isVisible(field)) {
          return field;
        }
      }
    }

    return null;
  }

  /**
   * Check if an element is visible on page
   * @param {HTMLElement} el
   * @returns {boolean}
   */
  function isVisible(el) {
    const style = window.getComputedStyle(el);
    return (
      style.display !== 'none' &&
      style.visibility !== 'hidden' &&
      style.opacity !== '0' &&
      el.offsetParent !== null
    );
  }

  // ===== BIOBRIDGE BANNER =====

  /**
   * Show BioBridge banner near the login form
   * @param {HTMLInputElement} passwordField
   * @param {boolean} hasSavedCredential
   */
  function showBanner(passwordField, hasSavedCredential) {
    if (biobridgeBanner) biobridgeBanner.remove();

    biobridgeBanner = document.createElement('div');
    biobridgeBanner.id = 'biobridge-banner';

    if (hasSavedCredential) {
      biobridgeBanner.innerHTML = `
        <div class="bb-banner-content">
          <span class="bb-logo">🔒</span>
          <span class="bb-text">BioBridge has your login</span>
          <button id="bb-autofill-btn" class="bb-btn bb-btn-primary">👆 Unlock & Fill</button>
          <button id="bb-dismiss-btn" class="bb-btn bb-btn-dismiss">✕</button>
        </div>
      `;
    } else {
      biobridgeBanner.innerHTML = `
        <div class="bb-banner-content">
          <span class="bb-logo">🔒</span>
          <span class="bb-text">Save this login to BioBridge?</span>
          <button id="bb-save-btn" class="bb-btn bb-btn-primary">💾 Save</button>
          <button id="bb-dismiss-btn" class="bb-btn bb-btn-dismiss">✕</button>
        </div>
      `;
    }

    // Insert banner near the password field
    const form = passwordField.closest('form');
    const insertTarget = form || passwordField.parentElement;
    insertTarget.insertAdjacentElement('beforebegin', biobridgeBanner);

    // Event listeners
    const dismissBtn = document.getElementById('bb-dismiss-btn');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => biobridgeBanner.remove());
    }

    const autofillBtn = document.getElementById('bb-autofill-btn');
    if (autofillBtn) {
      autofillBtn.addEventListener('click', () => handleAutofill(passwordField));
    }

    const saveBtn = document.getElementById('bb-save-btn');
    if (saveBtn) {
      saveBtn.addEventListener('click', () => handleSave(passwordField));
    }
  }

  // ===== AUTOFILL (JIT INJECTION) =====

  /**
   * Request credentials and inject into form with JIT timing
   * @param {HTMLInputElement} passwordField
   */
  async function handleAutofill(passwordField) {
    const autofillBtn = document.getElementById('bb-autofill-btn');
    if (autofillBtn) {
      autofillBtn.textContent = '⏳ Verifying...';
      autofillBtn.disabled = true;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'AUTOFILL_REQUEST',
        site: SITE,
      });

      if (!response?.success) {
        showBannerMessage('Vault is locked. Open BioBridge popup to authenticate.', 'error');
        return;
      }

      const { username, password } = response.data;
      const usernameField = findUsernameField(passwordField);

      // JIT Injection: fill and submit within 200ms
      const startTime = performance.now();

      // Fill username
      if (usernameField && username) {
        setNativeValue(usernameField, username);
      }

      // Fill password
      setNativeValue(passwordField, password);

      // Auto-submit the form
      const form = passwordField.closest('form');
      if (form) {
        // Small delay to let any JS validators run
        setTimeout(() => {
          form.submit();
        }, 50);
      }

      const elapsed = performance.now() - startTime;
      console.log(`BioBridge: JIT injection completed in ${elapsed.toFixed(1)}ms`);

      // Clear password from DOM after submission starts
      setTimeout(() => {
        setNativeValue(passwordField, '');
        if (biobridgeBanner) biobridgeBanner.remove();
      }, 200);

    } catch (err) {
      console.error('BioBridge autofill error:', err);
      showBannerMessage('Autofill failed. Try opening BioBridge popup.', 'error');
    }
  }

  // ===== SAVE CREDENTIALS =====

  /**
   * Save current form credentials to BioBridge
   * @param {HTMLInputElement} passwordField
   */
  async function handleSave(passwordField) {
    const usernameField = findUsernameField(passwordField);
    const username = usernameField?.value || '';
    const password = passwordField.value;

    if (!password) {
      showBannerMessage('Enter your password first, then click Save.', 'error');
      return;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'SAVE_FROM_CONTENT',
        site: SITE,
        username: username,
        password: password,
      });

      if (response?.success) {
        showBannerMessage('✅ Saved to BioBridge!', 'success');
        setTimeout(() => biobridgeBanner?.remove(), 2000);
      } else {
        showBannerMessage(
          response?.error === 'Vault is locked'
            ? 'Open BioBridge popup and authenticate first.'
            : 'Save failed. Try again.',
          'error'
        );
      }
    } catch (err) {
      console.error('BioBridge save error:', err);
      showBannerMessage('Save failed.', 'error');
    }
  }

  // ===== HELPERS =====

  /**
   * Set value on input using native setter (bypasses React/Angular)
   * @param {HTMLInputElement} input
   * @param {string} value
   */
  function setNativeValue(input, value) {
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    ).set;
    nativeInputValueSetter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  /**
   * Show a message in the banner
   * @param {string} message
   * @param {'success'|'error'} type
   */
  function showBannerMessage(message, type) {
    if (!biobridgeBanner) return;
    const content = biobridgeBanner.querySelector('.bb-banner-content');
    if (content) {
      content.innerHTML = `
        <span class="bb-logo">${type === 'success' ? '✅' : '⚠️'}</span>
        <span class="bb-text bb-text-${type}">${message}</span>
        <button id="bb-dismiss-btn" class="bb-btn bb-btn-dismiss">✕</button>
      `;
      document.getElementById('bb-dismiss-btn')?.addEventListener('click', () => {
        biobridgeBanner.remove();
      });
    }
  }

  // ===== INITIALIZATION =====

  async function init() {
    // Wait a bit for dynamic pages to load
    await new Promise(r => setTimeout(r, 500));

    const passwordFields = findPasswordFields();
    if (passwordFields.length === 0) return;

    // Check if we have saved credentials for this site
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'CHECK_SITE',
        site: SITE,
      });

      const hasSaved = response?.success && response.hasCredential;
      showBanner(passwordFields[0], hasSaved);
    } catch (err) {
      console.error('BioBridge init error:', err);
    }
  }

  // Run on page load
  if (document.readyState === 'complete') {
    init();
  } else {
    window.addEventListener('load', init);
  }

  // Watch for dynamically added login forms (SPAs)
  const observer = new MutationObserver(() => {
    const passwordFields = findPasswordFields();
    if (passwordFields.length > 0 && !document.getElementById('biobridge-banner')) {
      init();
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
})();
