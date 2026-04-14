// ===== BioBridge Storage Module =====
// Wrapper around chrome.storage.local

const KEYS = {
  VAULT: 'biobridge_vault',
  RECOVERY: 'biobridge_recovery',
  SETTINGS: 'biobridge_settings',
};

/**
 * Get a value from storage
 * @param {string} key
 * @returns {Promise<any>}
 */
export async function get(key) {
  const result = await chrome.storage.local.get(key);
  return result[key] || null;
}

/**
 * Set a value in storage
 * @param {string} key
 * @param {any} value
 */
export async function set(key, value) {
  await chrome.storage.local.set({ [key]: value });
}

/**
 * Remove a key from storage
 * @param {string} key
 */
export async function remove(key) {
  await chrome.storage.local.remove(key);
}

// ===== VAULT OPERATIONS =====

/**
 * Get the entire vault
 * @returns {Promise<Object>}
 */
export async function getVault() {
  return (await get(KEYS.VAULT)) || {};
}

/**
 * Save the entire vault
 * @param {Object} vault
 */
export async function saveVault(vault) {
  await set(KEYS.VAULT, vault);
}

/**
 * Get encrypted credential for a site
 * @param {string} site
 * @returns {Promise<Object|null>}
 */
export async function getCredential(site) {
  const vault = await getVault();
  return vault[site] || null;
}

/**
 * Save encrypted credential for a site
 * @param {string} site
 * @param {Object} encryptedData
 */
export async function saveCredential(site, encryptedData) {
  const vault = await getVault();
  vault[site] = {
    ...encryptedData,
    createdAt: vault[site]?.createdAt || Date.now(),
    updatedAt: Date.now(),
  };
  await saveVault(vault);
}

/**
 * Delete credential for a site
 * @param {string} site
 */
export async function deleteCredential(site) {
  const vault = await getVault();
  delete vault[site];
  await saveVault(vault);
}

/**
 * Get all site names (without decrypted data)
 * @returns {Promise<Object>}
 */
export async function getAllSites() {
  const vault = await getVault();
  const sites = {};
  for (const [site, data] of Object.entries(vault)) {
    sites[site] = {
      username: data.username || 'Encrypted',
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
    };
  }
  return sites;
}

// ===== RECOVERY OPERATIONS =====

/**
 * Get recovery data
 * @returns {Promise<Object>}
 */
export async function getRecovery() {
  return (await get(KEYS.RECOVERY)) || {};
}

/**
 * Save recovery data
 * @param {Object} data
 */
export async function saveRecovery(data) {
  const existing = await getRecovery();
  await set(KEYS.RECOVERY, { ...existing, ...data });
}

// ===== SETTINGS OPERATIONS =====

/**
 * Get settings
 * @returns {Promise<Object>}
 */
export async function getSettings() {
  return (await get(KEYS.SETTINGS)) || {};
}

/**
 * Save settings
 * @param {Object} data
 */
export async function saveSettings(data) {
  const existing = await getSettings();
  await set(KEYS.SETTINGS, { ...existing, ...data });
}

export { KEYS };
