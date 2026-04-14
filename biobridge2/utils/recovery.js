// ===== BioBridge Recovery Module =====
// Handles OTP generation, verification, and email sending via EmailJS

import { sha256 } from './crypto.js';
import * as storage from './storage.js';

const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const MAX_ATTEMPTS = 3;

// EmailJS configuration - replace with your actual IDs
const EMAILJS_CONFIG = {
  serviceId: 'YOUR_SERVICE_ID',       // Replace after EmailJS setup
  templateId: 'YOUR_TEMPLATE_ID',     // Replace after EmailJS setup
  publicKey: 'YOUR_PUBLIC_KEY',       // Replace after EmailJS setup
};

/**
 * Generate a random 6-digit OTP
 * @returns {string}
 */
export function generateOTP() {
  const array = crypto.getRandomValues(new Uint8Array(4));
  const num = ((array[0] << 24) | (array[1] << 16) | (array[2] << 8) | array[3]) >>> 0;
  const otp = (num % 900000 + 100000).toString();
  return otp;
}

/**
 * Mask an email address for display
 * @param {string} email
 * @returns {string}
 */
export function maskEmail(email) {
  const [local, domain] = email.split('@');
  const maskedLocal = local[0] + '***' + (local.length > 1 ? local[local.length - 1] : '');
  return `${maskedLocal}@${domain}`;
}

/**
 * Start recovery: generate OTP, hash it, store it, send email
 * @returns {Promise<{ success: boolean, maskedEmail?: string, error?: string }>}
 */
export async function startRecovery() {
  const recovery = await storage.getRecovery();

  if (!recovery.email) {
    return { success: false, error: 'No recovery email configured' };
  }

  const otp = generateOTP();
  const otpHash = await sha256(otp);

  // Store hashed OTP with expiry and attempt counter
  await storage.saveRecovery({
    otpHash: otpHash,
    otpExpiry: Date.now() + OTP_EXPIRY_MS,
    otpAttempts: 0,
  });

  // Send OTP via EmailJS
  const sent = await sendOTPEmail(recovery.email, otp);
  if (!sent) {
    return { success: false, error: 'Failed to send recovery email' };
  }

  return {
    success: true,
    maskedEmail: maskEmail(recovery.email),
  };
}

/**
 * Verify an OTP entered by the user
 * @param {string} otp - 6-digit code from user
 * @returns {Promise<{ success: boolean, error?: string, attempts?: number, locked?: boolean }>}
 */
export async function verifyOTP(otp) {
  const recovery = await storage.getRecovery();

  // Check if OTP exists
  if (!recovery.otpHash) {
    return { success: false, error: 'No recovery in progress' };
  }

  // Check expiry
  if (Date.now() > recovery.otpExpiry) {
    await clearOTP();
    return { success: false, error: 'OTP expired. Please try again.' };
  }

  // Check attempts
  if (recovery.otpAttempts >= MAX_ATTEMPTS) {
    await clearOTP();
    return { success: false, error: 'Too many attempts', locked: true };
  }

  // Increment attempts
  const newAttempts = (recovery.otpAttempts || 0) + 1;
  await storage.saveRecovery({ otpAttempts: newAttempts });

  // Verify hash
  const inputHash = await sha256(otp);
  if (inputHash !== recovery.otpHash) {
    if (newAttempts >= MAX_ATTEMPTS) {
      await clearOTP();
      return { success: false, error: 'Too many attempts', attempts: newAttempts, locked: true };
    }
    return { success: false, error: 'Invalid code', attempts: newAttempts };
  }

  // Success - clear OTP data
  await clearOTP();
  return { success: true };
}

/**
 * Clear OTP data from storage
 */
async function clearOTP() {
  await storage.saveRecovery({
    otpHash: null,
    otpExpiry: null,
    otpAttempts: 0,
  });
}

/**
 * Send OTP via EmailJS
 * @param {string} email - Recipient email
 * @param {string} otp - 6-digit OTP
 * @returns {Promise<boolean>}
 */
async function sendOTPEmail(email, otp) {
  try {
    const response = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service_id: EMAILJS_CONFIG.serviceId,
        template_id: EMAILJS_CONFIG.templateId,
        user_id: EMAILJS_CONFIG.publicKey,
        template_params: {
          to_email: email,
          otp_code: otp,
          expiry_minutes: '5',
        },
      }),
    });

    return response.ok;
  } catch (err) {
    console.error('EmailJS send error:', err);
    return false;
  }
}
