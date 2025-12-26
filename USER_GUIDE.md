# VaultKey User Guide 📖

Welcome to VaultKey! This guide will help you set up and master your hardware security key.

## 1. First Time Setup
1. **Connect**: Plug your VaultKey into a USB port.
2. **Open App**: Launch the VaultKey Desktop App.
3. **Initialize**: You will be prompted to set a **Master PIN**. 
   - *Security Tip*: Use a PIN with at least 8 characters. This PIN is processed using Argon2id for maximum protection.

## 2. Using the Vault
- **Unlock**: Enter your Master PIN to access your stored credentials.
- **Add Entry**: Click the "+" button, enter a name and the secret (password).
- **Auto-Type**: Select an entry and click "Type". VaultKey will emulate a keyboard and type the password for you.
- **Auto-Lock**: The vault will automatically lock after 5 minutes of inactivity (default).

## 3. TOTP (Authenticators)
- Add TOTP secrets (base32) to generate 6-digit codes.
- Codes refresh every 30 seconds.
- Click the code to copy it, or use "Type" to enter it automatically.

## 4. FIDO2 / WebAuthn
- **Registration**: When a website asks to "Register a Security Key", VaultKey's LED will blink fast. **Press the physical button** on the device to confirm.
- **Authentication**: When logging in, the LED will blink. Press the button again.
- **PIN**: Some sites may require a **FIDO2 PIN**. This is separate from your Master PIN and can be managed in the "FIDO2 Resident Keys" tab.

## 5. Hardware Signals (LED)
| LED Signal | Meaning |
|------------|---------|
| **Slow Blink** | Device is active and idle. |
| **Fast Blink** | **Action Required!** Press the button to confirm. |
| **Solid On** | Operation in progress (e.g., KDF calculating). |
| **Off** | Device locked or disconnected. |

## 6. Troubleshooting
- **Not Recognized**: Try a different USB port or cable.
- **Button Not Responding**: Ensure you are pressing the button when the LED is blinking fast.
- **LOCKED status**: If you enter the PIN wrong 5 times, the device locks. Power cycle the device to try again (Brute-force protection).

---
*Stay secure with VaultKey!*
