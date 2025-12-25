# VaultKey Protocol v1

This document specifies the communication protocol between the VaultKey Hardware (RP2350) and the VaultKey App (Tauri).

## 🛡️ Security Principles

- **Host-Untrusted**: The host PC is considered compromised. No cleartext secrets should ever be stored on the host.
- **Hardware-Enforced**: Cryptographic keys stay within the RP2350's Secure Storage.
- **CBOR/COSE**: We use CBOR for efficient binary serialization and COSE (CBOR Object Signing and Encryption) for message integrity and confidentiality.

## 🔐 Authentication Flow (Challenge-Response)

To unlock the vault, the App must prove knowledge of the user's PIN/Password through a challenge-response mechanism.

1.  **Handshake**: App sends a `Ping`. Device responds with `Pong`.
2.  **Challenge**: App requests `AuthChallenge`. Device generates a 32-byte cryptographically secure random challenge.
3.  **Response**: App derives a key from the user's PIN using Argon2id (on the host/app side) and signs/HMACs the challenge.
4.  **Verification**: Device verifies the HMAC. If valid, the vault enters the "Unlocked" state.

## 📦 Vault Storage

The vault is stored in the RP2350's internal flash or external secure SPI flash, encrypted using **AES-256-GCM**.

- **Master Key**: Derived within the hardware from a device-unique secret and the user-provided verification.
- **Entries**: Each entry is a CBOR structure containing:
    - `site`: Display name / URL
    - `username`: Cleartext
    - `password`: Encrypted
    - `notes`: Encrypted
    - `created_at`: Timestamp

## 📄 Schema

See [schema.cddl](schema.cddl) for the formal message definitions.
