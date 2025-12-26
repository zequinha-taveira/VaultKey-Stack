# VaultKey Stack

**Firmware + App + Protocolos**  
*Open standards. Real security.*

VaultKey Stack is a complete, 100% open-source stack for a hardware-backed password manager. It is designed around security, auditability, and modern open standards.

## 🚀 Vision

The project aims to provide a "Zero Trust" security model where the host computer is never fully trusted with sensitive secrets. All critical cryptographic operations happen inside the dedicated hardware (RP2350).

## 🧩 Architecture

- **VaultKey Firmware**: C-based firmware for the RP2350 microcontroller, leveraging the Pico SDK and secure hardware features.
- **VaultKey App**: A cross-platform desktop application built with Tauri v2 (Rust backend + Web frontend).
- **VaultKey Protocol**: A robust communication protocol based on CBOR and COSE for secure messaging between the host and the device.

## 🛡️ Security Features

- **Hardware Enclave**: All secrets are stored and processed on the RP2350. The host computer never sees your master PIN.
- **Hardware TRNG**: Uses the RP2350 hardware True Random Number Generator for all encryption nonces (IVs).
- **Hardened KDF**: PINs are derived into master keys using an iterative mixing algorithm with per-device salts.
- **Session Memory**: Authentication keys exist only in RAM and are zeroized upon disconnect or lockout.
- **Flash Lockout**: After 5 failed PIN attempts, the device hardware locks itself to prevent brute-force attacks.
- **Binary Integrity**: Encrypted data is authenticated via AES-GCM tags.

## 🛠️ Tech Stack

- **Hardware**: RP2350 (Raspberry Pi Pico 2)
- **Firmware**: C, Pico SDK, TinyUSB, Custom AES-GCM engine.
- **App Backend**: Rust, Tauri v2
- **App Frontend**: Modern JS + Vanilla CSS.

## 🏗️ Building

### Firmware (Reproducible)
To ensure binary bit-identity, build using Docker:
```bash
cd firmware
./build_docker.sh
```

### App
```bash
cd app
npm install
npm run tauri dev
```

## 📜 Licensing

This project is dual-licensed under:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

---
*VaultKey Stack — Open standards. Real security.*
