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

## 🛠️ Tech Stack

- **Hardware**: RP2350 (Raspberry Pi Pico 2)
- **Firmware**: C, TinyUSB, mbedTLS/wolfSSL
- **App Backend**: Rust, Tauri v2
- **App Frontend**: Modern Web Tech (Svelte/React/Vanilla)
- **Protocol**: CBOR, CDDL, COSE

## 📜 Licensing

This project is dual-licensed under:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

---
*VaultKey Stack — Open standards. Real security.*
