# VaultKey Stack - Threat Model (STRIDE)

This document analyzes security threats to the VaultKey Stack and outlines our mitigation strategies.

## 🎯 Assets to Protect
1.  **User Secrets**: Passwords, notes, and keys stored in the vault.
2.  **Master Key**: The root of trust derived from the user's PIN.
3.  **Device Integrity**: Assurance that the firmware hasn't been tampered with.

---

## 🛡️ STRIDE Analysis

| Threat Category | Potential Threat | Mitigation Strategy |
| :--- | :--- | :--- |
| **Spoofing** | Attacker creates a fake VaultKey app to steal PINs. | Firmware should use a visual indicator (LED) when unlocked. App binaries should be signed. |
| **Tampering** | Malware on host modifies CDDL messages to extract secrets. | Use COSE for end-to-end encryption and integrity between App and Firmware. |
| **Repudiation** | Attacker claims a vault action was performed without authorization. | Implement secure logging (Phase 5) and physical button confirmation for critical actions. |
| **Information Disclosure** | Memory scraping of the host app to extract the derived master key. | Use `zeroize` in Rust (done) and zeroize memory in C (Phase 2). Minimize key lifetime in RAM. |
| **Denial of Service** | Flooding the device with requests to lock it out or drain battery. | Hardware-enforced rate limiting and exponential backoff for failed PIN attempts. |
| **Elevation of Privilege** | Exploiting a buffer overflow in the CBOR parser to run arbitrary code. | Use memory-safe Rust for the bridge. Use hardened CBOR parsers (QCBOR) and fuzzing in firmware. |

---

## 📈 Risk Matrix

- **High Risk**: Host compromise (malware). Our "Zero Trust" model assumes the host is untrusted.
- **Medium Risk**: Physical theft of the device. Mitigation: PIN protection and hardware-backed KDF.
- **Low Risk**: Supply chain attack on Pico SDK. Mitigation: Build reproducibility and SBOM.

---
*VaultKey Stack — Open standards. Real security.*
