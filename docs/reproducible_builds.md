# Reproducible Builds

To ensure the integrity of the VaultKey Stack, all binaries must be reproducible. This means that anyone should be able to compile the source code and get the exact same binary output.

## 🛠️ Requirements
- **Docker**: Used to provide a consistent build environment.
- **Pinned Versions**: All compilers and libraries are pinned to specific versions.

## 📦 Firmware (RP2350)
The firmware is built using a specific version of the ARM GNU Toolchain within a Docker container.

```bash
docker build -t vaultkey-firmware-builder ./firmware/docker
docker run --rm -v $(pwd)/firmware:/home/builder/src vaultkey-firmware-builder
```

## 🦀 App (Tauri/Rust)
The app uses Cargo's deterministic build features and a pinned Rust toolchain via `rust-toolchain.toml`.

```bash
# In app directory
cargo build --release --locked
```

## ✅ Verification
Use `sha256sum` to compare your local build with the official release.
```bash
sha256sum vaultkey-firmware.uf2
```

---
*VaultKey Stack — Open standards. Real security.*
