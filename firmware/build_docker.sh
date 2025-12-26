#!/bin/bash
# VaultKey Reproducible Build Trigger

echo "Building Docker image..."
docker build -t vaultkey-builder .

echo "Running build..."
docker run --rm -v "$(pwd)":/build vaultkey-builder

echo "Build complete. Check build/vaultkey_firmware.uf2"
