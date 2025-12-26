@echo off
echo Building Docker image...
docker build -t vaultkey-builder .

echo Running build...
docker run --rm -v "%cd%":/build vaultkey-builder

echo Build complete. Check build/vaultkey_firmware.uf2
pause
