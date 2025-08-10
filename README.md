# XCrypto — File Encryption & Decryption Tool

**Authors:** Dhruv Kumar Dubey 


## Overview
XCrypto is a cross-platform encryption toolkit providing secure file encryption, steganography (hide text in images), compression, and file integrity verification. It includes:
- Desktop GUI (PyQT5) — full feature set (AES encryption, steganography, key library, compression).
- Web App (Flask) — lightweight AES-based encrypt/decrypt with interactive chatbot.


## Features
- AES authenticated encryption (recommended: AES-GCM)
- Password-based key derivation (PBKDF2 / Argon2)
- Steganography (LSB) — **use PNG/BMP only**
- File integrity checks using **SHA-256**
- Compression: `.zip` and `.7z`
- Key library (encrypted on disk)
- Web interface (Flask) with optional chatbot guidance


## Quick start — development (Linux / WSL / macOS)

1. Clone repo

git clone https://github.com/dhruvkumaran/xcrypto.git

cd xcrypto
