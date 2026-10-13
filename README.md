# cipherbox

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cryptography: AES-256-GCM](https://img.shields.io/badge/cipher-AES--256--GCM-brightgreen.svg)](#cryptographic-architecture)
[![KDF: PBKDF2-HMAC-SHA256](https://img.shields.io/badge/kdf-PBKDF2--SHA256%20(600k%20iters)-orange.svg)](#key-derivation)

A robust, production-grade CLI utility and Python library for authenticated symmetric file and text encryption. Built on AES-256-GCM (Authenticated Encryption with Associated Data, AEAD) to guarantee both strict data confidentiality and tamper-evident message integrity.

---

## Why AES-GCM?

Many basic encryption scripts rely on legacy modes like AES-CBC or unauthenticated Fernet implementations that do not verify integrity at the cryptographic layer. Without authenticated encryption:
- Adversaries can perform **bit-flipping attacks** or exploit **padding oracle vulnerabilities** (e.g., POODLE, Lucky Thirteen).
- Ciphertexts can be silently altered in transit without detection until parsed by higher-level application logic.

`cipherbox` uses **AES-256-GCM**, which calculates a 128-bit Galois Message Authentication Code (GMAC) tag during encryption. If even a single bit of the ciphertext or header is modified, decryption immediately halts and rejects the payload with an authentication failure before exposing any data.

---

## Cryptographic Architecture

```
+-----------------------------------------------------------------------------------------+
|                                    CIPHERBOX ENVELOPE                                   |
+--------------+-----------------+-------------------+-------------------+----------------+
| Magic (4B)   | Version (1B)    | KDF Salt (16B)    | Nonce/IV (12B)    | Auth Tag (16B) |
| b"CBOX"      | 0x01            | CSPRNG Salt       | NIST SP 800-38D   | GCM GMAC Tag   |
+--------------+-----------------+-------------------+-------------------+----------------+
|                               CIPHERTEXT PAYLOAD (N Bytes)                              |
+-----------------------------------------------------------------------------------------+
```

- **Cipher**: AES-256 in Galois/Counter Mode (GCM).
- **Key Derivation (KDF)**: PBKDF2-HMAC-SHA256 with **600,000 iterations** (exceeding OWASP Password Storage and Derivation Cheat Sheet guidelines) and a 128-bit CSPRNG salt.
- **Nonce / IV**: 96-bit (12 bytes) cryptographically random nonce generated fresh per operation (`os.urandom`) to prevent IV reuse.
- **Envelope Overhead**: 49-byte fixed binary header containing all parameters necessary for standalone decryption without maintaining external state or configuration.

---

## Installation & Setup

1. Clone repository:
   ```bash
   git clone https://github.com/777nq/AES-Encryption-Decryption-Tool.git
   cd AES-Encryption-Decryption-Tool
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## CLI Usage

### 1. File Encryption & Decryption

Encrypt any file (documents, archives, disk images, binaries):
```bash
# Encrypt confidential file (password prompted securely)
python cipherbox.py enc -f database_backup.sql -o database_backup.sql.enc

# Decrypt back to original plaintext
python cipherbox.py dec -f database_backup.sql.enc -o restored_backup.sql
```

> **Security Note:** If `-p / --password` is omitted, `cipherbox` prompts for the password via `getpass` without echoing characters to terminal or leaving passwords in shell history (`~/.bash_history`).

### 2. String & Text Payloads

Encrypt sensitive strings (API tokens, private keys, secrets):
```bash
# Encrypt text into self-contained Base64 payload
python cipherbox.py enc -t "secret_api_key_live_99218a" -p "MasterVaultPassphrase#2026"
```

```text
[+] Encrypted Payload (Base64):
Q0JPWAESBwbHnL8vA8k6+Jj5YwX9xM+vLz0...
```

Decrypt the payload:
```bash
python cipherbox.py dec -t "Q0JPWAESBwbHnL8vA8k6+Jj5YwX9xM+vLz0..." -p "MasterVaultPassphrase#2026"
```

```text
[+] Decrypted Text:
secret_api_key_live_99218a
```

### 3. Tamper Resistance Demonstration

If an attacker alters any byte in the ciphertext or attempts a brute-force guess:
```text
[-] Decryption failed: Authentication failed: incorrect password or data has been tampered with.
```
Decryption aborts with exit code `2`.

---

## Command Reference

| Command | Flag | Description |
|---------|------|-------------|
| `enc` / `encrypt` | `-f`, `--file` | Path to source file to encrypt |
| | `-o`, `--output` | Destination path for encrypted envelope |
| | `-t`, `--text` | Raw text string to encrypt (outputs Base64) |
| | `-p`, `--password` | Master password (prompted if omitted) |
| `dec` / `decrypt` | `-f`, `--file` | Path to encrypted file to decrypt |
| | `-o`, `--output` | Destination path for decrypted plaintext file |
| | `-t`, `--text` | Base64-encoded encrypted string payload |
| | `-p`, `--password` | Master password for decryption |

---

## Python API Integration

`cipherbox` can also be imported directly into Python applications:

```python
from cipherbox import encrypt_string, decrypt_string, encrypt_file, decrypt_file

# String encryption
ciphertext = encrypt_string("confidential_payload", "UserMasterPassword")
plaintext = decrypt_string(ciphertext, "UserMasterPassword")

# File encryption
encrypt_file("credentials.json", "credentials.json.enc", "UserMasterPassword")
decrypt_file("credentials.json.enc", "restored.json", "UserMasterPassword")
```

---

## Running Test Suite

```bash
python -m unittest test_cipherbox.py -v
```

Tests verify:
- Cryptographic roundtrip fidelity on arbitrary strings and binary blobs
- Integrity violation detection (tampered ciphertext / header magic corruption)
- Incorrect password rejection via GCM authentication tags
- File stream handling with temporary files

---

## License

This project is licensed under the [MIT License](LICENSE).
