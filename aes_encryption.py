#!/usr/bin/env python3
"""
Backwards-compatible entrypoint forwarding to the AES-256-GCM cipherbox engine.
"""
from cipherbox import main, encrypt_string, decrypt_string, encrypt_file, decrypt_file

if __name__ == "__main__":
    main()
