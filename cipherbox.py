#!/usr/bin/env python3
"""
cipherbox - Authenticated AES-256-GCM File & Text Encryption Engine

Security Architecture:
- Cipher: AES-256-GCM (Galois/Counter Mode, AEAD)
- Key Derivation: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP recommended)
- Salt: 16 bytes (128 bits) CSPRNG via os.urandom
- Nonce / IV: 12 bytes (96 bits) CSPRNG via os.urandom (NIST SP 800-38D)
- Authentication Tag: 16 bytes (128 bits) verifying integrity and authenticity
- Payload Header: Standardized 49-byte self-contained envelope (Magic: b"CBOX")
"""

import argparse
import base64
import getpass
import os
import sys
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC_BYTES = b"CBOX"
FORMAT_VERSION = 1
SALT_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16
HEADER_LENGTH = len(MAGIC_BYTES) + 1 + SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH  # 4 + 1 + 16 + 12 + 16 = 49 bytes
KDF_ITERATIONS = 600000


class CryptographicError(Exception):
    """Base exception for encryption and decryption failures."""
    pass


class AuthenticationFailedError(CryptographicError):
    """Raised when authentication tag verification fails (tampering or bad password)."""
    pass


class InvalidEnvelopeError(CryptographicError):
    """Raised when the payload envelope format or magic header is invalid."""
    pass


def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derives a 256-bit symmetric encryption key using PBKDF2-HMAC-SHA256.
    """
    if not password:
        raise ValueError("Password must not be empty.")
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"Salt must be exactly {SALT_LENGTH} bytes.")

    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,  # 256-bit AES key
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """
    Encrypts raw bytes using AES-256-GCM and packages the result into a self-contained envelope.

    Envelope Layout:
    [0..4]   : Magic bytes (b"CBOX")
    [4..5]   : Version byte (0x01)
    [5..21]  : KDF Salt (16 bytes)
    [21..33] : AES-GCM Nonce (12 bytes)
    [33..49] : AES-GCM Auth Tag (16 bytes)
    [49..N]  : Ciphertext
    """
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    # cryptography's AESGCM.encrypt appends the 16-byte tag to the ciphertext
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, associated_data=None)

    # Split ciphertext and tag
    ciphertext = ciphertext_and_tag[:-TAG_LENGTH]
    tag = ciphertext_and_tag[-TAG_LENGTH:]

    # Construct envelope
    header = MAGIC_BYTES + bytes([FORMAT_VERSION]) + salt + nonce + tag
    return header + ciphertext


def decrypt_bytes(payload: bytes, password: str) -> bytes:
    """
    Unpacks a CBOX envelope and decrypts the payload with AES-256-GCM.
    Verifies cryptographic authenticity before returning plaintext.
    """
    if len(payload) < HEADER_LENGTH:
        raise InvalidEnvelopeError("Payload is smaller than minimum required header size.")

    magic = payload[:4]
    version = payload[4]
    if magic != MAGIC_BYTES:
        raise InvalidEnvelopeError("Invalid header magic: not a valid CipherBox payload.")
    if version != FORMAT_VERSION:
        raise InvalidEnvelopeError(f"Unsupported envelope version: {version}.")

    salt = payload[5:21]
    nonce = payload[21:33]
    tag = payload[33:49]
    ciphertext = payload[49:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    # AESGCM.decrypt expects ciphertext + tag concatenated
    ciphertext_with_tag = ciphertext + tag

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
        return plaintext
    except InvalidTag:
        raise AuthenticationFailedError(
            "Authentication failed: incorrect password or data has been tampered with."
        )


def encrypt_string(text: str, password: str) -> str:
    """Encrypts a plaintext string and returns a base64-encoded envelope."""
    encrypted_bytes = encrypt_bytes(text.encode("utf-8"), password)
    return base64.b64encode(encrypted_bytes).decode("ascii")


def decrypt_string(encoded_payload: str, password: str) -> str:
    """Decrypts a base64-encoded envelope string and returns plaintext."""
    try:
        raw_payload = base64.b64decode(encoded_payload.strip().encode("ascii"))
    except Exception as err:
        raise InvalidEnvelopeError(f"Malformed base64 payload: {err}")
    decrypted_bytes = decrypt_bytes(raw_payload, password)
    return decrypted_bytes.decode("utf-8")


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Encrypts an input file and writes the protected envelope to output_path."""
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with open(input_path, "rb") as f_in:
        plaintext = f_in.read()

    encrypted_data = encrypt_bytes(plaintext, password)

    with open(output_path, "wb") as f_out:
        f_out.write(encrypted_data)


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Decrypts a protected envelope file and writes plaintext to output_path."""
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    with open(input_path, "rb") as f_in:
        encrypted_data = f_in.read()

    plaintext = decrypt_bytes(encrypted_data, password)

    with open(output_path, "wb") as f_out:
        f_out.write(plaintext)


def prompt_password(confirm: bool = False) -> str:
    """Securely prompts for a password via getpass without echoing to terminal."""
    pwd = getpass.getpass("Enter password: ")
    if not pwd:
        sys.stderr.write("Error: Password cannot be empty.\n")
        sys.exit(1)
    if confirm:
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            sys.stderr.write("Error: Passwords do not match.\n")
            sys.exit(1)
    return pwd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipherbox",
        description="cipherbox: Authenticated AES-256-GCM symmetric encryption utility.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a text string:
  cipherbox enc -t "Confidential API Key" -p "MasterKey123"

  # Decrypt a base64 payload:
  cipherbox dec -t "Q0JPWAE..." -p "MasterKey123"

  # Encrypt a file (password prompted securely):
  cipherbox enc -f database.dump -o database.dump.enc

  # Decrypt a file:
  cipherbox dec -f database.dump.enc -o restored_database.dump
        """
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Command action")

    # Encrypt subparser
    enc_parser = subparsers.add_parser("enc", aliases=["encrypt"], help="Encrypt text or files")
    enc_parser.add_argument("-t", "--text", type=str, help="Text string to encrypt")
    enc_parser.add_argument("-f", "--file", type=str, help="Path to input file to encrypt")
    enc_parser.add_argument("-o", "--output", type=str, help="Path to write encrypted output file")
    enc_parser.add_argument("-p", "--password", type=str, help="Encryption password (prompted if omitted)")

    # Decrypt subparser
    dec_parser = subparsers.add_parser("dec", aliases=["decrypt"], help="Decrypt text or files")
    dec_parser.add_argument("-t", "--text", type=str, help="Base64-encoded encrypted string")
    dec_parser.add_argument("-f", "--file", type=str, help="Path to encrypted input file")
    dec_parser.add_argument("-o", "--output", type=str, help="Path to write decrypted output file")
    dec_parser.add_argument("-p", "--password", type=str, help="Decryption password (prompted if omitted)")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command in ("enc", "encrypt"):
            if not args.text and not args.file:
                sys.stderr.write("Error: You must provide either --text or --file to encrypt.\n")
                sys.exit(1)

            password = args.password or prompt_password(confirm=True)

            if args.file:
                out_path = args.output or f"{args.file}.enc"
                encrypt_file(args.file, out_path, password)
                print(f"[+] File successfully encrypted: {out_path}")
            elif args.text:
                result = encrypt_string(args.text, password)
                print(f"[+] Encrypted Payload (Base64):\n{result}")

        elif args.command in ("dec", "decrypt"):
            if not args.text and not args.file:
                sys.stderr.write("Error: You must provide either --text or --file to decrypt.\n")
                sys.exit(1)

            password = args.password or prompt_password(confirm=False)

            if args.file:
                if not args.output:
                    # Strip .enc if present, else append .dec
                    out_path = args.file[:-4] if args.file.endswith(".enc") else f"{args.file}.dec"
                else:
                    out_path = args.output

                decrypt_file(args.file, out_path, password)
                print(f"[+] File successfully decrypted: {out_path}")
            elif args.text:
                plaintext = decrypt_string(args.text, password)
                print(f"[+] Decrypted Text:\n{plaintext}")

    except AuthenticationFailedError as auth_err:
        sys.stderr.write(f"[-] Decryption failed: {auth_err}\n")
        sys.exit(2)
    except (InvalidEnvelopeError, FileNotFoundError, ValueError) as err:
        sys.stderr.write(f"[-] Error: {err}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
