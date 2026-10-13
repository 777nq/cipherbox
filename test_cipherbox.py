import os
import tempfile
import unittest

from cipherbox import (
    encrypt_string,
    decrypt_string,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_file,
    decrypt_file,
    AuthenticationFailedError,
    InvalidEnvelopeError,
)

class TestCipherBox(unittest.TestCase):
    def setUp(self):
        self.password = "StrongPassphrase!2026#Secure"
        self.sample_text = "The quick brown fox jumps over the lazy dog 1234567890."

    def test_string_roundtrip(self):
        encrypted = encrypt_string(self.sample_text, self.password)
        self.assertIsInstance(encrypted, str)
        decrypted = decrypt_string(encrypted, self.password)
        self.assertEqual(decrypted, self.sample_text)

    def test_wrong_password_fails(self):
        encrypted = encrypt_string(self.sample_text, self.password)
        with self.assertRaises(AuthenticationFailedError):
            decrypt_string(encrypted, "WrongPassword!404")

    def test_tampered_ciphertext_fails(self):
        # Authenticated encryption (AEAD) must catch any bit-flip
        raw_payload = bytearray(encrypt_bytes(self.sample_text.encode("utf-8"), self.password))
        # Flip a bit in the ciphertext payload
        raw_payload[-1] ^= 0x01
        with self.assertRaises(AuthenticationFailedError):
            decrypt_bytes(bytes(raw_payload), self.password)

    def test_invalid_header_magic(self):
        raw_payload = bytearray(encrypt_bytes(self.sample_text.encode("utf-8"), self.password))
        # Corrupt magic bytes
        raw_payload[0] = ord("X")
        with self.assertRaises(InvalidEnvelopeError):
            decrypt_bytes(bytes(raw_payload), self.password)

    def test_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, "original.bin")
            encrypted_file = os.path.join(tmpdir, "protected.cbox")
            restored_file = os.path.join(tmpdir, "restored.bin")

            test_data = os.urandom(64 * 1024)  # 64 KB binary data
            with open(input_file, "wb") as f:
                f.write(test_data)

            encrypt_file(input_file, encrypted_file, self.password)
            self.assertTrue(os.path.exists(encrypted_file))

            decrypt_file(encrypted_file, restored_file, self.password)
            with open(restored_file, "rb") as f:
                restored_data = f.read()

            self.assertEqual(restored_data, test_data)

if __name__ == "__main__":
    unittest.main()
