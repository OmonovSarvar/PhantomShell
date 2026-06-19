import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16


class AESCipher:
    """AES-256-GCM authenticated encryption."""

    def __init__(self, key: bytes):
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
        self._gcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Returns nonce(12) + ciphertext + tag(16)."""
        nonce = os.urandom(NONCE_SIZE)
        ct = self._gcm.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, data: bytes) -> bytes:
        """Expects nonce(12) + ciphertext + tag(16)."""
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("Ciphertext too short")
        nonce = data[:NONCE_SIZE]
        ct = data[NONCE_SIZE:]
        return self._gcm.decrypt(nonce, ct, None)

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(KEY_SIZE)
