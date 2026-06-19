import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

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


class KeyExchange:

    def __init__(self):
        self._private_key = X25519PrivateKey.generate()

    def public_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes_raw()

    def derive_key(self, peer_public_bytes: bytes) -> bytes:
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self._private_key.exchange(peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=None,
            info=b"phantomshell-ecdh",
        ).derive(shared_secret)


# Send own public key, receive peer public key, derive shared AES key and return cipher.
def negotiate_keys(transport) -> AESCipher:
    kx = KeyExchange()
    transport.send(kx.public_bytes())
    peer_pub = transport.recv(32)
    shared_key = kx.derive_key(peer_pub)
    return AESCipher(shared_key)
