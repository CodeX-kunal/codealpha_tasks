"""AES-256-GCM for data at rest + scrypt for passwords.

* Every sensitive value gets a fresh random 96-bit nonce.
* The column name is bound in as AAD, so a ciphertext copied into another column fails to decrypt.
* GCM is authenticated: any tampering raises InvalidTag instead of returning garbage.
* Credentials: password -> scrypt hash (one-way) -> AES-256-GCM encrypted before storage.
"""
import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = "v1"  # allows key rotation later (v2:...)
_SCRYPT = dict(n=2**14, r=8, p=1, dklen=32)


class Crypto:
    def __init__(self, enc_key: bytes, mac_key: bytes):
        if len(enc_key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        self._aes = AESGCM(enc_key)
        self._mac_key = mac_key

    # ---- AES-256-GCM -------------------------------------------------
    def encrypt(self, plaintext: str, field: str) -> str:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, plaintext.encode("utf-8"), field.encode())
        return f"{VERSION}:" + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, stored: str, field: str) -> str:
        version, _, body = stored.partition(":")
        if version != VERSION:
            raise ValueError("unsupported ciphertext version")
        raw = base64.urlsafe_b64decode(body.encode())
        nonce, ct = raw[:12], raw[12:]
        return self._aes.decrypt(nonce, ct, field.encode()).decode("utf-8")

    # ---- credentials -------------------------------------------------
    def protect_password(self, password: str) -> str:
        salt = os.urandom(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
        return self.encrypt(base64.b64encode(salt + digest).decode(), "password")

    def check_password(self, password: str, stored: str) -> bool:
        blob = base64.b64decode(self.decrypt(stored, "password"))
        salt, digest = blob[:16], blob[16:]
        candidate = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
        return hmac.compare_digest(digest, candidate)

    def dummy_check(self, password: str) -> None:
        """Burn the same CPU when the user does not exist (blunts user enumeration by timing)."""
        hashlib.scrypt(password.encode(), salt=b"\x00" * 16, **_SCRYPT)

    # ---- blind index: lets us test 'is this email taken?' without storing it in plaintext ----
    def blind_index(self, value: str) -> str:
        return hmac.new(self._mac_key, b"email-bidx:" + value.encode(), hashlib.sha256).hexdigest()
