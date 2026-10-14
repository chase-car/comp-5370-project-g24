"""
crypto.py
---------
All cryptographic primitives live here. Nothing in this file implements
its own math -- everything is built on the `cryptography` library.

Covers:
  - Confidentiality : X25519 ECDH + HKDF -> AES-256-GCM
  - Integrity        : AES-GCM's built-in authentication tag
  - Authentication    : Ed25519 digital signatures over the handshake
"""

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

NONCE_SIZE = 12          # bytes, required length for AES-GCM
AES_KEY_SIZE = 32        # bytes, AES-256


# ---------------------------------------------------------------------
# Key exchange (confidentiality)
# ---------------------------------------------------------------------

def generate_ephemeral_keypair():
    """Generate a fresh X25519 keypair for one session (one handshake)."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_bytes(public_key: X25519PublicKey | Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_key_from_bytes(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def ed25519_public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(data)


def derive_session_keys(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey,
                         salt: bytes, info: bytes = b"secure-chat-session") -> bytes:
    """
    Run ECDH, then stretch the shared secret with HKDF into a session key.

    `salt` should be the concatenation of both ephemeral public keys so
    both directions of the handshake bind to the exact same session
    (prevents certain key-reuse / unknown key-share issues).
    """
    shared_secret = private_key.exchange(peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------
# Authenticated encryption (confidentiality + integrity)
# ---------------------------------------------------------------------

def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encrypt with AES-256-GCM.
    Returns (nonce, ciphertext_with_tag). A fresh random nonce is used
    every call -- never reuse a nonce with the same key.
    associated_data is authenticated but NOT encrypted (e.g. sequence number).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt + verify with AES-256-GCM.
    Raises cryptography.exceptions.InvalidTag if the ciphertext or
    associated_data was tampered with, or the wrong key/nonce is used.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


# ---------------------------------------------------------------------
# Digital signatures (authentication)
# ---------------------------------------------------------------------

def generate_identity_keypair():
    """Generate a LONG-TERM Ed25519 identity keypair (not per-session)."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    """Returns True if valid, False if the signature does not match."""
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def fingerprint(public_key_bytes: bytes) -> str:
    """Short human-comparable fingerprint of a public key (out-of-band check)."""
    import hashlib
    digest = hashlib.sha256(public_key_bytes).hexdigest()
    # group into chunks like "a1b2 c3d4 ..." for easier reading aloud
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))
