"""
Unit tests for crypto.py.

Run with:  pytest tests/test_crypto.py -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto
from cryptography.exceptions import InvalidTag


def test_ecdh_both_sides_agree():
    """Two parties running ECDH must derive the SAME shared key."""
    priv_a, pub_a = crypto.generate_ephemeral_keypair()
    priv_b, pub_b = crypto.generate_ephemeral_keypair()

    salt = b"test-salt"
    key_a = crypto.derive_session_keys(priv_a, pub_b, salt)
    key_b = crypto.derive_session_keys(priv_b, pub_a, salt)

    assert key_a == key_b


def test_encrypt_decrypt_round_trip():
    key = os.urandom(32)
    plaintext = b"hello, this is a secret message"
    nonce, ciphertext = crypto.encrypt(key, plaintext)
    recovered = crypto.decrypt(key, nonce, ciphertext)
    assert recovered == plaintext


def test_tampered_ciphertext_is_rejected():
    """Flipping a single bit in the ciphertext must make decryption fail."""
    key = os.urandom(32)
    nonce, ciphertext = crypto.encrypt(key, b"attack at dawn")

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01  # flip one bit

    with pytest.raises(InvalidTag):
        crypto.decrypt(key, nonce, bytes(tampered))


def test_tampered_associated_data_is_rejected():
    """The sequence number (associated data) is authenticated too."""
    key = os.urandom(32)
    nonce, ciphertext = crypto.encrypt(key, b"transfer $10", associated_data=b'{"seq": 1}')

    with pytest.raises(InvalidTag):
        # Attacker tries to resubmit with a different sequence number
        crypto.decrypt(key, nonce, ciphertext, associated_data=b'{"seq": 2}')


def test_wrong_key_is_rejected():
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    nonce, ciphertext = crypto.encrypt(key1, b"secret")
    with pytest.raises(InvalidTag):
        crypto.decrypt(key2, nonce, ciphertext)


def test_signature_valid():
    priv, pub = crypto.generate_identity_keypair()
    message = b"ephemeral-key-bytes"
    sig = crypto.sign(priv, message)
    assert crypto.verify(pub, sig, message) is True


def test_signature_rejects_wrong_signer():
    """A MITM signing with their OWN key instead of the real peer's key
    must fail verification against the real peer's public key."""
    priv_real, pub_real = crypto.generate_identity_keypair()
    priv_attacker, _ = crypto.generate_identity_keypair()

    message = b"ephemeral-key-bytes"
    forged_sig = crypto.sign(priv_attacker, message)

    assert crypto.verify(pub_real, forged_sig, message) is False


def test_signature_rejects_tampered_message():
    priv, pub = crypto.generate_identity_keypair()
    sig = crypto.sign(priv, b"original ephemeral key")
    assert crypto.verify(pub, sig, b"swapped ephemeral key") is False
