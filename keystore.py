"""
keystore.py
-----------
Handles long-term Ed25519 identity keys: generating them, saving/loading
them from disk, and a simple "trusted keys" file that implements a
Signal/SSH-style trust-on-first-use (TOFU) model.

Trust model used here (document this choice in your report):
  - The FIRST time you talk to a peer, you must verify their fingerprint
    out-of-band (read it to them over the phone, compare in person, etc).
  - After that, their fingerprint is pinned in trusted_keys.json.
  - If it ever changes, the program warns you loudly -- that's exactly
    the signal a MITM attack would produce.
"""

import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from crypto import generate_identity_keypair, public_key_to_bytes, fingerprint


def generate_and_save_identity(path: str) -> None:
    """Create a new identity keypair and write the PRIVATE key to `path`."""
    private_key, _ = generate_identity_keypair()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
        # Stretch goal: swap NoEncryption() for BestAvailableEncryption(password)
        # to require a passphrase before the key can be loaded.
    )
    with open(path, "wb") as f:
        f.write(pem)
    os.chmod(path, 0o600)  # owner read/write only


def load_identity(path: str) -> Ed25519PrivateKey:
    """Load a private identity key from disk, generating one if missing."""
    if not os.path.exists(path):
        print(f"[keystore] No identity key found at {path}, generating one...")
        generate_and_save_identity(path)
    with open(path, "rb") as f:
        pem = f.read()
    return serialization.load_pem_private_key(pem, password=None)


class TrustStore:
    """A tiny JSON file mapping peer name -> hex-encoded public key."""

    def __init__(self, path: str):
        self.path = path
        self.entries = {}
        if os.path.exists(path):
            with open(path, "r") as f:
                self.entries = json.load(f)

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self.entries, f, indent=2)

    def is_known(self, name: str) -> bool:
        return name in self.entries

    def get(self, name: str) -> bytes | None:
        hexkey = self.entries.get(name)
        return bytes.fromhex(hexkey) if hexkey else None

    def trust(self, name: str, public_key_bytes: bytes):
        self.entries[name] = public_key_bytes.hex()
        self._save()

    def check_or_prompt(self, name: str, public_key_bytes: bytes) -> bool:
        """
        Returns True if the key matches what's already trusted, or if the
        user chooses to trust it now (TOFU). Returns False if it does NOT
        match a previously trusted key -- this is the MITM warning case.
        """
        print(f"\nPeer '{name}' fingerprint:\n  {fingerprint(public_key_bytes)}")

        if not self.is_known(name):
            answer = input(
                f"First time seeing '{name}'. Verify this fingerprint out-of-band "
                f"(phone call, in person, etc). Trust it? [y/N]: "
            ).strip().lower()
            if answer == "y":
                self.trust(name, public_key_bytes)
                return True
            return False

        known = self.get(name)
        if known == public_key_bytes:
            print(f"[keystore] '{name}' key matches previously trusted key. OK.")
            return True

        print("=" * 60)
        print(f"!! WARNING: '{name}' key DOES NOT MATCH the previously")
        print("!! trusted key. This could mean a MAN-IN-THE-MIDDLE attack,")
        print("!! or the peer legitimately regenerated their keys.")
        print("=" * 60)
        answer = input("Trust the NEW key anyway? [y/N]: ").strip().lower()
        if answer == "y":
            self.trust(name, public_key_bytes)
            return True
        return False

    def auto_verify(self, name: str, public_key_bytes: bytes) -> bool:
        """
        Non-interactive trust-on-first-use. Safe to call from a BACKGROUND
        thread -- it never calls input(). Use this instead of
        check_or_prompt() whenever handshakes can run concurrently with a
        main thread that is also reading stdin (e.g. the multi-peer
        broadcast chat, where one handshake thread per connection can be
        live at the same time as the chat input loop). Two threads both
        calling input() on the same stdin is a real race condition in
        Python -- it can corrupt or crash the interpreter -- so this path
        trades "block and ask" for "trust immediately, print the
        fingerprint, and let the user verify or correct it after the fact."

        First contact: trust is granted automatically, but the fingerprint
        is still printed so the user can verify it out-of-band and, if it's
        wrong, remove it from the trust file by hand.
        Later contact with a DIFFERENT key for the same name: rejected
        automatically with no prompt -- exactly what should happen if a
        MITM attack swaps in a new identity key after the first exchange.
        """
        print(f"\nPeer '{name}' fingerprint:\n  {fingerprint(public_key_bytes)}")
        print(f"(Verify this out-of-band if you haven't already. "
              f"To reset trust, edit {self.path}.)")

        if not self.is_known(name):
            self.trust(name, public_key_bytes)
            return True

        known = self.get(name)
        if known == public_key_bytes:
            return True

        print("=" * 60)
        print(f"!! WARNING: '{name}' key DOES NOT MATCH the previously trusted key.")
        print("!! Refusing this connection automatically. This could mean a")
        print("!! MAN-IN-THE-MIDDLE attack, or the peer regenerated their keys.")
        print(f"!! To accept the new key, remove the '{name}' entry from {self.path}.")
        print("=" * 60)
        return False
