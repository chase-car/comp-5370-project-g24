"""
protocol.py
-----------
Ties crypto.py and network.py together into the actual secure channel:

  1. Handshake  : exchange + verify identity keys, exchange signed
                  ephemeral keys, derive a shared session key.
  2. Messaging  : encrypt-and-authenticate every chat message, with a
                  sequence number to detect replay / drop / reorder.

Wire messages are JSON (never pickle -- pickle lets a malicious peer
execute arbitrary code on load).
"""

import json

from network import Connection
import crypto


class HandshakeFailed(Exception):
    pass


class SecureChannel:
    """
    Represents one fully-established, authenticated, encrypted session
    with a peer. Created by `perform_handshake`.
    """

    def __init__(self, conn: Connection, send_key: bytes, recv_key: bytes, peer_name: str = None):
        self.conn = conn
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_seq = 0
        self.recv_seq = 0
        self.seen_nonces = set()  # extra replay guard within a session
        self.peer_name = peer_name  # set by perform_handshake once known

    # -- sending ---------------------------------------------------
    def send_message(self, plaintext: str) -> None:
        seq = self.send_seq
        self.send_seq += 1

        associated_data = json.dumps({"seq": seq}).encode()
        nonce, ciphertext = crypto.encrypt(
            self.send_key, plaintext.encode("utf-8"), associated_data
        )
        frame = {
            "seq": seq,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }
        self.conn.send_frame(json.dumps(frame).encode())

    # -- receiving -------------------------------------------------
    def recv_message(self) -> str:
        """
        Returns the decrypted plaintext, or raises ValueError if the
        message fails authentication or looks like a replay.
        """
        raw = self.conn.recv_frame()
        frame = json.loads(raw.decode())

        seq = frame["seq"]
        nonce = bytes.fromhex(frame["nonce"])
        ciphertext = bytes.fromhex(frame["ciphertext"])

        # Replay / reorder protection: reject anything not strictly
        # increasing.
        if seq < self.recv_seq:
            raise ValueError(f"Rejected: sequence {seq} already seen "
                              f"(replay or duplicate)")

        associated_data = json.dumps({"seq": seq}).encode()
        try:
            plaintext = crypto.decrypt(self.recv_key, nonce, ciphertext, associated_data)
        except Exception as e:
            raise ValueError(f"Rejected: authentication failed ({e})")

        self.recv_seq = seq + 1
        return plaintext.decode("utf-8")


def perform_handshake(conn: Connection, identity_private_key, my_name: str,
                       trust_store, interactive: bool = True) -> SecureChannel:
    identity_public_key = identity_private_key.public_key()
    identity_pub_bytes = crypto.public_key_to_bytes(identity_public_key)

    eph_private, eph_public = crypto.generate_ephemeral_keypair()
    eph_pub_bytes = crypto.public_key_to_bytes(eph_public)

    signed_data = eph_pub_bytes + my_name.encode()
    signature = crypto.sign(identity_private_key, signed_data)

    outgoing = {
        "name": my_name,
        "identity_pub": identity_pub_bytes.hex(),
        "ephemeral_pub": eph_pub_bytes.hex(),
        "signature": signature.hex(),
    }
    conn.send_frame(json.dumps(outgoing).encode())

    incoming = json.loads(conn.recv_frame().decode())
    peer_name = incoming["name"]
    peer_identity_pub_bytes = bytes.fromhex(incoming["identity_pub"])
    peer_eph_pub_bytes = bytes.fromhex(incoming["ephemeral_pub"])
    peer_signature = bytes.fromhex(incoming["signature"])

    # Authentication check: did the peer actually hold the private
    # key matching their claimed identity, and sign this ephemeral key?
    peer_identity_pub = crypto.ed25519_public_key_from_bytes(peer_identity_pub_bytes)
    signed_payload = peer_eph_pub_bytes + peer_name.encode()
    if not crypto.verify(peer_identity_pub, peer_signature, signed_payload):
        raise HandshakeFailed(
            "Signature verification FAILED -- the ephemeral key was not "
            "signed by the claimed identity. Possible MITM attack."
        )

    # Trust check
    if interactive:
        trusted = trust_store.check_or_prompt(peer_name, peer_identity_pub_bytes)
    else:
        trusted = trust_store.auto_verify(peer_name, peer_identity_pub_bytes)

    if not trusted:
        raise HandshakeFailed(
            f"Peer '{peer_name}' was not trusted. Aborting handshake."
        )

    # --- Derive the shared session key (confidentiality) ---
    peer_eph_pub = crypto.x25519_public_key_from_bytes(peer_eph_pub_bytes)
    salt = b"".join(sorted([eph_pub_bytes, peer_eph_pub_bytes]))
    session_key = crypto.derive_session_keys(eph_private, peer_eph_pub, salt)

    key_a2b = crypto.derive_session_keys(eph_private, peer_eph_pub, salt, info=b"a-to-b")
    key_b2a = crypto.derive_session_keys(eph_private, peer_eph_pub, salt, info=b"b-to-a")

    # Whoever's ephemeral key sorts first is consistently "A" on both ends.
    i_am_a = eph_pub_bytes == sorted([eph_pub_bytes, peer_eph_pub_bytes])[0]
    if i_am_a:
        send_key, recv_key = key_a2b, key_b2a
    else:
        send_key, recv_key = key_b2a, key_a2b

    print(f"[protocol] Handshake complete with '{peer_name}'. Session secured.")
    return SecureChannel(conn, send_key, recv_key, peer_name=peer_name)
