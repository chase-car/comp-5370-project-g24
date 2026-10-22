# Secure Messaging Program

A peer-to-peer terminal chat program in Python implementing confidentiality,
integrity, and authentication.

**Group 24** — Chase Carithers, Charles Norris, Dev Patel

## What's implemented

| Property | How |
|---|---|
| Confidentiality | X25519 (ECDH) key exchange + HKDF + AES-256-GCM |
| Integrity | AES-GCM authentication tag over every message (tamper = rejected) |
| Authentication | Ed25519 signatures over each session's ephemeral key, tied to a trust-on-first-use (TOFU) fingerprint store |
| Replay / reorder protection | Strictly increasing sequence numbers, included in GCM's associated data |


## Setup

```bash
cd secure_chat
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

There are three runnable programs. Use whichever fits what you're testing:

| Program | What it is | When to use it |
|---|---|---|
| `main.py` | Two-peer chat, one listener + one connector | Simplest case; use this first |
| `p2p_chat_secure.py` | Multi-peer broadcast chat, every instance is both server and client | Testing 3+ people at once |
| `relay.py` | Dumb TCP relay (no encryption of its own) | Only needed if direct connections are blocked by NAT/firewall — see "Testing across two machines" below |

### `main.py` (two peers)

**Terminal 1 (listener):**
```bash
python main.py --listen 5000 --name alice --keyfile alice_identity.pem
```

**Terminal 2 (connector):**
```bash
python main.py --connect 127.0.0.1:5000 --name bob --keyfile bob_identity.pem
```

### `p2p_chat_secure.py` (three or more peers)

Every instance listens and can connect out, so any instance can be "first":

```bash
# Terminal 1
python p2p_chat_secure.py --name alice --port 5000 --keyfile alice.pem

# Terminal 2 — connects to alice
python p2p_chat_secure.py --name bob --port 5001 --connect 127.0.0.1:5000 --keyfile bob.pem

# Terminal 3 — connects to alice (or to bob — either works)
python p2p_chat_secure.py --name carol --port 5002 --connect 127.0.0.1:5000 --keyfile carol.pem
```
Use `/peers` in any terminal to confirm who's connected, and `/connect <host> <port>` to add more peers manually.

In both programs, the first time two peers talk, each side is shown the
other's key **fingerprint**. In real use you'd verify this out-of-band
(read it aloud on a phone call, compare in person) before trusting it —
this is exactly what stops a man-in-the-middle attack. `main.py` asks
interactively (`y`/`N`); `p2p_chat_secure.py` trusts automatically on
first contact but still prints the fingerprint for you to check, 
and still refuses automatically if a fingerprint ever changes later.

Type messages and press enter. Type `/quit` to disconnect.

## Testing

### 1. Automated unit tests

```bash
pytest tests/ -v
```

Covers:
- ECDH agreement (both sides derive the identical key)
- Encrypt/decrypt round trip
- Tampered ciphertext rejected (integrity)
- Tampered associated data (sequence number) rejected
- Wrong key rejected
- Valid and forged signatures (authentication / MITM resistance)
- Replayed and out-of-order messages rejected

If any of these fail after an edit, fix that before testing manually —
the manual tests below assume the primitives already work.

### 2. Manual local test

Run the two `main.py` commands above in two terminal windows side by
side. Confirm:
- [ ] The fingerprint prompt appears and matches on both sides (compare them — they should be each other's fingerprint, not identical to each other)
- [ ] After typing `y` on both, you see `Handshake complete` on both sides
- [ ] A message typed in one terminal appears in the other
- [ ] `/quit` in one terminal cleanly prints `disconnected` on the other, not a crash

Repeat with `p2p_chat_secure.py` and three terminals, additionally checking:
- [ ] `/peers` in each terminal lists the other two names
- [ ] A message typed in any terminal appears in BOTH others


## Project structure

```
secure_chat/
├── main.py              # Two-peer CLI entry point, threaded send/receive loop
├── p2p_chat_secure.py   # Multi-peer broadcast version, each instance is server+client
├── relay.py             # Dumb TCP relay for NAT/firewall workaround (no crypto of its own)
├── network.py           # Raw TCP + length-prefixed message framing
├── crypto.py            # ECDH, HKDF, AES-GCM, Ed25519 — all primitives
├── protocol.py          # Handshake + secure message format, ties it together
├── keystore.py          # Long-term identity keys + trust-on-first-use store
├── tests/
│   ├── test_crypto.py      # Primitive-level tests + simulated attacks
│   └── test_protocol.py    # Replay-protection tests
├── requirements.txt
└── README.md
```

## How the handshake works

1. Each peer generates a fresh **ephemeral** X25519 keypair for this session.
2. Each peer signs `ephemeral_public_key || name` with their **long-term**
   Ed25519 identity key, and sends `(name, identity_pub, ephemeral_pub, signature)`.
3. Each peer verifies the other's signature against the claimed identity
   key. If this fails, the ephemeral key could have been swapped by an
   attacker-in-the-middle, so the handshake aborts.
4. Each peer checks the claimed identity key against `trusted_keys.json`
   (trust-on-first-use), prompting the user if it's new or changed.
5. Both sides run ECDH on the ephemeral keys and stretch the result with
   HKDF into two independent directional AES-256 keys.
6. Every message after this point is AES-GCM encrypted, with its sequence
   number as associated data, so a copied/replayed/reordered message is
   rejected by the recipient.
