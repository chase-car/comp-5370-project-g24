"""
Tests for protocol.py's SecureChannel -- specifically replay protection.
These use a fake in-memory Connection instead of real sockets, so they
run fast and don't need two processes.
"""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from protocol import SecureChannel


class FakeConnection:
    """A stand-in for network.Connection that stores frames in a list
    instead of sending them over a real socket."""

    def __init__(self):
        self.frames = []
        self._pos = 0

    def send_frame(self, payload: bytes):
        self.frames.append(payload)

    def recv_frame(self) -> bytes:
        frame = self.frames[self._pos]
        self._pos += 1
        return frame


def test_normal_messages_round_trip():
    conn = FakeConnection()
    key = os.urandom(32)
    sender = SecureChannel(conn, send_key=key, recv_key=key)
    receiver = SecureChannel(conn, send_key=key, recv_key=key)

    sender.send_message("hello")
    sender.send_message("world")

    assert receiver.recv_message() == "hello"
    assert receiver.recv_message() == "world"


def test_replayed_message_is_rejected():
    """Capture a legitimate frame and resend it -- receiver must reject it."""
    conn = FakeConnection()
    key = os.urandom(32)
    sender = SecureChannel(conn, send_key=key, recv_key=key)
    receiver = SecureChannel(conn, send_key=key, recv_key=key)

    sender.send_message("transfer $10 to alice")
    receiver.recv_message()  # consumed normally, recv_seq is now 1

    # Attacker replays the exact same captured frame again
    conn.frames.append(conn.frames[0])
    with pytest.raises(ValueError, match="already seen"):
        receiver.recv_message()


def test_out_of_order_old_message_is_rejected():
    conn = FakeConnection()
    key = os.urandom(32)
    sender = SecureChannel(conn, send_key=key, recv_key=key)
    receiver = SecureChannel(conn, send_key=key, recv_key=key)

    sender.send_message("first")
    sender.send_message("second")

    first_frame = conn.frames[0]
    receiver.recv_message()  # "first", recv_seq -> 1
    receiver.recv_message()  # "second", recv_seq -> 2

    # Attacker re-injects the OLD "first" frame
    conn.frames.append(first_frame)
    with pytest.raises(ValueError, match="already seen"):
        receiver.recv_message()
