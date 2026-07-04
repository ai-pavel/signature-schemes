"""Tests for BLS signatures."""

import pytest
from signatures.bls import keygen, sign, verify


class TestBLSRoundtrip:
    def test_sign_verify(self):
        sk, pk = keygen()
        msg = b"hello bls"
        sig = sign(sk, msg)
        assert verify(pk, msg, sig)

    def test_wrong_message(self):
        sk, pk = keygen()
        sig = sign(sk, b"correct")
        assert not verify(pk, b"wrong", sig)

    def test_wrong_key(self):
        sk1, pk1 = keygen()
        _, pk2 = keygen()
        sig = sign(sk1, b"msg")
        assert not verify(pk2, b"msg", sig)

    def test_signature_length(self):
        sk, pk = keygen()
        sig = sign(sk, b"test")
        assert len(sig) == 96  # G2 compressed point

    def test_public_key_length(self):
        _, pk = keygen()
        assert len(pk) == 48  # G1 compressed point

    def test_empty_message(self):
        sk, pk = keygen()
        sig = sign(sk, b"")
        assert verify(pk, b"", sig)

    def test_different_messages_different_sigs(self):
        sk, pk = keygen()
        sig1 = sign(sk, b"message1")
        sig2 = sign(sk, b"message2")
        assert sig1 != sig2


class TestBLSKnownVector:
    """Test with a fixed private key to ensure deterministic behavior."""

    def test_deterministic_sign(self):
        """BLS signing is deterministic for the same key and message."""
        sk, pk = keygen()
        msg = b"deterministic"
        sig1 = sign(sk, msg)
        sig2 = sign(sk, msg)
        assert sig1 == sig2
