"""Tests for ECDSA over secp256k1 with known test vectors."""

import pytest
from signatures.ecdsa import (
    G, N, P, Point,
    keygen, sign, verify,
    point_mul, point_add, _modinv,
)


class TestPointArithmetic:
    def test_generator_on_curve(self):
        assert (G.y * G.y - G.x * G.x * G.x - 7) % P == 0

    def test_identity(self):
        assert point_add(None, G) == G
        assert point_add(G, None) == G

    def test_scalar_mul_order(self):
        assert point_mul(N, G) is None

    def test_double(self):
        g2 = point_add(G, G)
        g2_mul = point_mul(2, G)
        assert g2 == g2_mul


class TestKnownVector:
    """Test vector derived from Bitcoin wiki / BIP-340 reference.

    Private key = 1  =>  public key = G.
    """
    def test_privkey_one(self):
        pk = point_mul(1, G)
        assert pk == G

    def test_sign_verify_roundtrip(self):
        sk, pk = keygen()
        msg = b"test message"
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

    def test_known_private_key(self):
        """Private key = 0xdeadbeef, verify point is on curve."""
        sk = 0xDEADBEEF
        pk = point_mul(sk, G)
        assert pk is not None
        assert (pk.y * pk.y - pk.x * pk.x * pk.x - 7) % P == 0

    def test_signature_components_in_range(self):
        sk, _ = keygen()
        r, s = sign(sk, b"hello")
        assert 1 <= r < N
        assert 1 <= s <= N // 2  # low-s enforced

    def test_deterministic_verification(self):
        """Sign with a known key and verify multiple times."""
        sk = 42
        pk = point_mul(sk, G)
        sig = sign(sk, b"deterministic test")
        for _ in range(5):
            assert verify(pk, b"deterministic test", sig)
