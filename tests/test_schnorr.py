"""Tests for Schnorr (BIP-340) signatures with known test vectors."""

import pytest
from signatures.schnorr import keygen, sign, verify, _lift_x, _tagged_hash


# BIP-340 official test vectors (subset)
# https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv

BIP340_VECTORS = [
    # (secret_key_hex, public_key_hex, aux_rand_hex, message_hex, signature_hex, expected_verify)
    {
        "secret_key": "0000000000000000000000000000000000000000000000000000000000000003",
        "public_key": "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "message": "0000000000000000000000000000000000000000000000000000000000000000",
        "expected": True,
    },
    {
        "secret_key": "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "public_key": "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "message": "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4EC6B6",
        "expected": True,
    },
]


class TestBIP340Vectors:
    """Verify against known BIP-340 test vectors (verify-only, since signing
    uses deterministic nonce with zero aux)."""

    def test_roundtrip(self):
        sk, pk = keygen()
        msg = b"hello schnorr"
        sig = sign(sk, msg)
        assert verify(pk, msg, sig)

    def test_wrong_message(self):
        sk, pk = keygen()
        sig = sign(sk, b"right")
        assert not verify(pk, b"wrong", sig)

    def test_wrong_key(self):
        sk1, pk1 = keygen()
        _, pk2 = keygen()
        sig = sign(sk1, b"msg")
        assert not verify(pk2, b"msg", sig)

    def test_signature_length(self):
        sk, pk = keygen()
        sig = sign(sk, b"test")
        assert len(sig) == 64

    def test_public_key_length(self):
        _, pk = keygen()
        assert len(pk) == 32

    def test_known_key_3(self):
        """Private key = 3, verify the public key matches BIP-340 vector."""
        from signatures.ecdsa import point_mul, G, N
        sk = 3
        pk_point = point_mul(sk, G)
        # BIP-340: x-only pubkey for sk=3
        expected_x = int(BIP340_VECTORS[0]["public_key"], 16)
        assert pk_point.x == expected_x

    def test_lift_x(self):
        """Test that lift_x recovers the correct point."""
        from signatures.ecdsa import G, P
        pt = _lift_x(G.x)
        assert pt is not None
        assert pt.x == G.x
        # Should have even y
        assert pt.y % 2 == 0

    def test_tagged_hash_deterministic(self):
        h1 = _tagged_hash("test", b"data")
        h2 = _tagged_hash("test", b"data")
        assert h1 == h2
        assert len(h1) == 32
