"""Tests for Ed25519 with RFC 8032 test vectors."""

import pytest
from signatures.ed25519 import keygen, sign, verify, B, L, Q, _point_mul, _to_affine


# RFC 8032 Section 7.1 - Test Vectors
# https://www.rfc-editor.org/rfc/rfc8032#section-7.1

RFC8032_VECTORS = [
    {
        # TEST 1
        "secret_key": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d183f8e3",
        "message": "",
        "signature": (
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        ),
    },
    {
        # TEST 2
        "secret_key": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public_key": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": (
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e159c7e94b6b505b9cb4fbb"
            "c625e3cb8988f30e54f42ff80f67e20e"
        ),
    },
    {
        # TEST 3
        "secret_key": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public_key": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": (
            "6291d657deec24024827e69c3abe01a3"
            "0ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc659"
            "4a7c15e9716ed28dc027beceea1ec40a"
        ),
    },
]


class TestRFC8032Vectors:
    @pytest.mark.parametrize("vec", RFC8032_VECTORS, ids=["test1", "test2", "test3"])
    def test_sign(self, vec):
        sk = bytes.fromhex(vec["secret_key"])
        pk = bytes.fromhex(vec["public_key"])
        msg = bytes.fromhex(vec["message"])
        expected_sig = bytes.fromhex(vec["signature"])

        sig = sign(sk, msg)
        assert sig == expected_sig, f"Signature mismatch"

    @pytest.mark.parametrize("vec", RFC8032_VECTORS, ids=["test1", "test2", "test3"])
    def test_verify(self, vec):
        pk = bytes.fromhex(vec["public_key"])
        msg = bytes.fromhex(vec["message"])
        sig = bytes.fromhex(vec["signature"])

        assert verify(pk, msg, sig)

    @pytest.mark.parametrize("vec", RFC8032_VECTORS, ids=["test1", "test2", "test3"])
    def test_public_key_derivation(self, vec):
        """Verify that the public key derived from the secret key matches."""
        from signatures.ed25519 import _sha512, _clamp, _encode_point
        sk = bytes.fromhex(vec["secret_key"])
        expected_pk = bytes.fromhex(vec["public_key"])
        h = _sha512(sk)
        a = _clamp(h[:32])
        A = _point_mul(a, B)
        pk = _encode_point(A)
        assert pk == expected_pk


class TestEdDSARoundtrip:
    def test_roundtrip(self):
        sk, pk = keygen()
        msg = b"round trip test"
        sig = sign(sk, msg)
        assert verify(pk, msg, sig)

    def test_wrong_message(self):
        sk, pk = keygen()
        sig = sign(sk, b"correct")
        assert not verify(pk, b"incorrect", sig)

    def test_wrong_key(self):
        sk1, pk1 = keygen()
        _, pk2 = keygen()
        sig = sign(sk1, b"msg")
        assert not verify(pk2, b"msg", sig)

    def test_empty_message(self):
        sk, pk = keygen()
        sig = sign(sk, b"")
        assert verify(pk, b"", sig)

    def test_signature_length(self):
        sk, pk = keygen()
        sig = sign(sk, b"len check")
        assert len(sig) == 64

    def test_base_point_order(self):
        """L * B should be the identity."""
        result = _point_mul(L, B)
        x, y = _to_affine(result)
        assert x == 0
        assert y == 1
