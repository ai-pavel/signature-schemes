"""BLS signatures over the BLS12-381 curve.

Uses ``py_ecc`` for the pairing-based cryptography.  Key generation uses
``secrets`` and message hashing uses ``hashlib``.
"""

from __future__ import annotations

import hashlib
import secrets

from py_ecc.bls import G2ProofOfPossession as bls_pop
from py_ecc.bls.g2_primitives import G1_to_pubkey, pubkey_to_G1
from py_ecc.bls.g2_primitives import signature_to_G2, G2_to_signature
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.optimized_bls12_381 import (
    G1,
    multiply,
    curve_order,
    Z1,
)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def keygen() -> tuple[int, bytes]:
    """Generate a BLS private key (int) and public key (48-byte compressed G1)."""
    sk = secrets.randbelow(curve_order - 1) + 1
    pk_point = multiply(G1, sk)
    pk_bytes = G1_to_pubkey(pk_point)
    return sk, pk_bytes


def sign(private_key: int, message: bytes) -> bytes:
    """Produce a BLS signature (96-byte compressed G2 point).

    The message is hashed to a G2 point using the standard hash-to-curve
    method, then multiplied by the private key.
    """
    # Use the standard BLS sign from py_ecc
    sig = bls_pop.Sign(private_key, message)
    return sig


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a BLS signature."""
    return bls_pop.Verify(public_key, message, signature)
