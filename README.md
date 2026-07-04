# signature-schemes

[![CI](https://github.com/pavel-genai/signature-schemes/actions/workflows/ci.yml/badge.svg)](https://github.com/pavel-genai/signature-schemes/actions/workflows/ci.yml)

Pure-Python implementations of four digital signature schemes:

| Scheme | Curve / Primitive | Module |
|--------|-------------------|--------|
| ECDSA | secp256k1 | `signatures.ecdsa` |
| Schnorr (BIP-340) | secp256k1 | `signatures.schnorr` |
| Ed25519 | Curve25519 | `signatures.ed25519` |
| BLS | BLS12-381 (via py_ecc) | `signatures.bls` |

ECDSA, Schnorr, and Ed25519 are implemented from scratch using only `hashlib` and `secrets` from the standard library. BLS uses `py_ecc` for pairing operations.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

Every module exposes the same three-function interface:

```python
from signatures.ecdsa import keygen, sign, verify

private_key, public_key = keygen()
signature = sign(private_key, b"hello")
assert verify(public_key, b"hello", signature)
```

## Tests

```bash
pytest
```

## Benchmarks

```bash
python benchmarks.py
```

Signs and verifies 1000 messages with each scheme and prints a comparison table.
