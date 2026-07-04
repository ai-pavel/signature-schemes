#!/usr/bin/env python3
"""Benchmark digital signature schemes: ECDSA, Schnorr, Ed25519, BLS."""

import time
import os
from signatures.ecdsa import keygen as ecdsa_keygen, sign as ecdsa_sign, verify as ecdsa_verify
from signatures.schnorr import keygen as schnorr_keygen, sign as schnorr_sign, verify as schnorr_verify
from signatures.ed25519 import keygen as ed25519_keygen, sign as ed25519_sign, verify as ed25519_verify
from signatures.bls import keygen as bls_keygen, sign as bls_sign, verify as bls_verify

ITERATIONS = 1000


def benchmark_scheme(name, keygen_fn, sign_fn, verify_fn):
    """Benchmark a single signature scheme."""
    messages = [os.urandom(32) for _ in range(ITERATIONS)]

    # Keygen
    start = time.perf_counter_ns()
    keys = [keygen_fn() for _ in range(ITERATIONS)]
    keygen_ns = (time.perf_counter_ns() - start) / ITERATIONS

    # Sign
    start = time.perf_counter_ns()
    signatures = []
    for i in range(ITERATIONS):
        sk, pk = keys[i]
        sig = sign_fn(sk, messages[i])
        signatures.append((pk, sig))
    sign_ns = (time.perf_counter_ns() - start) / ITERATIONS

    # Verify
    start = time.perf_counter_ns()
    for i in range(ITERATIONS):
        pk, sig = signatures[i]
        verify_fn(pk, messages[i], sig)
    verify_ns = (time.perf_counter_ns() - start) / ITERATIONS

    return {
        "name": name,
        "keygen_us": keygen_ns / 1000,
        "sign_us": sign_ns / 1000,
        "verify_us": verify_ns / 1000,
    }


def print_table(results):
    """Print a formatted comparison table."""
    header = f"{'Scheme':<12} {'Keygen (µs)':>14} {'Sign (µs)':>14} {'Verify (µs)':>14}"
    separator = "-" * len(header)
    print(separator)
    print(header)
    print(separator)
    for r in results:
        print(f"{r['name']:<12} {r['keygen_us']:>14.1f} {r['sign_us']:>14.1f} {r['verify_us']:>14.1f}")
    print(separator)
    print(f"\nEach measurement averaged over {ITERATIONS} iterations.")


def main():
    schemes = [
        ("ECDSA", ecdsa_keygen, ecdsa_sign, ecdsa_verify),
        ("Schnorr", schnorr_keygen, schnorr_sign, schnorr_verify),
        ("Ed25519", ed25519_keygen, ed25519_sign, ed25519_verify),
        ("BLS", bls_keygen, bls_sign, bls_verify),
    ]

    results = []
    for name, kg, s, v in schemes:
        print(f"Benchmarking {name}...")
        try:
            r = benchmark_scheme(name, kg, s, v)
            results.append(r)
        except Exception as e:
            print(f"  Skipped {name}: {e}")

    if results:
        print()
        print_table(results)


if __name__ == "__main__":
    main()
