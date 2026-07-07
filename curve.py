# SPDX-License-Identifier: GPL-3.0-or-later
"""
Curve constants and low-level signature equation helpers.
No detection logic here - just correct, reusable math primitives.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# secp256k1 order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class Signature:
    """A single ECDSA signature with its equation context."""

    __slots__ = ("r", "s", "z", "pubkey", "txid", "timestamp", "index")

    def __init__(self, r: int, s: int, z: int, pubkey: Optional[str] = None, 
                 txid: Optional[str] = None, timestamp: Optional[int] = None, 
                 index: Optional[int] = None):
        self.r = r
        self.s = s
        self.z = z
        self.pubkey = pubkey        # optional: which key this claims to be from
        self.txid = txid
        self.timestamp = timestamp
        self.index = index

    def __repr__(self) -> str:
        pk = f" pk={self.pubkey[:8]}..." if self.pubkey else ""
        return f"Sig#{self.index}(r={hex(self.r)[:10]}..{pk})"


def modinv(a: int, m: int = N) -> Optional[int]:
    """
    Compute modular inverse of a modulo m.
    Returns None if inverse doesn't exist (gcd(a, m) != 1).
    """
    try:
        return pow(a, -1, m)
    except ValueError:
        logger.warning(f"Modular inverse failed: gcd({a}, {m}) != 1")
        return None


def validate_signature(sig: Signature) -> tuple[bool, str]:
    """
    Validate a signature for basic correctness.
    Returns (is_valid, reason).
    
    Checks:
      - 1 <= r < N
      - 1 <= s < N
      - r != 0 and s != 0 (pow(..., -1, N) safety)
      - z < N (z is a hash, but should be reduced mod N if oversized)
    """
    if not (1 <= sig.r < N):
        return False, f"r out of range: {sig.r}"
    
    if not (1 <= sig.s < N):
        return False, f"s out of range: {sig.s}"
    
    if sig.r == 0:
        return False, "r is zero"
    
    if sig.s == 0:
        return False, "s is zero"
    
    if sig.z >= N:
        logger.warning(f"z >= N, will be reduced mod N: {sig.z} -> {sig.z % N}")
    
    return True, "valid"


def recover_key_from_reuse(sig1: Signature, sig2: Signature) -> Optional[tuple[int, int]]:
    """
    Given two signatures that share the same r (i.e. same nonce k),
    solve directly for k and the private key d.

    k  = (z1 - z2) / (s1 - s2)  mod N
    d  = (s1*k - z1) / r        mod N

    Returns (k, d) or None if the equations are degenerate (s1 == s2).
    """
    r = sig1.r
    assert r == sig2.r, "recover_key_from_reuse requires equal r values"

    s_diff = (sig1.s - sig2.s) % N
    if s_diff == 0:
        return None  # degenerate: identical signatures, nothing to solve

    z_diff = (sig1.z - sig2.z) % N
    
    s_diff_inv = modinv(s_diff, N)
    if s_diff_inv is None:
        return None
    
    k = (z_diff * s_diff_inv) % N

    r_inv = modinv(r, N)
    if r_inv is None:
        return None
    
    d = ((sig1.s * k - sig1.z) * r_inv) % N

    return k, d


def recover_key_from_known_step_sequence(sig: Signature, k: int) -> Optional[int]:
    """
    Given a signature and a known nonce k, recover the private key d.
    
    From s = k^{-1}(z + r*d) mod N:
    d = (s*k - z) * r^{-1} mod N
    """
    r_inv = modinv(sig.r, N)
    if r_inv is None:
        return None
    
    d = ((sig.s * k - sig.z) * r_inv) % N
    return d


def recover_key_from_known_linear_relation(sig: Signature, k: int) -> Optional[int]:
    """
    Given a signature and a known nonce k, recover the private key d.
    Same as recover_key_from_known_step_sequence.
    """
    return recover_key_from_known_step_sequence(sig, k)


def verify_private_key(d: int, expected_pubkey_point) -> bool:
    """
    Verify a recovered private key against a known public key point (Q = d*G).
    expected_pubkey_point: an object with .x() / .y() or None to skip.
    Caller supplies actual EC backend (e.g. the `ecdsa` library) if verification desired.
    """
    raise NotImplementedError("Wire up to your EC backend of choice (e.g. `ecdsa` lib)")
