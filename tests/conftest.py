# SPDX-License-Identifier: GPL-3.0-or-later
"""
Pytest fixtures for ECDSA analyzer tests.
"""

import pytest
import random
from curve import Signature, N


# Mock EC point for testing (simplified, not real secp256k1)
class MockPoint:
    """Mock EC point for testing purposes."""
    def __init__(self, x: int, y: int = None):
        self.x_val = x
        self.y_val = y if y is not None else x  # Default y to x for simplicity
    
    def x(self):
        return self.x_val
    
    def y(self):
        return self.y_val
    
    def __eq__(self, other):
        if not isinstance(other, MockPoint):
            return False
        return self.x_val == other.x_val and self.y_val == other.y_val
    
    def __mul__(self, scalar: int):
        """Mock scalar multiplication."""
        # Simplified: just scale the x coordinate
        return MockPoint((self.x_val * scalar) % N, (self.y_val * scalar) % N if self.y_val else None)
    
    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)
    
    def __hash__(self):
        return hash((self.x_val, self.y_val))


# Mock generator point
G = MockPoint(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)


def make_key_func(seed: int = None) -> tuple[int, str, "MockPoint"]:
    """
    Create a key pair (d, pubkey_str, Q) where Q = d*G.
    
    Returns:
        d: private key
        pubkey_str: hex string representation of public key
        Q: public key point (MockPoint)
    """
    if seed is not None:
        rng = random.Random(seed)
        d = rng.randint(1, N - 1)
    else:
        d = random.randint(1, N - 1)
    Q = d * G
    pubkey_str = hex(Q.x_val)
    return d, pubkey_str, Q


def make_signature_func(d: int, k: int, z: int, pubkey: str = None, index: int = 0) -> Signature:
    """
    Create a signature from private key d, nonce k, and message hash z.
    
    In real ECDSA:
    - r = (k*G).x mod N
    - s = k^{-1}(z + r*d) mod N
    
    For testing, we compute r from k*G.
    """
    # r = (k*G).x mod N
    r = (k * G).x() % N
    
    # s = k^{-1}(z + r*d) mod N
    k_inv = pow(k, -1, N)
    s = (k_inv * (z + r * d)) % N
    
    return Signature(
        r=r,
        s=s,
        z=z,
        pubkey=pubkey,
        index=index,
    )


# Export functions for direct import by tests
make_key = make_key_func
make_signature = make_signature_func


@pytest.fixture
def make_signature_fixture():
    """Factory fixture that creates valid signatures from (d, k, z)."""
    return make_signature_func


@pytest.fixture
def make_key_fixture():
    """Factory fixture that creates a key pair (d, pubkey_str, Q)."""
    return make_key_func


@pytest.fixture
def sample_signatures():
    """Create a set of sample signatures for testing."""
    return [
        make_signature_func(d=12345, k=67890, z=11111, pubkey="abc123", index=0),
        make_signature_func(d=12345, k=67891, z=22222, pubkey="abc123", index=1),
        make_signature_func(d=54321, k=99999, z=33333, pubkey="def456", index=2),
    ]


@pytest.fixture
def nonce_reuse_signatures():
    """Create signatures with nonce reuse (same k, same key)."""
    d = 12345
    k = 67890  # Same nonce
    return [
        make_signature_func(d=d, k=k, z=11111, pubkey="abc123", index=0),
        make_signature_func(d=d, k=k, z=22222, pubkey="abc123", index=1),
    ]


@pytest.fixture
def cross_key_collision_signatures():
    """Create signatures with cross-key r-collision (same k, different keys)."""
    k = 67890  # Same nonce
    return [
        make_signature_func(d=12345, k=k, z=11111, pubkey="abc123", index=0),
        make_signature_func(d=54321, k=k, z=22222, pubkey="def456", index=1),
    ]


@pytest.fixture
def catastrophic_k_equals_z_signature():
    """Create a signature where k = z (catastrophic bug)."""
    d = 12345
    z = 67890
    k = z  # Catastrophic: k = z
    return make_signature_func(d=d, k=k, z=z, pubkey="abc123", index=0)


@pytest.fixture
def catastrophic_k_equals_r_signature():
    """Create a signature where k = r (catastrophic bug)."""
    d = 12345
    k = 67890
    z = 11111
    return make_signature_func(d=d, k=k, z=z, pubkey="abc123", index=0)


@pytest.fixture
def small_nonce_signature():
    """Create a signature with a small constant nonce."""
    d = 12345
    k = 12345  # Small nonce
    z = 67890
    return make_signature_func(d=d, k=k, z=z, pubkey="abc123", index=0)


@pytest.fixture
def offset_nonce_signature():
    """Create a signature with k = z + offset."""
    d = 12345
    z = 67890
    offset = 7
    k = (z + offset) % N
    return make_signature_func(d=d, k=k, z=z, pubkey="abc123", index=0)
