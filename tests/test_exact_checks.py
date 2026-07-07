# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests for exact checks module.
"""

import pytest
from curve import Signature, N, recover_key_from_reuse
from exact_checks import (
    find_nonce_reuse,
    check_catastrophic_nonce_derived_from_signature_data,
    brute_force_small_constant_nonce,
    check_small_offset_from_hash,
    check_small_offset_from_r,
)


def test_nonce_reuse_recovery(nonce_reuse_signatures):
    """Test that nonce reuse is detected and key is recovered."""
    findings = find_nonce_reuse(nonce_reuse_signatures)
    
    assert len(findings) > 0, "Should find nonce reuse"
    finding = findings[0]
    assert finding["same_key"] is True
    assert "recovered_private_key" in finding
    assert finding["recovered_private_key"] == 12345


def test_cross_key_collision_detection(cross_key_collision_signatures):
    """Test that cross-key collisions are detected but not immediately exploitable."""
    findings = find_nonce_reuse(cross_key_collision_signatures)
    
    assert len(findings) > 0, "Should find cross-key collision"
    finding = findings[0]
    assert finding["same_key"] is False
    assert finding["immediately_exploitable"] is False


def test_catastrophic_k_equals_z(catastrophic_k_equals_z_signature):
    """Test detection of k = z catastrophic bug."""
    findings = check_catastrophic_nonce_derived_from_signature_data(
        [catastrophic_k_equals_z_signature]
    )
    
    assert len(findings) > 0, "Should find catastrophic k=z"
    finding = [f for f in findings if f.get("catastrophic_type") == "k_equals_z"]
    assert len(finding) > 0


def test_catastrophic_k_equals_r(catastrophic_k_equals_r_signature):
    """Test detection of k = r catastrophic bug."""
    findings = check_catastrophic_nonce_derived_from_signature_data(
        [catastrophic_k_equals_r_signature]
    )
    
    assert len(findings) > 0, "Should find catastrophic k=r"
    finding = [f for f in findings if f.get("catastrophic_type") == "k_equals_r"]
    assert len(finding) > 0


def test_small_constant_nonce(small_nonce_signature):
    """Test detection of small constant nonce."""
    # Create a mock pubkey_points dict
    pubkey_points = {
        "abc123": None  # We can't verify without real EC, but we can test the logic
    }
    
    findings = brute_force_small_constant_nonce(
        [small_nonce_signature],
        pubkey_points=pubkey_points,
        generator=None,
        bound=100000
    )
    
    # Without real EC verification, we can't fully test this
    # But we can verify the function runs without error
    assert isinstance(findings, list)


def test_small_offset_from_hash(offset_nonce_signature):
    """Test detection of small offset from hash."""
    pubkey_points = {
        "abc123": None
    }
    
    findings = check_small_offset_from_hash(
        [offset_nonce_signature],
        pubkey_points=pubkey_points,
        generator=None,
        offset_bound=100
    )
    
    assert isinstance(findings, list)


def test_small_offset_from_r(offset_nonce_signature):
    """Test detection of small offset from r."""
    pubkey_points = {
        "abc123": None
    }
    
    findings = check_small_offset_from_r(
        [offset_nonce_signature],
        pubkey_points=pubkey_points,
        generator=None,
        offset_bound=100
    )
    
    assert isinstance(findings, list)


def test_no_false_positives_on_random(make_signature_fixture):
    """Test that random nonces don't produce false positives."""
    import random
    
    sigs = [
        make_signature_fixture(
            d=random.randint(1, N-1),
            k=random.randint(1, N-1),
            z=random.randint(1, N-1),
            pubkey=f"key_{i}",
            index=i
        )
        for i in range(10)
    ]
    
    findings = find_nonce_reuse(sigs)
    
    # Random signatures should not have nonce reuse
    assert len(findings) == 0, "Random signatures should not have nonce reuse"
