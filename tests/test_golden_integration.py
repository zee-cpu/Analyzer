"""
Golden end-to-end integration test.

Unlike the per-module unit tests, this exercises the REAL main.py phase
functions (run_exact_phase, run_lattice_phase, run_poly_recurrence_phase,
print_final_verdict) directly, in the same sequence main() calls them -
not a reimplementation of that logic, the actual production code path.

One canonical multi-key dataset with KNOWN ground truth is used across
all three phases, so a regression in how the phases integrate together
(not just in the underlying detection functions, which already have
their own unit tests) gets caught here. This is the test recommended
after the project's SOTA pipeline was otherwise complete, specifically
to have ONE test that would fail if a future change broke the wiring
between phases rather than the phases' internal logic.

Kept deliberately small and fast (lattice phase runs in 'fast' mode
only) so this can be run routinely, not just occasionally - a slow
golden test that people avoid running defeats its own purpose.
"""

import pytest
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from curve import Signature, N
from parser import group_by_pubkey
from tests.conftest import make_key, G, make_signature
import main as main_module


def _sign(k, z, d):
    r = (k * G).x() % N
    s = (pow(k, -1, N) * (z + r * d)) % N
    return r, s


def _random_z(rng):
    return rng.randint(1, N - 1)


def build_golden_dataset():
    """
    Four keys, each with a known ground-truth outcome:

    1. key_reuse: same-key nonce reuse -> Phase 1 should recover this key
       directly, before Phase 2/3 even matter.
    2. key_lattice_bias: 40-bit MSB-biased nonces, uniform across all
       signatures -> Phase 2 (fast mode) should recover this key.
    3. key_poly_recurrence: unknown-coefficient linear recurrence ->
       Phase 1/2 should NOT catch this (no reuse, no bounded bit bias),
       Phase 3 should recover it.
    4. key_clean: genuinely random nonces, no relation of any kind ->
       no phase should report a finding. This is the most important key
       in the set - a false positive here across ANY phase is a bug.

    Returns (all_signatures, ground_truth_dict).
    """
    rng = random.Random(99999)
    all_sigs = []
    ground_truth = {}
    idx = 0

    def emit(sigs_list, pubkey, sig_data):
        nonlocal idx
        for r, s, z in sig_data:
            sigs_list.append(Signature(r, s, z, pubkey=pubkey, index=idx))
            idx += 1

    # --- Key 1: same-key nonce reuse ---
    d1, pub1, Q1 = make_key(seed=1001)
    sigs1 = []
    for _ in range(10):
        k = rng.randint(1, N - 1)
        z = _random_z(rng)
        r, s = _sign(k, z, d1)
        emit(sigs1, pub1, [(r, s, z)])
    k_reused = rng.randint(1, N - 1)
    z_a, z_b = _random_z(rng), _random_z(rng)
    emit(sigs1, pub1, [_sign(k_reused, z_a, d1) + (z_a,)])
    emit(sigs1, pub1, [_sign(k_reused, z_b, d1) + (z_b,)])
    all_sigs.extend(sigs1)
    ground_truth["key_reuse"] = {"pubkey": pub1, "private_key": d1, "expected_phase": 1}

    # --- Key 2: 40-bit MSB lattice bias, uniform ---
    d2, pub2, Q2 = make_key(seed=1002)
    sigs2 = []
    for _ in range(18):
        k = rng.randint(0, (1 << (256 - 40)) - 1)
        z = _random_z(rng)
        r, s = _sign(k, z, d2)
        emit(sigs2, pub2, [(r, s, z)])
    all_sigs.extend(sigs2)
    ground_truth["key_lattice_bias"] = {"pubkey": pub2, "private_key": d2, "expected_phase": 2}

    # --- Key 3: unknown-coefficient linear recurrence ---
    d3, pub3, Q3 = make_key(seed=1003)
    alpha = rng.randint(1, N - 1)
    beta = rng.randint(1, N - 1)
    k = rng.randint(1, N - 1)
    sigs3 = []
    for _ in range(10):
        z = _random_z(rng)
        r, s = _sign(k, z, d3)
        emit(sigs3, pub3, [(r, s, z)])
        k = (alpha * k + beta) % N
    all_sigs.extend(sigs3)
    ground_truth["key_poly_recurrence"] = {"pubkey": pub3, "private_key": d3, "expected_phase": 3}

    # --- Key 4: genuinely clean, no relation of any kind ---
    d4, pub4, Q4 = make_key(seed=1004)
    sigs4 = []
    for _ in range(20):
        k = rng.randint(1, N - 1)
        z = _random_z(rng)
        r, s = _sign(k, z, d4)
        emit(sigs4, pub4, [(r, s, z)])
    all_sigs.extend(sigs4)
    ground_truth["key_clean"] = {"pubkey": pub4, "private_key": d4, "expected_phase": None}

    return all_sigs, ground_truth


def test_golden_dataset_full_pipeline():
    """
    Runs the actual main.py phase functions in sequence (not a
    reimplementation) against the golden dataset, and checks that:
    - key_reuse is recovered by Phase 1
    - key_lattice_bias is recovered by Phase 2 (fast mode)
    - key_poly_recurrence is recovered by Phase 3
    - key_clean produces NO finding in any phase (most important assertion)
    """
    sigs, ground_truth = build_golden_dataset()
    groups = group_by_pubkey(sigs)

    # --- Phase 1 ---
    exact_results = main_module.run_exact_phase(groups)

    reuse_hit = next(
        (f for f in exact_results["reuse_findings"] if f.get("immediately_exploitable")),
        None,
    )
    assert reuse_hit is not None, "Phase 1 failed to recover the same-key nonce reuse"
    assert reuse_hit["recovered_private_key"] == ground_truth["key_reuse"]["private_key"]

    # nothing else should have been flagged as exploitable by Phase 1
    other_exploitable = [
        f for f in exact_results["reuse_findings"]
        if f.get("immediately_exploitable") and f is not reuse_hit
    ]
    assert other_exploitable == [], "Phase 1 found unexpected additional reuse"
    assert exact_results["sequential_findings"] == []
    assert exact_results["linear_relation_findings"] == []

    # --- Phase 2 (fast mode only, to keep this test fast) ---
    lattice_summary, _ = main_module.run_lattice_phase(groups, mode="fast")

    lattice_hit = next((r for r in lattice_summary if r[2] == "COMPROMISED"), None)
    assert lattice_hit is not None, "Phase 2 failed to recover the lattice-biased key"
    assert lattice_hit[0].startswith(ground_truth["key_lattice_bias"]["pubkey"][:16])

    # key_clean must NOT show up as compromised in the lattice phase
    clean_pub_prefix = ground_truth["key_clean"]["pubkey"][:16]
    assert not any(
        r[0].startswith(clean_pub_prefix) and r[2] == "COMPROMISED"
        for r in lattice_summary
    ), "Phase 2 falsely flagged the clean key as compromised"

    # --- Phase 3 ---
    poly_summary, _ = main_module.run_poly_recurrence_phase(groups)

    poly_hit = next((r for r in poly_summary if r[2] == "COMPROMISED"), None)
    assert poly_hit is not None, "Phase 3 failed to recover the polynomial-recurrence key"
    assert poly_hit[0].startswith(ground_truth["key_poly_recurrence"]["pubkey"][:16])

    assert not any(
        r[0].startswith(clean_pub_prefix) and r[2] == "COMPROMISED"
        for r in poly_summary
    ), "Phase 3 falsely flagged the clean key as compromised"

    # --- Final verdict wiring ---
    from rich.console import Console as RichConsole

    original_console = main_module.console
    recording_console = RichConsole(record=True, width=100)
    main_module.console = recording_console
    try:
        main_module.print_final_verdict(exact_results, lattice_summary, poly_summary)
    finally:
        main_module.console = original_console

    rendered = recording_console.export_text()
    assert "COMPROMISED" in rendered, (
        "print_final_verdict did not report COMPROMISED despite real "
        "findings from Phase 1/2/3 - this is the actual integration bug "
        "class this test exists to catch"
    )


def test_golden_dataset_clean_key_alone_produces_no_findings():
    """
    Isolates just the clean key (no other keys in the dataset at all) and
    confirms every phase reports nothing - this is the same assertion as
    above but without other keys present, in case cross-key interference
    (e.g. accidental grouping bugs) could mask a false positive when
    other compromised keys are in the same run.
    """
    rng = random.Random(2000)
    d, pub, Q = make_key(seed=2000)
    sigs = []
    for i in range(20):
        k = rng.randint(1, N - 1)
        z = _random_z(rng)
        r, s = _sign(k, z, d)
        sigs.append(Signature(r, s, z, pubkey=pub, index=i))

    groups = group_by_pubkey(sigs)

    exact_results = main_module.run_exact_phase(groups)
    assert exact_results["reuse_findings"] == []
    assert exact_results["const_findings"] == []
    assert exact_results["sequential_findings"] == []
    assert exact_results["linear_relation_findings"] == []

    lattice_summary, _ = main_module.run_lattice_phase(groups, mode="fast")
    assert not any(r[2] == "COMPROMISED" for r in lattice_summary)

    poly_summary, _ = main_module.run_poly_recurrence_phase(groups)
    assert not any(r[2] == "COMPROMISED" for r in poly_summary)
