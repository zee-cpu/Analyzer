import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from curve import Signature, N
from poly_recurrence import (
    PolyRecurrenceHypothesis,
    run_poly_recurrence_attack,
    sweep_poly_recurrence,
)
from tests.conftest import make_key, make_signature, G


def _make_recurrence_signatures(d, a_coeffs, count, rng, pubkey=None):
    """
    a_coeffs: coefficients of k_{i+1} = a_coeffs[0] + a_coeffs[1]*k_i +
    a_coeffs[2]*k_i^2 + ... (degree = len(a_coeffs) - 1)
    """
    k = [rng.randint(1, N - 1)]
    for i in range(count - 1):
        new_k = sum(a_coeffs[j] * (k[i] ** j) for j in range(len(a_coeffs))) % N
        k.append(new_k)

    sigs = []
    for i, ki in enumerate(k):
        r = (ki * G).x() % N
        z = rng.randint(1, N - 1)
        s = (pow(ki, -1, N) * (z + r * d)) % N
        sigs.append(Signature(r, s, z, pubkey=pubkey, index=i))
    return sigs


def test_degree_1_recurrence_exact_minimum_signatures():
    """
    Degree-1 (linear) recurrence with UNKNOWN alpha/beta, using exactly
    the minimum required signatures (degree+3=4). This is the
    generalization of exact_checks.py's known-coefficient linear
    relation check to the case where the coefficients themselves are
    unknown.
    """
    rng = random.Random(10000)
    d, pub, Q = make_key(seed=10000)
    alpha = rng.randint(1, N - 1)
    beta = rng.randint(1, N - 1)

    sigs = _make_recurrence_signatures(d, [beta, alpha], 4, rng, pubkey=pub)

    hyp = PolyRecurrenceHypothesis(degree=1)
    result = run_poly_recurrence_attack(sigs, hyp, Q, G)

    assert result.verified is True
    assert result.candidate_d == d


def test_sweep_recovers_key_from_longer_chain():
    """
    With more signatures than the strict minimum, the sweep should try
    multiple windows and recover the key even though any single window
    only has a partial chance of success (see module docstring).
    """
    rng = random.Random(10001)
    d, pub, Q = make_key(seed=10001)
    a_coeffs = [rng.randint(1, N - 1) for _ in range(4)]  # degree 3

    sigs = _make_recurrence_signatures(d, a_coeffs, 20, rng, pubkey=pub)

    results = sweep_poly_recurrence(sigs, Q, G, degrees=[1, 2, 3], max_windows_per_degree=15)
    hit = next((r for r in results if r.verified), None)

    assert hit is not None
    assert hit.candidate_d == d


def test_no_false_positive_on_random_unrelated_nonces():
    """
    Critical negative control: genuinely random nonces (no recurrence
    relation at all) must never produce a verified finding, across many
    attempted windows and degrees. Every candidate root is checked
    against the public key, so false positives require an astronomically
    unlikely collision.
    """
    rng = random.Random(10002)
    d, pub, Q = make_key(seed=10002)

    # Random nonces with no recurrence relation
    sigs = []
    for i in range(10):
        k = rng.randint(1, N - 1)
        z = rng.randint(1, N - 1)
        r = (k * G).x() % N
        s = (pow(k, -1, N) * (z + r * d)) % N
        sigs.append(Signature(r, s, z, pubkey=pub, index=i))

    results = sweep_poly_recurrence(sigs, Q, G, degrees=[1, 2, 3], max_windows_per_degree=10)
    verified = [r for r in results if r.verified]

    assert len(verified) == 0


def test_no_false_positive_across_multiple_independent_trials():
    """
    Run multiple independent trials with random nonces to ensure no
    false positives occur.
    """
    for trial in range(5):
        rng = random.Random(20000 + trial)
        d, pub, Q = make_key(seed=20000 + trial)

        sigs = []
        for i in range(8):
            k = rng.randint(1, N - 1)
            z = rng.randint(1, N - 1)
            r = (k * G).x() % N
            s = (pow(k, -1, N) * (z + r * d)) % N
            sigs.append(Signature(r, s, z, pubkey=pub, index=i))

        results = sweep_poly_recurrence(sigs, Q, G, degrees=[1, 2], max_windows_per_degree=5)
        verified = [r for r in results if r.verified]

        assert len(verified) == 0, f"False positive in trial {trial}"


def test_wrong_signature_count_returns_unverified_not_crash():
    """
    If we pass fewer signatures than required for a given degree,
    the attack should return an unverified result, not crash.
    """
    rng = random.Random(10003)
    d, pub, Q = make_key(seed=10003)

    # Only 2 signatures, but degree 1 needs 4
    sigs = []
    for i in range(2):
        k = rng.randint(1, N - 1)
        z = rng.randint(1, N - 1)
        r = (k * G).x() % N
        s = (pow(k, -1, N) * (z + r * d)) % N
        sigs.append(Signature(r, s, z, pubkey=pub, index=i))

    hyp = PolyRecurrenceHypothesis(degree=1)
    result = run_poly_recurrence_attack(sigs, hyp, Q, G)

    assert result.verified is False


def test_wrong_pubkey_never_falsely_verifies():
    """
    Even with a valid recurrence, using the wrong public key must
    never produce a verified result.
    """
    rng = random.Random(10004)
    d, pub, Q = make_key(seed=10004)
    _, _, wrong_Q = make_key(seed=99999)  # Different key

    alpha = rng.randint(1, N - 1)
    beta = rng.randint(1, N - 1)

    sigs = _make_recurrence_signatures(d, [beta, alpha], 4, rng, pubkey=pub)

    hyp = PolyRecurrenceHypothesis(degree=1)
    result = run_poly_recurrence_attack(sigs, hyp, wrong_Q, G)

    assert result.verified is False


def test_sweep_with_insufficient_signatures_reports_cleanly():
    """
    Sweep with too few signatures should return empty or unverified
    results, not crash.
    """
    rng = random.Random(10005)
    d, pub, Q = make_key(seed=10005)

    # Only 2 signatures
    sigs = []
    for i in range(2):
        k = rng.randint(1, N - 1)
        z = rng.randint(1, N - 1)
        r = (k * G).x() % N
        s = (pow(k, -1, N) * (z + r * d)) % N
        sigs.append(Signature(r, s, z, pubkey=pub, index=i))

    results = sweep_poly_recurrence(sigs, Q, G, degrees=[1, 2, 3], max_windows_per_degree=5)
    verified = [r for r in results if r.verified]

    assert len(verified) == 0
