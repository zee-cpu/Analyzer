# SPDX-License-Identifier: GPL-3.0-or-later
"""
Phase 1: exact, deterministic checks. No statistics, no thresholds, no lattice.
Every finding here is a mathematical certainty (up to ~2^-128 collision chance),
not a confidence score.
"""

from collections import defaultdict
from curve import Signature, recover_key_from_reuse, N, modinv


def find_nonce_reuse(signatures: list[Signature]) -> list[dict]:
    """
    Group ALL signatures by r value, regardless of claimed pubkey.
    Any group with >1 signature means the same nonce k was used twice.

    This single check subsumes both "same-key reuse" and "cross-key reuse" -
    the r-collision is the event; whether the two signatures claim the same
    pubkey just changes what you can immediately do with the result.
    """
    by_r = defaultdict(list)
    for sig in signatures:
        by_r[sig.r].append(sig)

    findings = []
    for r, group in by_r.items():
        if len(group) < 2:
            continue

        # check every pair in the collision group
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                sig_a, sig_b = group[i], group[j]
                same_key = (
                    sig_a.pubkey is not None
                    and sig_a.pubkey == sig_b.pubkey
                )

                finding = {
                    "r": r,
                    "sig_indices": (sig_a.index, sig_b.index),
                    "same_key": same_key,
                    "immediately_exploitable": same_key,
                }

                if same_key:
                    recovered = recover_key_from_reuse(sig_a, sig_b)
                    if recovered:
                        k, d = recovered
                        finding["recovered_nonce"] = k
                        finding["recovered_private_key"] = d
                    else:
                        finding["immediately_exploitable"] = False
                        finding["note"] = "degenerate pair (s1 == s2), cannot solve"
                else:
                    finding["note"] = (
                        "r collision across different claimed pubkeys - "
                        "same nonce used by two different signers. Not "
                        "directly solvable without independently knowing "
                        "one of the two private keys, but is strong forensic "
                        "evidence of a shared broken RNG."
                    )

                findings.append(finding)

    return findings


# Nonce bit-length classes actually observed and published in Breitner &
# Heninger, "Biased Nonce Sense" (eprint.iacr.org/2019/023), Table 1 and
# Section 5.4. These are real incident signatures, not invented thresholds -
# each entry cites the exact bit length and known root cause where published.
#
# NOTE: these are bit-length CLASSES to test the lattice attack against, not
# literal r-value ranges - the paper's attack works by hypothesizing a nonce
# bit-length and running HNP lattice reduction, exactly like our
# hnp_lattice.sweep_bias_hypotheses(). This table tells the sweep which
# bit-widths are worth prioritizing first because they have real-world
# precedent, rather than sweeping blindly.
KNOWN_INCIDENT_BIT_LENGTHS = [
    {
        "name": "bitcore 64-bit nonce bug",
        "nonce_bits": 64,
        "side": "msb",  # nonce itself is short/small -> top bits are the "known" (zero) portion
        "source": "Breitner & Heninger 2019, Sec 5.4 - bitcore JS library, "
                   "July 12 2014 - Aug 11 2014, root-caused to an EC library "
                   "swap that set nonce length to 8 bytes",
        "citation": "eprint.iacr.org/2019/023",
    },
    {
        "name": "160-bit nonce (sporadic)",
        "nonce_bits": 160,
        "side": "msb",
        "source": "Breitner & Heninger 2019, Sec 5.4 - 3 signatures, single key, "
                   "Sept 2017, cause unconfirmed (hypothesized 160-bit hash-based nonce gen)",
        "citation": "eprint.iacr.org/2019/023",
    },
    {
        "name": "128-bit nonce (sporadic)",
        "nonce_bits": 128,
        "side": "msb",
        "source": "Breitner & Heninger 2019, Sec 5.4 - 4 signatures, 2 keys, March 2016",
        "citation": "eprint.iacr.org/2019/023",
    },
    {
        "name": "110-bit nonce (sporadic)",
        "nonce_bits": 110,
        "side": "msb",
        "source": "Breitner & Heninger 2019, Sec 5.4 - 1 signature, Jan 2017",
        "citation": "eprint.iacr.org/2019/023",
    },
    {
        "name": "224-bit key, 160-bit DSA nonce",
        "nonce_bits": 160,
        "side": "msb",
        "source": "Breitner & Heninger 2019, Sec 8 (SSH) - hypothesized SHA-1/MD5-based "
                   "nonce generation in a 224-bit subgroup",
        "citation": "eprint.iacr.org/2019/023",
    },
]

# The single most common repeated-nonce constant found on-chain by the same
# paper: k = (n-1)/2, responsible for 2,456,870 signatures in their dataset.
# This is a literal equality check, same rigor as find_nonce_reuse - not a
# statistical guess.
KNOWN_CONSTANT_NONCE_K = (
    0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
)
KNOWN_CONSTANT_NONCE_SOURCE = (
    "Breitner & Heninger 2019, Sec 5.4 - by far the most common repeated-nonce "
    "value found on the Bitcoin blockchain. Root cause not confirmed in the "
    "paper; value equals (n-1)/2 for secp256k1's order n."
)


def check_known_constant_nonce(signatures: list[Signature]) -> list[dict]:
    """
    Cheap, exact pre-check: does any signature's r equal the r produced by
    the published k=(n-1)/2 constant nonce, responsible for millions of real
    Bitcoin repeated-nonce incidents? Direct equality check on r, computed
    once from the known constant - no statistics involved.

    If two or more signatures share this r, find_nonce_reuse() will already
    flag and solve the collision - this check exists to label *why* it
    happened for reporting purposes, and to flag a single occurrence even
    before a second one is seen.
    """
    from ecdsa import SECP256k1
    G = SECP256k1.generator
    r_const = (KNOWN_CONSTANT_NONCE_K * G).x() % N

    findings = []
    for sig in signatures:
        if sig.r == r_const:
            findings.append({
                "signature_index": sig.index,
                "match": "k = (n-1)/2 published constant nonce",
                "note": KNOWN_CONSTANT_NONCE_SOURCE,
                "recovered_nonce": KNOWN_CONSTANT_NONCE_K,
            })
    return findings


def recommended_bias_bit_widths() -> list[int]:
    """
    Bit-widths worth prioritizing first in an HNP lattice sweep, based on
    real published incidents (see KNOWN_INCIDENT_BIT_LENGTHS) rather than an
    arbitrary geometric sequence. Callers should still run a broader blind
    sweep afterward for coverage beyond documented incident classes.
    """
    return sorted({e["nonce_bits"] for e in KNOWN_INCIDENT_BIT_LENGTHS})


def recover_key_from_known_step_sequence(sig_a: Signature, sig_b: Signature, step: int, index_gap: int = 1) -> int | None:
    """
    If two signatures from the SAME key came from nonces related by a
    known step (k_b = k_a + step * index_gap mod N - e.g. a broken counter
    incrementing by a fixed, suspected amount), the private key is
    recoverable directly via linear algebra - no lattice needed. This is
    the sequential-nonce special case of the general "known relationship
    between nonces" family; it's an exact solve like nonce reuse, not a
    probabilistic search, as long as the step value is actually correct.

    Derivation: from k = a*d + b (mod N) where a = r*s^-1, b = z*s^-1:
        k_a = a_a*d + b_a
        k_b = a_b*d + b_b = k_a + step*index_gap
    Subtracting: (a_b - a_a)*d = (b_a - b_b) + step*index_gap  (mod N)
    solves directly for d.

    Returns the candidate private key, or None if the equations are
    degenerate (a_a == a_b, i.e. r_a*s_a^-1 == r_b*s_b^-1). The caller
    MUST verify the candidate against a known public key point - an
    incorrect step guess produces a numerically valid but wrong d, this
    function cannot tell the difference on its own (unlike nonce reuse,
    where r_a == r_b is itself strong evidence before any solve is
    attempted; here the step is a guess, not an observed fact).
    """
    s_a_inv = modinv(sig_a.s, N)
    s_b_inv = modinv(sig_b.s, N)
    a_a = (sig_a.r * s_a_inv) % N
    b_a = (sig_a.z * s_a_inv) % N
    a_b = (sig_b.r * s_b_inv) % N
    b_b = (sig_b.z * s_b_inv) % N

    coef = (a_b - a_a) % N
    if coef == 0:
        return None

    rhs = (b_a - b_b + step * index_gap) % N
    d_candidate = (rhs * modinv(coef, N)) % N
    return d_candidate


def check_sequential_nonce_candidates(
    signatures_by_key: dict,
    pubkey_points: dict,
    generator,
    candidate_steps: list[int] = None,
) -> list[dict]:
    """
    For each key's signature set, try a list of suspected small step
    values against adjacent signature pairs (by list order - callers
    should pass signatures already sorted by whatever ordering is
    plausible, e.g. timestamp or original file order, since "adjacent"
    only means something meaningful under a real ordering).

    candidate_steps defaults to [1, 2, -1, -2] - the overwhelmingly most
    common real-world sequential nonce bugs are a counter incrementing or
    decrementing by 1 or 2 (off-by-one style bugs). This is deliberately
    NOT an open-ended search: testing every step up to some bound would
    need one solve + one EC verification per step per pair, and the
    value of doing that quickly drops once you're past small, plausible
    step sizes a real counter bug would produce - at that point you're
    better served by the unknown-small-step lattice approach (separate,
    not yet implemented) than by guessing arbitrarily many literal values.

    pubkey_points: dict mapping the same keys used in signatures_by_key
    to their EC public key points, for verification. A key with no entry
    here is skipped (candidates can't be verified without it - same
    requirement as the lattice phase).

    Returns confirmed findings only - every entry here has already been
    verified against the real public key point, so (unlike a lattice
    "candidate") a result in this list is a certain, not probabilistic,
    recovered private key.
    """
    if candidate_steps is None:
        candidate_steps = [1, 2, -1, -2]

    findings = []
    for pubkey, sigs in signatures_by_key.items():
        if pubkey not in pubkey_points or len(sigs) < 2:
            continue
        Q = pubkey_points[pubkey]

        for i in range(len(sigs) - 1):
            sig_a, sig_b = sigs[i], sigs[i + 1]
            for step in candidate_steps:
                candidate_d = recover_key_from_known_step_sequence(sig_a, sig_b, step, index_gap=1)
                if candidate_d is None:
                    continue
                if candidate_d * generator == Q:
                    findings.append({
                        "pubkey": pubkey,
                        "sig_indices": (sig_a.index, sig_b.index),
                        "assumed_step": step,
                        "recovered_private_key": candidate_d,
                        "note": f"nonces related by k_next = k_prev + ({step}) mod N, "
                                f"verified against the real public key",
                    })
                    break  # found the right step for this pair, no need to try others

    return findings


def recover_key_from_known_linear_relation(
    sig_a: Signature, sig_b: Signature, alpha: int, beta: int
) -> int | None:
    """
    Generalization of recover_key_from_known_step_sequence to an arbitrary
    KNOWN affine relation between two nonces from the same key:
        k_b = alpha * k_a + beta  (mod N)
    for known alpha, beta. This is the "C2: linear nonce relations" case
    documented in real-world MEV searcher nonce failures (Madhwal et al.,
    "Chain Reactions: How Nonce Collisions in ECDSA Compromise Polygon MEV
    Searchers", arXiv:2605.21498) - predictable nonce-generation shortcuts
    (e.g. reusing a scaled or offset counter for speed under latency
    pressure) create exactly this relation.

    NOTE ON SCOPE: this requires alpha and beta to be KNOWN or SPECIFICALLY
    SUSPECTED values to test, not unknowns to be discovered. The literature
    is clear that the case where alpha/beta themselves are unknown (a true
    "blind" LCG with hidden parameters) does not have an established,
    provably-correct lattice construction - Bleichenbacher's classical LCG
    attack and its ECDSA adaptations require KNOWN generator parameters,
    and at least one recent paper (Cebrian-Marquez, "Breaking ECDSA with
    Two Affinely Related Nonces", 2025) explicitly lists the fully-unknown-
    coefficient case as open future work rather than a solved problem. This
    function deliberately does NOT attempt that harder, unresolved case -
    see check_linear_relation_candidates for the specific known-coefficient
    values it tests by default (the step=1 sequential case is the alpha=1
    special case, already covered by recover_key_from_known_step_sequence).

    Derivation: from k = a*d + b (mod N):
        k_a = a_a*d + b_a
        k_b = a_b*d + b_b = alpha*k_a + beta = alpha*(a_a*d + b_a) + beta
    => (a_b - alpha*a_a)*d = alpha*b_a + beta - b_b  (mod N)
    solves directly for d.

    Returns the candidate private key, or None if degenerate
    (a_b == alpha*a_a mod N). As with the sequential case, the caller MUST
    verify the candidate against a known public key point.
    """
    s_a_inv = modinv(sig_a.s, N)
    s_b_inv = modinv(sig_b.s, N)
    a_a = (sig_a.r * s_a_inv) % N
    b_a = (sig_a.z * s_a_inv) % N
    a_b = (sig_b.r * s_b_inv) % N
    b_b = (sig_b.z * s_b_inv) % N

    coef = (a_b - alpha * a_a) % N
    if coef == 0:
        return None

    rhs = (alpha * b_a + beta - b_b) % N
    d_candidate = (rhs * modinv(coef, N)) % N
    return d_candidate


def check_linear_relation_candidates(
    signatures_by_key: dict,
    pubkey_points: dict,
    generator,
    candidate_relations: list[tuple[int, int]] = None,
) -> list[dict]:
    """
    For each key's signature set, try a list of suspected (alpha, beta)
    affine relations against adjacent signature pairs. Same exact-solve,
    verify-against-real-pubkey approach as check_sequential_nonce_candidates
    (which this generalizes and would be redundant with for alpha=1 cases -
    run that one for pure counter-style bugs, this one for scaled/doubled
    nonce reuse patterns).

    candidate_relations defaults to a small set of simple, real-world-
    plausible scalings: doubling/halving (alpha=2 or a modular half) and
    sign-flip variants, PLUS beta offsets of 0, 1, -1. This is deliberately
    a small, curated list of plausible relations a real implementation
    shortcut might produce - not an open-ended search, for the same reason
    check_sequential_nonce_candidates only tries a few step values rather
    than searching arbitrarily far.
    """
    if candidate_relations is None:
        half = modinv(2, N)
        candidate_relations = [
            (2, 0), (2, 1), (2, -1),
            (half, 0), (half, 1), (half, -1),
            (-1, 0), (-1, 1), (-1, -1),
        ]

    findings = []
    for pubkey, sigs in signatures_by_key.items():
        if pubkey not in pubkey_points or len(sigs) < 2:
            continue
        Q = pubkey_points[pubkey]

        for i in range(len(sigs) - 1):
            sig_a, sig_b = sigs[i], sigs[i + 1]
            for alpha, beta in candidate_relations:
                candidate_d = recover_key_from_known_linear_relation(sig_a, sig_b, alpha, beta)
                if candidate_d is None:
                    continue
                if candidate_d * generator == Q:
                    findings.append({
                        "pubkey": pubkey,
                        "sig_indices": (sig_a.index, sig_b.index),
                        "assumed_alpha": alpha,
                        "assumed_beta": beta,
                        "recovered_private_key": candidate_d,
                        "note": f"nonces related by k_b = {alpha}*k_a + ({beta}) mod N, "
                                f"verified against the real public key",
                    })
                    break

    return findings


# ============================================================================
# AGENT 3: Single-Signature Catastrophic Checks
# ============================================================================

def check_catastrophic_nonce_derived_from_signature_data(
    signatures: list[Signature],
    pubkey_points: dict = None,
    generator = None,
) -> list[dict]:
    """
    Test for catastrophic nonce derivation bugs where k is derived from
    known signature data (z, r, or d itself).
    
    Tests three cases:
    1. k = z (message hash used as nonce)
    2. k = r (signature r-coordinate used as nonce)
    3. k = d (private key used as nonce)
    
    For each case, computes candidate d and verifies against pubkey if available.
    
    Returns list of findings with recovered keys.
    """
    findings = []
    
    for sig in signatures:
        # Case 1: k = z
        # d = (s - 1) * z * r^{-1} mod N
        # Derivation: s = k^{-1}(z + rd) = z^{-1}(z + rd)
        # => s*z = z + rd => rd = s*z - z = z(s-1) => d = z(s-1)r^{-1}
        r_inv = modinv(sig.r, N)
        if r_inv is not None:
            d_candidate = ((sig.s - 1) * sig.z * r_inv) % N
            if d_candidate > 0:
                finding = {
                    "sig_index": sig.index,
                    "catastrophic_type": "k_equals_z",
                    "recovered_private_key": d_candidate,
                    "note": "nonce derived from message hash: k = z",
                }
                
                # Verify if pubkey is available
                if pubkey_points and sig.pubkey and sig.pubkey in pubkey_points:
                    Q = pubkey_points[sig.pubkey]
                    if generator and d_candidate * generator == Q:
                        finding["verified"] = True
                        findings.append(finding)
                    else:
                        finding["verified"] = False
                else:
                    # No verification possible, but still report as candidate
                    finding["verified"] = None
                    findings.append(finding)
        
        # Case 2: k = r
        # d = s - z * r^{-1} mod N
        # Derivation: s = r^{-1}(z + rd) => sr = z + rd => d = (sr - z)r^{-1} = s - zr^{-1}
        if r_inv is not None:
            d_candidate = (sig.s - sig.z * r_inv) % N
            if d_candidate > 0:
                finding = {
                    "sig_index": sig.index,
                    "catastrophic_type": "k_equals_r",
                    "recovered_private_key": d_candidate,
                    "note": "nonce derived from signature r-coordinate: k = r",
                }
                
                if pubkey_points and sig.pubkey and sig.pubkey in pubkey_points:
                    Q = pubkey_points[sig.pubkey]
                    if generator and d_candidate * generator == Q:
                        finding["verified"] = True
                        findings.append(finding)
                    else:
                        finding["verified"] = False
                else:
                    finding["verified"] = None
                    findings.append(finding)
        
        # Case 3: k = d (private key used as nonce)
        # d = z * (s - r)^{-1} mod N
        # Derivation: s = d^{-1}(z + rd) => sd = z + rd => d(s - r) = z => d = z(s-r)^{-1}
        s_minus_r = (sig.s - sig.r) % N
        s_minus_r_inv = modinv(s_minus_r, N)
        if s_minus_r_inv is not None:
            d_candidate = (sig.z * s_minus_r_inv) % N
            if d_candidate > 0:
                finding = {
                    "sig_index": sig.index,
                    "catastrophic_type": "k_equals_d",
                    "recovered_private_key": d_candidate,
                    "note": "nonce derived from private key: k = d",
                }
                
                if pubkey_points and sig.pubkey and sig.pubkey in pubkey_points:
                    Q = pubkey_points[sig.pubkey]
                    if generator and d_candidate * generator == Q:
                        finding["verified"] = True
                        findings.append(finding)
                    else:
                        finding["verified"] = False
                else:
                    finding["verified"] = None
                    findings.append(finding)
    
    return findings


def brute_force_small_constant_nonce(
    signatures: list[Signature],
    pubkey_points: dict = None,
    generator = None,
    bound: int = 2**24,
) -> list[dict]:
    """
    Brute-force test small constant nonces k in [1, bound].
    
    For each signature with a known pubkey, test:
    d = (s*k - z) * r^{-1} mod N
    
    Verify d*G == Q.
    
    Optimization: Precompute r^{-1}*G once per signature, then incrementally check.
    
    Args:
        signatures: List of signatures to test
        pubkey_points: Dict mapping pubkey hex to EC point
        generator: EC generator point
        bound: Maximum nonce value to test (default 2^24)
    
    Returns:
        List of findings with recovered keys
    """
    findings = []
    
    if not pubkey_points or not generator:
        return findings
    
    for sig in signatures:
        if not sig.pubkey or sig.pubkey not in pubkey_points:
            continue
        
        Q = pubkey_points[sig.pubkey]
        r_inv = modinv(sig.r, N)
        if r_inv is None:
            continue
        
        # Test each small nonce
        for k in range(1, min(bound + 1, 2**25)):  # Cap at 2^25 to avoid excessive loops
            d_candidate = ((sig.s * k - sig.z) * r_inv) % N
            if d_candidate > 0 and d_candidate * generator == Q:
                findings.append({
                    "sig_index": sig.index,
                    "pubkey": sig.pubkey,
                    "attack_type": "small_constant_nonce",
                    "recovered_nonce": k,
                    "recovered_private_key": d_candidate,
                    "note": f"small constant nonce found: k = {k}",
                    "verified": True,
                })
                break  # Found the nonce for this signature
    
    return findings


def check_small_offset_from_hash(
    signatures: list[Signature],
    pubkey_points: dict = None,
    generator = None,
    offset_bound: int = 2**16,
) -> list[dict]:
    """
    Test k = z + c for small offsets c in [-offset_bound, offset_bound].
    
    For each signature with known pubkey:
    d = (s*(z+c) - z) * r^{-1} mod N
      = (s*z + s*c - z) * r^{-1} mod N
      = (z(s-1) + s*c) * r^{-1} mod N
    
    Verify d*G == Q.
    """
    findings = []
    
    if not pubkey_points or not generator:
        return findings
    
    for sig in signatures:
        if not sig.pubkey or sig.pubkey not in pubkey_points:
            continue
        
        Q = pubkey_points[sig.pubkey]
        r_inv = modinv(sig.r, N)
        if r_inv is None:
            continue
        
        for c in range(-offset_bound, offset_bound + 1):
            k = (sig.z + c) % N
            d_candidate = ((sig.s * k - sig.z) * r_inv) % N
            if d_candidate > 0 and d_candidate * generator == Q:
                findings.append({
                    "sig_index": sig.index,
                    "pubkey": sig.pubkey,
                    "attack_type": "small_offset_from_hash",
                    "offset": c,
                    "recovered_nonce": k,
                    "recovered_private_key": d_candidate,
                    "note": f"small offset from hash found: k = z + {c}",
                    "verified": True,
                })
                break
    
    return findings


def check_small_offset_from_r(
    signatures: list[Signature],
    pubkey_points: dict = None,
    generator = None,
    offset_bound: int = 2**16,
) -> list[dict]:
    """
    Test k = r + c for small offsets c in [-offset_bound, offset_bound].
    
    For each signature with known pubkey:
    d = (s*(r+c) - z) * r^{-1} mod N
    
    Verify d*G == Q.
    """
    findings = []
    
    if not pubkey_points or not generator:
        return findings
    
    for sig in signatures:
        if not sig.pubkey or sig.pubkey not in pubkey_points:
            continue
        
        Q = pubkey_points[sig.pubkey]
        r_inv = modinv(sig.r, N)
        if r_inv is None:
            continue
        
        for c in range(-offset_bound, offset_bound + 1):
            k = (sig.r + c) % N
            d_candidate = ((sig.s * k - sig.z) * r_inv) % N
            if d_candidate > 0 and d_candidate * generator == Q:
                findings.append({
                    "sig_index": sig.index,
                    "pubkey": sig.pubkey,
                    "attack_type": "small_offset_from_r",
                    "offset": c,
                    "recovered_nonce": k,
                    "recovered_private_key": d_candidate,
                    "note": f"small offset from r found: k = r + {c}",
                    "verified": True,
                })
                break
    
    return findings
