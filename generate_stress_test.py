# SPDX-License-Identifier: GPL-3.0-or-later
"""
Stress-test signature generator for the ECDSA nonce bias analyzer.

Produces one RSZ.txt file containing MULTIPLE independent keys, each
exercising a different detection path at a different difficulty level -
including some deliberately marginal/hard cases and one genuinely clean
control key, so a "detected" or "not detected" result is actually
informative rather than guaranteed either way.

Every biased key here applies bias to k BEFORE deriving r and s, so all
signatures are internally consistent (s = k^-1(z + r*d) mod N genuinely
holds) - this is the mistake that made the original hand-rolled generator
produce undetectable, mathematically broken data.

Ground truth for every key is printed at the end and also written to
stress_test_answers.json so results can be checked programmatically
instead of by eye.
"""

import hashlib
import json
import random
from ecdsa import SECP256k1, SigningKey

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = SECP256k1.generator

rng = random.Random(20260704)  # fixed seed: reproducible stress test


def fresh_key():
    sk = SigningKey.generate(curve=SECP256k1, entropy=lambda n: rng.randbytes(n))
    d = sk.privkey.secret_multiplier
    pub = sk.get_verifying_key().to_string("compressed").hex()
    return d, pub


def make_signature(k, z, d):
    point = k * G
    r = point.x() % N
    k_inv = pow(k, -1, N)
    s = (k_inv * (z + r * d)) % N
    return r, s


def random_z():
    data = f"tx_{rng.randint(0, 10**12)}".encode()
    return int(hashlib.sha256(data).hexdigest(), 16)


sig_blocks = []
ground_truth = {}
global_idx = 1


def emit(pubkey, r, s, z, txid_tag):
    global global_idx
    txid = hashlib.sha256(f"txid_{txid_tag}_{global_idx}".encode()).hexdigest()
    sig_blocks.append(
        f"Signature #{global_idx}\n"
        f"  TXID: {txid}\n"
        f"  R = {r:064x}\n"
        f"  S = {s:064x}\n"
        f"  Z = {z:064x}\n"
        f"  PubKey: {pubkey}\n"
    )
    global_idx += 1


# ---------------------------------------------------------------------------
# KEY 1: exact nonce reuse (same key), 20 clean sigs + 1 reused pair
# Expected: Phase 1 catches this immediately, trivial difficulty by design -
# this path has no "hard mode", reuse is binary (either r collides or not).
# ---------------------------------------------------------------------------
d1, pub1 = fresh_key()
for _ in range(20):
    k = rng.randint(1, N - 1)
    z = random_z()
    r, s = make_signature(k, z, d1)
    emit(pub1, r, s, z, "k1_clean")

k_reused = rng.randint(1, N - 1)
z_a, z_b = random_z(), random_z()
r_a, s_a = make_signature(k_reused, z_a, d1)
r_b, s_b = make_signature(k_reused, z_b, d1)
emit(pub1, r_a, s_a, z_a, "k1_reuse_a")
emit(pub1, r_b, s_b, z_b, "k1_reuse_b")

ground_truth["key_1_exact_reuse"] = {
    "pubkey": pub1, "private_key": hex(d1),
    "expected": "Phase 1 nonce-reuse should recover this immediately",
}

# ---------------------------------------------------------------------------
# KEY 2: published constant nonce k=(n-1)/2, single occurrence mixed into
# otherwise clean signatures. Expected: Phase 1 constant-nonce check flags
# it; NOT independently exploitable unless a second use of the same
# constant appears (it doesn't here) - tests that the tool correctly
# reports "flagged but not solved" rather than over-claiming.
# ---------------------------------------------------------------------------
d2, pub2 = fresh_key()
K_CONST = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
for i in range(15):
    if i == 7:
        k = K_CONST
    else:
        k = rng.randint(1, N - 1)
    z = random_z()
    r, s = make_signature(k, z, d2)
    emit(pub2, r, s, z, "k2_const")

ground_truth["key_2_known_constant"] = {
    "pubkey": pub2, "private_key": hex(d2),
    "expected": "Phase 1 constant-nonce check should flag signature index 8 "
                "(the const), but NOT recover the key (only appears once)",
}

# ---------------------------------------------------------------------------
# KEY 3: EASY MSB bias, 64-bit (matches the real bitcore incident exactly).
# 20 signatures, all biased uniformly. Should be found trivially by fast mode.
# ---------------------------------------------------------------------------
d3, pub3 = fresh_key()
BIAS_3 = 64
for _ in range(20):
    k = rng.randint(0, (1 << (256 - BIAS_3)) - 1)
    z = random_z()
    r, s = make_signature(k, z, d3)
    emit(pub3, r, s, z, "k3_msb64")

ground_truth["key_3_easy_msb_64"] = {
    "pubkey": pub3, "private_key": hex(d3), "bias_bits": BIAS_3, "side": "msb",
    "expected": "fast mode should recover this (matches published bitcore incident width)",
}

# ---------------------------------------------------------------------------
# KEY 4: MODERATE LSB bias, 24-bit, 20 signatures (Minerva-style, low bits
# zero). Not in the published incident bit-width list, so fast mode's
# priority-only sweep may MISS it depending on which widths it tries -
# a genuinely useful test of whether thorough mode's wider sweep is needed.
# ---------------------------------------------------------------------------
d4, pub4 = fresh_key()
BIAS_4 = 24
for _ in range(20):
    k_high = rng.randint(0, (1 << (256 - BIAS_4)) - 1)
    k = k_high << BIAS_4  # low BIAS_4 bits = 0
    z = random_z()
    r, s = make_signature(k, z, d4)
    emit(pub4, r, s, z, "k4_lsb24")

ground_truth["key_4_moderate_lsb_24"] = {
    "pubkey": pub4, "private_key": hex(d4), "bias_bits": BIAS_4, "side": "lsb",
    "expected": "may need thorough mode's wider bit-width sweep to catch this - "
                "24 bits is not in the published-incident priority list",
}

# ---------------------------------------------------------------------------
# KEY 5: HARD/marginal MSB bias, 12-bit, only 20 signatures. Per the lattice
# dimension math, 12-bit bias realistically needs on the order of ~24+
# signatures for LLL alone to reliably succeed - this key is deliberately
# UNDER-provisioned. This is a genuine stress case: it is plausible and
# acceptable for the tool to correctly report "no bias found" here. If it
# finds it, great; if not, that's an honest negative, not a bug.
# ---------------------------------------------------------------------------
d5, pub5 = fresh_key()
BIAS_5 = 12
for _ in range(20):
    k = rng.randint(0, (1 << (256 - BIAS_5)) - 1)
    z = random_z()
    r, s = make_signature(k, z, d5)
    emit(pub5, r, s, z, "k5_hard_msb12")

ground_truth["key_5_hard_msb_12_underprovisioned"] = {
    "pubkey": pub5, "private_key": hex(d5), "bias_bits": BIAS_5, "side": "msb",
    "expected": "MARGINAL/HARD: only 20 sigs for a 12-bit bias is likely "
                "insufficient for LLL. A 'no bias found' result here is an "
                "honest negative, not necessarily a tool failure. Try BKZ "
                "(thorough mode) or add more signatures of this key to confirm.",
}

# ---------------------------------------------------------------------------
# KEY 6: MIXED bias - only 60% of this key's signatures are biased (32-bit
# MSB), the rest are clean. Fast mode's all-at-once lattice should FAIL
# (contaminated by clean sigs); thorough mode's subset sampling should
# succeed since biased sigs are a majority.
# ---------------------------------------------------------------------------
d6, pub6 = fresh_key()
BIAS_6 = 32
for i in range(25):
    if i < 15:  # 15 biased, 10 clean -> 60% biased, majority regime
        k = rng.randint(0, (1 << (256 - BIAS_6)) - 1)
    else:
        k = rng.randint(1, N - 1)
    z = random_z()
    r, s = make_signature(k, z, d6)
    emit(pub6, r, s, z, "k6_mixed32")

ground_truth["key_6_mixed_partial_bias"] = {
    "pubkey": pub6, "private_key": hex(d6), "bias_bits": BIAS_6, "side": "msb",
    "biased_fraction": "15/25 (60%)",
    "expected": "fast mode should FAIL (all-at-once lattice contaminated by "
                "10 clean sigs). thorough mode MAY OR MAY NOT succeed with "
                "default settings (max_subset_attempts=25): random subset "
                "size is drawn uniformly from 6 to 24, and the odds of an "
                "all-biased draw only get good near the small end (~1/35 at "
                "size 6, but far worse at size 12+) - with only 25 attempts "
                "spread across that whole range, success is a coin-flip at "
                "best. To reliably catch this case, lower max_subset_size "
                "or raise max_subset_attempts substantially (see README).",
}

# ---------------------------------------------------------------------------
# KEY 7: genuinely CLEAN control key, no bias, no reuse, nothing. This is
# the most important key in the file: if the tool finds ANYTHING here,
# that's a false positive and a real bug worth reporting.
# ---------------------------------------------------------------------------
d7, pub7 = fresh_key()
for _ in range(25):
    k = rng.randint(1, N - 1)
    z = random_z()
    r, s = make_signature(k, z, d7)
    emit(pub7, r, s, z, "k7_clean_control")

ground_truth["key_7_clean_control"] = {
    "pubkey": pub7, "private_key": hex(d7),
    "expected": "MUST show 'no exploitable bias found'. Any finding here is "
                "a false positive - report it as a bug.",
}

# ---------------------------------------------------------------------------
# KEY 8: cross-key nonce reuse - same k used once in key 8 and once in a
# throwaway second identity. Expected: Phase 1 flags the r-collision as
# cross-key (forensic), correctly does NOT claim direct key recovery from
# this alone (that would require also knowing the other side's key).
# ---------------------------------------------------------------------------
d8, pub8 = fresh_key()
d8b, pub8b = fresh_key()  # a second, unrelated key sharing one nonce with key 8
k_shared = rng.randint(1, N - 1)

for _ in range(15):
    k = rng.randint(1, N - 1)
    z = random_z()
    r, s = make_signature(k, z, d8)
    emit(pub8, r, s, z, "k8_clean")

z8 = random_z()
r8, s8 = make_signature(k_shared, z8, d8)
emit(pub8, r8, s8, z8, "k8_shared")

z8b = random_z()
r8b, s8b = make_signature(k_shared, z8b, d8b)
emit(pub8b, r8b, s8b, z8b, "k8b_shared")

ground_truth["key_8_cross_key_reuse"] = {
    "pubkey_a": pub8, "private_key_a": hex(d8),
    "pubkey_b": pub8b, "private_key_b": hex(d8b),
    "expected": "Phase 1 should flag an r-collision between these two "
                "DIFFERENT pubkeys, labeled cross-key/forensic, NOT solved "
                "(correctly - solving requires independently knowing one side).",
}

# ---------------------------------------------------------------------------
rng.shuffle(sig_blocks)  # don't hand the analyzer a suspiciously ordered file

with open("stress_test_RSZ.txt", "w") as f:
    f.write("=" * 70 + "\n")
    f.write("STRESS TEST - SYNTHETIC SIGNATURES, MULTIPLE KEYS, MIXED DIFFICULTY\n")
    f.write(f"Total signatures: {global_idx - 1}\n")
    f.write("=" * 70 + "\n\n")
    f.write("\n".join(sig_blocks))

with open("stress_test_answers.json", "w") as f:
    json.dump(ground_truth, f, indent=2)

print(f"wrote stress_test_RSZ.txt: {global_idx - 1} signatures across 8 keys (9 identities)")
print("wrote stress_test_answers.json: ground truth for scoring your results")
print()
print("Summary of what's in this file:")
for name, info in ground_truth.items():
    print(f"  {name}")
    print(f"    -> {info['expected']}")
