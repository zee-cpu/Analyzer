# SPDX-License-Identifier: GPL-3.0-or-later
"""
Metadata-informed subset selection for the HNP lattice sweep.

Real nonce-bias incidents are almost always TIME-BOUNDED: a specific
buggy software version gets deployed, produces biased signatures for as
long as it's in use, then gets patched or replaced. Breitner & Heninger
2019 document exactly this pattern (e.g. the bitcore bug: "July 12 2014 -
Aug 11 2014"). This means signatures close together in time are far more
likely to share a root cause than a uniformly random subset would be -
so clustering by timestamp proximity, then testing those clusters BEFORE
falling back to blind random sampling, should convert real incidents into
successes far faster than random subset sampling alone.

This module only PROPOSES candidate subsets - it doesn't run the lattice
attack itself. Callers (sweep_bias_hypotheses) try these candidates first,
then fall back to random sampling if none succeed.
"""

from dataclasses import dataclass
from curve import Signature


@dataclass
class SubsetCandidate:
    signatures: list  # list[Signature]
    method: str        # how this candidate was constructed, for reporting
    description: str


def cluster_by_timestamp(
    sigs: list,
    max_gap_seconds: int = 3600,
    min_cluster_size: int = 4,
) -> list[SubsetCandidate]:
    """
    Group signatures into clusters where consecutive timestamps (sorted)
    are no more than max_gap_seconds apart. This finds contiguous time
    windows rather than a single global time range, so it can surface
    multiple distinct incidents (e.g. two separate deployments of buggy
    software) within one signature set.

    Signatures with no timestamp are excluded - there's no time-proximity
    signal to cluster them on.
    """
    timestamped = [s for s in sigs if s.timestamp is not None]
    if len(timestamped) < min_cluster_size:
        return []

    timestamped.sort(key=lambda s: s.timestamp)

    clusters = []
    current = [timestamped[0]]
    for prev, cur in zip(timestamped, timestamped[1:]):
        if cur.timestamp - prev.timestamp <= max_gap_seconds:
            current.append(cur)
        else:
            if len(current) >= min_cluster_size:
                clusters.append(current)
            current = [cur]
    if len(current) >= min_cluster_size:
        clusters.append(current)

    candidates = []
    for cluster in clusters:
        span = cluster[-1].timestamp - cluster[0].timestamp
        candidates.append(SubsetCandidate(
            signatures=cluster,
            method="timestamp_cluster",
            description=f"{len(cluster)} sigs within a {span}s window "
                        f"(gap threshold {max_gap_seconds}s)",
        ))

    # largest clusters first - more signatures generally means a better
    # shot at the lattice attack succeeding, all else equal
    candidates.sort(key=lambda c: len(c.signatures), reverse=True)
    return candidates


def cluster_by_timestamp_multiscale(
    sigs: list,
    min_cluster_size: int = 4,
    max_candidates: int = 12,
) -> list[SubsetCandidate]:
    """
    Run cluster_by_timestamp at several gap thresholds spanning minutes to
    months, since the right threshold depends on how long the underlying
    incident lasted and how densely the signatures sample it - neither of
    which is known in advance. A single fixed threshold is fragile: tested
    directly during development, a 3-day threshold completely fragmented a
    genuine 30-day-wide incident into three disconnected pieces (small
    random gaps between individual signatures exceeded the threshold even
    though the whole window shared one root cause). Sweeping thresholds
    avoids depending on a lucky guess.
    """
    thresholds = [
        60, 3600, 6 * 3600, 86400,          # minutes to a day
        3 * 86400, 7 * 86400, 30 * 86400,   # days to a month
        90 * 86400, 180 * 86400,            # a quarter, half a year
    ]

    all_candidates = []
    seen_sig_sets = []
    total_sig_count = len(sigs)
    for threshold in thresholds:
        for cand in cluster_by_timestamp(sigs, max_gap_seconds=threshold, min_cluster_size=min_cluster_size):
            sig_set = frozenset(id(s) for s in cand.signatures)
            if sig_set in seen_sig_sets:
                continue  # identical cluster already found at a different threshold
            seen_sig_sets.append(sig_set)
            # skip a cluster that's actually the entire dataset - it provides
            # zero isolation value (equivalent to not clustering at all) and
            # would otherwise crowd out genuinely useful tighter clusters
            if len(cand.signatures) >= total_sig_count:
                continue
            all_candidates.append(cand)

    # Rank by DENSITY (signatures per unit time), not raw size. A tight
    # cluster of 16 signatures in a 7-day window is a far better candidate
    # than a loose cluster of 25 signatures spread over 30 days, even
    # though the latter is "bigger" - density is what correlates with
    # "these likely share one root cause" in the first place. Verified
    # during development: on a 15-true/25-contaminant synthetic incident,
    # raw-size ranking picked a fully contaminated 40-signature cluster
    # first, while density ranking correctly surfaces a 16-signature,
    # 1-contaminant cluster instead.
    def density_score(c):
        span = max(_cluster_span(c), 1)  # avoid div by zero for near-simultaneous sigs
        return len(c.signatures) / span

    all_candidates.sort(key=density_score, reverse=True)
    return all_candidates[:max_candidates]


def _cluster_span(candidate: "SubsetCandidate") -> int:
    ts = [s.timestamp for s in candidate.signatures if s.timestamp is not None]
    return max(ts) - min(ts) if ts else 0


def cluster_by_txid_prefix(
    sigs: list,
    prefix_len: int = 4,
    min_cluster_size: int = 4,
) -> list[SubsetCandidate]:
    """
    Weak secondary signal: group signatures whose txid shares a prefix.
    This is NOT a strong clustering signal on its own (txids are
    essentially random hashes, a shared prefix by chance is unlikely but
    not meaningful even when it happens) - it exists mainly to catch
    cases where txids were assigned in a batch/sequential process that
    correlates with signing-software version, which does happen in some
    real extraction/export tooling. Treat results from this as a weaker
    prior than timestamp clustering.
    """
    with_txid = [s for s in sigs if s.txid]
    if len(with_txid) < min_cluster_size:
        return []

    groups = {}
    for s in with_txid:
        key = s.txid[:prefix_len]
        groups.setdefault(key, []).append(s)

    candidates = []
    for prefix, group in groups.items():
        if len(group) >= min_cluster_size:
            candidates.append(SubsetCandidate(
                signatures=group,
                method="txid_prefix_cluster",
                description=f"{len(group)} sigs sharing txid prefix '{prefix}' "
                            f"(weak signal - treat as low-confidence)",
            ))

    candidates.sort(key=lambda c: len(c.signatures), reverse=True)
    return candidates


def propose_subset_candidates(
    sigs: list,
    min_cluster_size: int = 4,
    max_candidates: int = 10,
) -> list[SubsetCandidate]:
    """
    Try every available metadata-based clustering strategy and return a
    ranked list of candidate subsets to try before falling back to blind
    random sampling. Returns an empty list if no usable metadata is
    present (e.g. no timestamps and no txids) - callers should treat that
    as "no informed candidates available", not an error.
    """
    candidates = []
    candidates.extend(cluster_by_timestamp_multiscale(sigs, min_cluster_size=min_cluster_size))
    candidates.extend(cluster_by_txid_prefix(sigs, min_cluster_size=min_cluster_size))

    # de-duplicate: if a txid-prefix cluster is a subset of an already-
    # proposed timestamp cluster, it adds no new information - skip it
    seen_sig_sets = []
    deduped = []
    for c in candidates:
        sig_set = frozenset(id(s) for s in c.signatures)
        if any(sig_set <= seen for seen in seen_sig_sets):
            continue
        seen_sig_sets.append(sig_set)
        deduped.append(c)

    return deduped[:max_candidates]
