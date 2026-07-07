#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
ECDSA Nonce Bias Analyzer & Solver
Unified detection + exploitation pipeline with CLI support.

Pipeline:
  1. Exact checks   - nonce reuse (same-key + cross-key), known published
                       constant-nonce fingerprint. Zero false positives,
                       zero statistics, mathematical certainty.
  2. HNP lattice    - MSB/LSB bias hypothesis sweep via LLL/BKZ (fpylll).
                       Detection and recovery are the same step: a verified
                       candidate IS the finding.
  3. Poly recurrence - Polynomial nonce recurrence patterns.
"""

import sys
import os
import time
import json
import argparse
import logging
from collections import defaultdict
from pathlib import Path
from typing import Optional, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.align import Align
from rich.rule import Rule

from curve import N, Signature, modinv, validate_signature
from parser import parse_rsz_file, group_by_pubkey
from exact_checks import (
    find_nonce_reuse,
    check_known_constant_nonce,
    check_sequential_nonce_candidates,
    check_linear_relation_candidates,
    check_catastrophic_nonce_derived_from_signature_data,
    brute_force_small_constant_nonce,
    check_small_offset_from_hash,
    check_small_offset_from_r,
    recommended_bias_bit_widths,
    KNOWN_INCIDENT_BIT_LENGTHS,
)
from hnp_lattice import sweep_bias_hypotheses, BiasHypothesis, compute_min_detectable_bias_bits
from poly_recurrence import PolyRecurrenceHypothesis, run_poly_recurrence_attack

console = Console()

# Default args for when phase functions are called without CLI args
class DefaultArgs:
    """Default args for when phase functions are called without CLI args."""
    format = "json"
    small_nonce_bound = 0
    offset_bound = 0
    lattice_mode = "fast"
    bkz_block_size = 20
    enumerate_radius = 0
    poly_degrees = [1, 2, 3]
    poly_max_windows = 10

_default_args = DefaultArgs()

logger = logging.getLogger(__name__)

# Color constants
SCAN_GREEN = "bright_green"
SCAN_AMBER = "yellow"
SCAN_RED = "bright_red"


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="ECDSA Nonce Bias Analyzer - detect and exploit weak nonces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py signatures.txt --fast --yes --format json -o results.json
  python main.py signatures.txt --thorough --yes
  python main.py signatures.txt --poly-recurrence --yes
  python main.py signatures.txt --known-keys known.json --yes
        """
    )
    
    parser.add_argument("filepath", nargs="?", help="Path to signature file (R,S,Z format)")
    
    # Mode flags
    parser.add_argument("--fast", action="store_true",
                        help="Fast lattice sweep (priority bit-widths only, no BKZ)")
    parser.add_argument("--thorough", action="store_true",
                        help="Thorough sweep (full widths + BKZ + subset sampling)")
    parser.add_argument("--poly-recurrence", action="store_true",
                        help="Run polynomial recurrence phase")
    parser.add_argument("--no-poly", action="store_true",
                        help="Skip polynomial recurrence phase")
    
    # Output options
    parser.add_argument("--format", choices=["rich", "json"], default="rich",
                        help="Output format (default: rich)")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Auto-confirm all phases; non-interactive mode")
    parser.add_argument("--output", "-o", type=str, metavar="FILE",
                        help="Write JSON output to file")
    
    # Known keys for cross-key exploitation
    parser.add_argument("--known-keys", type=str, metavar="FILE",
                        help='JSON file: [{"pubkey": "hex", "private_key": "hex"}, ...]')
    
    # Tuning parameters
    parser.add_argument("--small-nonce-bound", type=int, default=2**24, metavar="B",
                        help="Brute-force bound for small constant nonces (default: 2^24, 0=disable)")
    parser.add_argument("--offset-bound", type=int, default=2**16, metavar="C",
                        help="Bound for k = z + c offset search (default: 2^16)")
    parser.add_argument("--bkz-block-size", type=int, default=20, metavar="K",
                        help="BKZ block size (default: 20, min 10, max 30)")
    parser.add_argument("--enumerate-radius", type=int, default=2, metavar="R",
                        help="Lattice enumeration radius (default: 2)")
    parser.add_argument("--modular-bias-limit", type=int, default=2**16, metavar="M",
                        help="Max modulus for modular bias sweep (default: 2^16, 0=disable)")
    parser.add_argument("--max-workers", type=int, default=None, metavar="N",
                        help="ProcessPoolExecutor max workers (default: os.cpu_count())")
    
    return parser.parse_args()


def _generator():
    """Get the secp256k1 generator point."""
    from ecdsa import SECP256k1
    return SECP256k1.generator


def _resolve_pubkey_point(pubkey_hex, sigs):
    """
    Attempt to resolve a pubkey hex string to an EC point.
    Returns None if not possible.
    """
    if pubkey_hex is None:
        return None
    try:
        from ecdsa import SECP256k1, VerifyingKey
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        if len(pubkey_bytes) == 33:
            vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
        elif len(pubkey_bytes) == 65:
            vk = VerifyingKey.from_string(pubkey_bytes[1:], curve=SECP256k1)
        else:
            return None
        return vk.pubkey.point
    except Exception:
        return None


def load_known_keys(filepath: str) -> dict:
    """Load known keys from JSON file."""
    if not filepath:
        return {}
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return {item['pubkey']: int(item['private_key'], 16) for item in data}
    except Exception as e:
        logger.warning(f"Failed to load known keys: {e}")
        return {}


def run_exact_phase(groups, args=None, known_keys=None) -> dict:
    """
    Run exact checks phase.
    Returns dict with keys: reuse_findings, const_findings, sequential_findings, 
    linear_relation_findings, catastrophic_findings, summary_rows.
    """
    if args is None:
        args = _default_args
    
    if args.format == "rich":
        console.rule("[bold]PHASE 1 // EXACT CHECKS[/bold]", style="grey35")
        console.print("[grey58]nonce reuse · known constant nonces · catastrophic derivation bugs[/grey58]")
        console.print()

    summary_rows = []
    reuse_findings = []
    const_findings = []
    sequential_findings = []
    linear_relation_findings = []
    catastrophic_findings = []
    
    if getattr(args, 'skip_phase1', False):
        return {"reuse_findings": [], "const_findings": [], "sequential_findings": [], "linear_relation_findings": [], "catastrophic_findings": [], "summary_rows": []}

    for pubkey, sigs in groups.items():
        pk_label = (pubkey[:16] + "...") if pubkey else "[UNKNOWN / UNGROUPED]"
        
        if args.format == "rich":
            console.print(f"[bold cyan]key {pk_label}[/bold cyan]  [grey58]({len(sigs)} signatures)[/grey58]")
        
        key_findings = []
        
        # 1. Nonce reuse detection
        reuse = find_nonce_reuse(sigs)
        if reuse:
            # Mark as immediately exploitable if private key recovered
            reuse_findings.extend(reuse)
            key_findings.extend(reuse)
            if args.format == "rich":
                for f in reuse:
                    console.print(Panel(
                        f"[bold white]type:[/bold white] nonce reuse\n"
                        f"[bold white]signatures:[/bold white] {f.get('sig1_index', '?')}, {f.get('sig2_index', '?')}\n"
                        f"[bright_red]recovered private key:[/bright_red] [bold]{hex(f['private_key'])}[/bold]",
                        title="[bold bright_red]🔴 KEY RECOVERED VIA NONCE REUSE[/bold bright_red]",
                        border_style="bright_red",
                        box=box.HEAVY,
                    ))
        
        # 2. Known constant nonce check
        known = check_known_constant_nonce(sigs)
        if known:
            const_findings.extend(known)
            key_findings.extend(known)
        
        # 3. Catastrophic nonce checks (if pubkey available)
        pubkey_point = _resolve_pubkey_point(pubkey, sigs)
        if pubkey_point is not None:
            generator = _generator()
            
            # k = z, k = r, k = d checks
            catastrophic = check_catastrophic_nonce_derived_from_signature_data(
                sigs, {pubkey: pubkey_point}, generator
            )
            if catastrophic:
                catastrophic_findings.extend(catastrophic)
                key_findings.extend(catastrophic)
                if args.format == "rich":
                    for f in catastrophic:
                        console.print(Panel(
                            f"[bold white]type:[/bold white] {f.get('type', 'catastrophic')}\n"
                            f"[bold white]signature:[/bold white] {f.get('sig_index', '?')}\n"
                            f"[bright_red]recovered private key:[/bright_red] [bold]{hex(f['private_key'])}[/bold]\n"
                            f"[grey58]{f.get('note', '')}[/grey58]",
                            title="[bold bright_red]🔴 KEY RECOVERED VIA CATASTROPHIC NONCE[/bold bright_red]",
                            border_style="bright_red",
                            box=box.HEAVY,
                        ))
            
            # Small constant nonce brute force
            if getattr(args, 'small_nonce_bound', 0) > 0:
                small_nonce = brute_force_small_constant_nonce(
                    sigs, {pubkey: pubkey_point}, generator, bound=args.small_nonce_bound
                )
                if small_nonce:
                    const_findings.extend(small_nonce)
                    key_findings.extend(small_nonce)
                    if args.format == "rich":
                        for f in small_nonce:
                            console.print(Panel(
                                f"[bold white]type:[/bold white] small constant nonce\n"
                                f"[bold white]nonce k:[/bold white] {f.get('nonce', '?')}\n"
                                f"[bright_red]recovered private key:[/bright_red] [bold]{hex(f['private_key'])}[/bold]",
                                title="[bold bright_red]🔴 KEY RECOVERED VIA SMALL NONCE[/bold bright_red]",
                                border_style="bright_red",
                                box=box.HEAVY,
                            ))
            
            # Offset from hash check
            if getattr(args, 'offset_bound', 0) > 0:
                offset_hash = check_small_offset_from_hash(
                    sigs, {pubkey: pubkey_point}, generator, offset_bound=args.offset_bound
                )
                if offset_hash:
                    const_findings.extend(offset_hash)
                    key_findings.extend(offset_hash)
                
                offset_r = check_small_offset_from_r(
                    sigs, {pubkey: pubkey_point}, generator, offset_bound=args.offset_bound
                )
                if offset_r:
                    const_findings.extend(offset_r)
                    key_findings.extend(offset_r)
        
        # Update summary
        if key_findings:
            summary_rows.append((pk_label, len(sigs), "COMPROMISED", f"{len(key_findings)} findings"))
        else:
            if args.format == "rich":
                console.print(f"  [{SCAN_GREEN}]✓ no exact vulnerabilities found[/{SCAN_GREEN}]")
            summary_rows.append((pk_label, len(sigs), "clean*", "exact checks passed"))
        
        if args.format == "rich":
            console.print()
    
    return {
        "reuse_findings": reuse_findings,
        "const_findings": const_findings,
        "sequential_findings": sequential_findings,
        "linear_relation_findings": linear_relation_findings,
        "catastrophic_findings": catastrophic_findings,
        "summary_rows": summary_rows,
    }

def run_lattice_phase(groups, args=None, mode=None) -> tuple[list, list]:
    """
    Run HNP lattice sweep phase.
    Returns (summary_rows, findings).
    """
    if args is None:
        args = _default_args
    if mode is None:
        mode = "thorough" if getattr(args, "thorough", False) else "fast"
    
    if args.format == "rich":
        console.rule("[bold]PHASE 2 // HNP LATTICE SWEEP[/bold]", style="grey35")
        console.print(f"[grey58]mode={mode} · bias hypotheses: MSB/LSB × published incident bit-widths + geometric sweep[/grey58]")
        console.print()
    
    priority_widths = recommended_bias_bit_widths()
    full_widths = sorted(set(priority_widths) | {4, 8, 16, 32, 40, 64, 96, 128, 160, 192})
    
    summary_rows = []
    all_findings = []
    
    if getattr(args, 'skip_phase1', False):
        return {"reuse_findings": [], "const_findings": [], "sequential_findings": [], "linear_relation_findings": [], "catastrophic_findings": [], "summary_rows": []}

    for pubkey, sigs in groups.items():
        pk_label = (pubkey[:16] + "...") if pubkey else "[UNKNOWN / UNGROUPED]"
        
        if pubkey is None:
            if args.format == "rich":
                console.print("[grey50]skipping lattice sweep for ungrouped signatures (no pubkey to verify against)[/grey50]")
                console.print()
            continue
        
        if len(sigs) < 3:
            summary_rows.append((pk_label, len(sigs), "skipped", "fewer than 3 signatures"))
            continue
        
        if args.format == "rich":
            console.print(f"[bold cyan]key {pk_label}[/bold cyan]  [grey58]({len(sigs)} signatures)[/grey58]")
        
        pubkey_point = _resolve_pubkey_point(pubkey, sigs)
        if pubkey_point is None:
            if args.format == "rich":
                console.print(f"  [grey50]no recoverable EC point for this pubkey — cannot verify lattice candidates, skipping[/grey50]")
                console.print()
            summary_rows.append((pk_label, len(sigs), "skipped", "pubkey not resolvable to EC point"))
            continue
        
        widths = priority_widths if mode == "fast" else full_widths
        
        hit = None
        attempts_log = []
        
        if args.format == "rich":
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[grey70]{task.description}"),
                BarColumn(bar_width=30, style="grey35", complete_style="bright_cyan"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("sweeping bias hypotheses", total=None)
                
                def _on_attempt(hyp_label, subset_info):
                    progress.update(task, description=f"testing {hyp_label} [{subset_info}]")
                
                attempts_log = sweep_bias_hypotheses(
                    sigs, pubkey_point, _generator(),
                    bit_widths=widths,
                    escalate_to_bkz=(mode == "thorough"),
                    mode=mode,
                    rng_seed=1,
                    on_attempt=_on_attempt,
                    bkz_block_size=args.bkz_block_size,
                )
                hit = next((r for r in attempts_log if r.verified), None)
        else:
            # JSON mode - no progress display
            attempts_log = sweep_bias_hypotheses(
                sigs, pubkey_point, _generator(),
                bit_widths=widths,
                escalate_to_bkz=(mode == "thorough"),
                mode=mode,
                rng_seed=1,
                bkz_block_size=args.bkz_block_size,
            )
            hit = next((r for r in attempts_log if r.verified), None)
        
        if hit:
            finding = {
                "type": "lattice_bias",
                "pubkey": pubkey,
                "hypothesis": hit.hypothesis.label(),
                "private_key": hit.candidate_d,
                "lattice_dimension": hit.lattice_dimension,
                "used_bkz": hit.used_bkz,
                "note": hit.note,
            }
            all_findings.append(finding)
            
            if args.format == "rich":
                console.print(Panel(
                    f"[bold white]hypothesis:[/bold white] {hit.hypothesis.label()}\n"
                    f"[bold white]lattice dimension:[/bold white] {hit.lattice_dimension}\n"
                    f"[bold white]method:[/bold white] {'BKZ' if hit.used_bkz else 'LLL'}\n"
                    f"[bright_red]recovered private key:[/bright_red] [bold]{hex(hit.candidate_d)}[/bold]\n"
                    f"[grey58]{hit.note}[/grey58]",
                    title="[bold bright_red]🔴 KEY RECOVERED VIA LATTICE ATTACK[/bold bright_red]",
                    border_style="bright_red",
                    box=box.HEAVY,
                ))
            summary_rows.append((pk_label, len(sigs), "COMPROMISED", hit.hypothesis.label()))
        else:
            skipped = [r for r in attempts_log if r.lattice_dimension == 0]
            genuinely_tried = [r for r in attempts_log if r.lattice_dimension > 0]
            
            if args.format == "rich":
                console.print(f"  [{SCAN_GREEN}]✓ no exploitable bias found "
                              f"({len(genuinely_tried)} hypotheses actually tested, "
                              f"{len(skipped)} skipped as mathematically infeasible "
                              f"for this signature count)[/{SCAN_GREEN}]")
                
                floor_bits = compute_min_detectable_bias_bits(len(sigs))
                
                if skipped and not genuinely_tried:
                    console.print(
                        f"  [{SCAN_AMBER}]⚠ every hypothesis for this key was skipped - "
                        f"{len(sigs)} signatures may simply be too few to test any bias "
                        f"strength meaningfully. This is NOT the same as a clean result; "
                        f"collect more signatures for this key before trusting a 'no bias "
                        f"found' conclusion here.[/{SCAN_AMBER}]"
                    )
                elif floor_bits is not None:
                    console.print(
                        f"  [grey58]with {len(sigs)} signatures, this key's data could only "
                        f"rule out bias >= {floor_bits} bits. A weaker/subtler bias than "
                        f"that would NOT have been detected even if present - this is a "
                        f"limitation of sample size, not evidence the key is clean beyond "
                        f"this floor.[/grey58]"
                    )
            
            summary_rows.append((
                pk_label, len(sigs),
                "clean*" if genuinely_tried else "inconclusive*",
                f"{len(genuinely_tried)} tested, {len(skipped)} skipped"
                + (f", floor={compute_min_detectable_bias_bits(len(sigs))} bits" if compute_min_detectable_bias_bits(len(sigs)) else ""),
            ))
        
        if args.format == "rich":
            console.print()
    
    return summary_rows, all_findings


def run_poly_recurrence_phase(groups, args=None) -> tuple[list, list]:
    """
    Run polynomial nonce recurrence phase.
    Returns (summary_rows, findings).
    """
    if args is None:
        args = _default_args

    if args.format == "rich":
        console.rule("[bold]PHASE 3 // POLYNOMIAL NONCE RECURRENCE[/bold]", style="grey35")
        console.print("[grey58]unknown-coefficient recurrences (k_next = f(k_prev) for unknown low-degree f) "
                      "· symbolic elimination + polynomial root-finding, not a lattice attack[/grey58]")
        console.print()
    
    summary_rows = []
    all_findings = []
    
    if getattr(args, 'skip_phase1', False):
        return {"reuse_findings": [], "const_findings": [], "sequential_findings": [], "linear_relation_findings": [], "catastrophic_findings": [], "summary_rows": []}

    for pubkey, sigs in groups.items():
        pk_label = (pubkey[:16] + "...") if pubkey else "[UNKNOWN / UNGROUPED]"
        
        if pubkey is None:
            if args.format == "rich":
                console.print("[grey50]skipping poly-recurrence phase for ungrouped signatures (no pubkey to verify against)[/grey50]")
                console.print()
            continue
        
        if len(sigs) < 4:  # degree=1 minimum
            summary_rows.append((pk_label, len(sigs), "skipped", "fewer than 4 signatures"))
            continue
        
        pubkey_point = _resolve_pubkey_point(pubkey, sigs)
        if pubkey_point is None:
            summary_rows.append((pk_label, len(sigs), "skipped", "pubkey not resolvable to EC point"))
            continue
        
        # Signatures must be tried in a plausible GENERATION order
        ordered_sigs = sigs
        if all(s.timestamp is not None for s in sigs):
            ordered_sigs = sorted(sigs, key=lambda s: s.timestamp)
        
        if args.format == "rich":
            console.print(f"[bold cyan]key {pk_label}[/bold cyan]  [grey58]({len(sigs)} signatures)[/grey58]")
        
        hit = None
        attempts_log = []
        
        if args.format == "rich":
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[grey70]{task.description}"),
                BarColumn(bar_width=30, style="grey35", complete_style="bright_cyan"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("testing recurrence degrees", total=None)
                
                def _on_progress(degree, window_idx):
                    progress.update(task, description=f"degree-{degree} recurrence, window {window_idx}")
                
                for degree in [1, 2, 3]:
                    hyp = PolyRecurrenceHypothesis(degree=degree)
                    window_size = hyp.required_signatures()
                    if len(ordered_sigs) < window_size:
                        continue
                    num_windows = min(len(ordered_sigs) - window_size + 1, 20)
                    for start in range(num_windows):
                        _on_progress(degree, start)
                        window = ordered_sigs[start:start + window_size]
                        result = run_poly_recurrence_attack(window, hyp, pubkey_point, _generator())
                        attempts_log.append(result)
                        if result.verified:
                            hit = result
                            break
                    if hit:
                        break
        else:
            # JSON mode - no progress display
            for degree in [1, 2, 3]:
                hyp = PolyRecurrenceHypothesis(degree=degree)
                window_size = hyp.required_signatures()
                if len(ordered_sigs) < window_size:
                    continue
                num_windows = min(len(ordered_sigs) - window_size + 1, 20)
                for start in range(num_windows):
                    window = ordered_sigs[start:start + window_size]
                    result = run_poly_recurrence_attack(window, hyp, pubkey_point, _generator())
                    attempts_log.append(result)
                    if result.verified:
                        hit = result
                        break
                if hit:
                    break
        
        if hit:
            finding = {
                "type": "poly_recurrence",
                "pubkey": pubkey,
                "degree": hit.hypothesis.degree,
                "private_key": hit.candidate_d,
                "note": hit.note,
            }
            all_findings.append(finding)
            
            if args.format == "rich":
                console.print(Panel(
                    f"[bold white]recurrence degree:[/bold white] {hit.hypothesis.degree}\n"
                    f"[bold white]polynomial degree:[/bold white] {hit.polynomial_degree}\n"
                    f"[bright_red]recovered private key:[/bright_red] [bold]{hex(hit.candidate_d)}[/bold]\n"
                    f"[grey58]{hit.note}[/grey58]",
                    title="[bold bright_red]🔴 KEY RECOVERED VIA POLYNOMIAL RECURRENCE[/bold bright_red]",
                    border_style="bright_red",
                    box=box.HEAVY,
                ))
            summary_rows.append((pk_label, len(sigs), "COMPROMISED", f"degree-{hit.hypothesis.degree}"))
        else:
            if args.format == "rich":
                console.print(f"  [{SCAN_GREEN}]✓ no recurrence relation found under {len(attempts_log)} tested windows[/{SCAN_GREEN}]")
                console.print(
                    f"  [grey58]this technique succeeds only ~33-40% per window even when a real "
                    f"recurrence exists (see poly_recurrence.py docstring) - a clean result here "
                    f"is weaker evidence than a clean HNP lattice sweep, not proof of no relation.[/grey58]"
                )
            summary_rows.append((pk_label, len(sigs), "inconclusive*", f"{len(attempts_log)} windows tried"))
        
        if args.format == "rich":
            console.print()
    
    return summary_rows, all_findings


def print_summary_table(exact_summary, lattice_summary, poly_summary, args):
    """Print summary table in Rich format."""
    if args.format != "rich":
        return
    
    console.rule("[bold]SUMMARY[/bold]", style="grey35")
    
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Key", style="cyan")
    table.add_column("Sigs", justify="right")
    table.add_column("Exact", justify="center")
    table.add_column("Lattice", justify="center")
    table.add_column("Poly", justify="center")
    
    # Combine summaries by key
    all_keys = set()
    exact_dict = {row[0]: row for row in exact_summary}
    lattice_dict = {row[0]: row for row in lattice_summary}
    poly_dict = {row[0]: row for row in poly_summary}
    
    all_keys.update(exact_dict.keys())
    all_keys.update(lattice_dict.keys())
    all_keys.update(poly_dict.keys())
    
    for key in sorted(all_keys):
        exact_row = exact_dict.get(key, (key, 0, "-", "-"))
        lattice_row = lattice_dict.get(key, (key, 0, "-", "-"))
        poly_row = poly_dict.get(key, (key, 0, "-", "-"))
        
        num_sigs = max(exact_row[1], lattice_row[1], poly_row[1])
        
        def style_status(status):
            if "COMPROMISED" in status:
                return f"[bright_red]{status}[/bright_red]"
            elif "clean" in status:
                return f"[bright_green]{status}[/bright_green]"
            elif "skipped" in status:
                return f"[grey50]{status}[/grey50]"
            else:
                return f"[yellow]{status}[/yellow]"
        
        table.add_row(
            key,
            str(num_sigs),
            style_status(exact_row[2]),
            style_status(lattice_row[2]),
            style_status(poly_row[2]),
        )
    
    console.print(table)
    console.print()


def output_json(results: dict, args):
    """Output results as JSON."""
    output = json.dumps(results, indent=2, default=str)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        if args.format == "rich":
            console.print(f"[grey58]JSON output written to {args.output}[/grey58]")
    
    if args.format == "json":
        print(output)


def interactive_mode(groups, args):
    """Run in interactive mode (backward compatibility)."""
    console.print()
    console.print("[bold]Available phases:[/bold]")
    console.print("  1. Exact checks (always runs)")
    console.print("  2. HNP lattice sweep")
    console.print("  3. Polynomial recurrence")
    console.print()
    
    # Run exact phase
    exact_results = run_exact_phase(groups, args)
    exact_summary = exact_results["summary_rows"]
    exact_findings = exact_results["reuse_findings"] + exact_results["const_findings"] + exact_results["catastrophic_findings"]
    
    # Ask about lattice phase
    run_lattice = False
    if not args.yes:
        response = console.input("[bold]Run lattice phase? [/bold][grey58](fast/thorough/skip)[/grey58] ").strip().lower()
        if response in ("fast", "f"):
            args.fast = True
            run_lattice = True
        elif response in ("thorough", "t"):
            args.thorough = True
            run_lattice = True
    
    lattice_summary = []
    lattice_findings = []
    if run_lattice or args.fast or args.thorough:
        lattice_summary, lattice_findings = run_lattice_phase(groups, args)
    
    # Ask about poly phase
    run_poly = False
    if not args.yes and not args.no_poly:
        response = console.input("[bold]Run polynomial recurrence phase? [/bold][grey58](y/n)[/grey58] ").strip().lower()
        run_poly = response in ("y", "yes")
    
    poly_summary = []
    poly_findings = []
    if run_poly or args.poly_recurrence:
        poly_summary, poly_findings = run_poly_recurrence_phase(groups, args)
    
    return exact_summary, exact_findings, lattice_summary, lattice_findings, poly_summary, poly_findings


def main():
    args = parse_args()
    
    # Handle no filepath case
    if not args.filepath:
        if args.format == "rich":
            console.print("[bold red]Error:[/bold red] No signature file provided.")
            console.print("Usage: python main.py <filepath> [options]")
            console.print("Run with --help for more information.")
        sys.exit(2)
    
    # Validate file exists
    if not Path(args.filepath).exists():
        if args.format == "rich":
            console.print(f"[bold red]Error:[/bold red] File not found: {args.filepath}")
        sys.exit(2)
    
    # Load known keys if provided
    known_keys = load_known_keys(args.known_keys)
    
    # Parse signatures
    start_time = time.time()
    
    if args.format == "rich":
        console.print()
        console.print(Panel(
            f"[bold]File:[/bold] {args.filepath}\n"
            f"[bold]Mode:[/bold] {'thorough' if args.thorough else 'fast' if args.fast else 'interactive'}\n"
            f"[bold]Format:[/bold] {args.format}",
            title="[bold]ECDSA Nonce Bias Analyzer[/bold]",
            border_style="cyan",
        ))
        console.print()
    
    try:
        sigs = parse_rsz_file(args.filepath)
    except Exception as e:
        if args.format == "rich":
            console.print(f"[bold red]Error parsing file:[/bold red] {e}")
        sys.exit(2)
    
    # Validate signatures
    valid_sigs = []
    invalid_count = 0
    for sig in sigs:
        is_valid, reason = validate_signature(sig)
        if is_valid:
            valid_sigs.append(sig)
        else:
            invalid_count += 1
            logger.warning(f"Invalid signature at index {sig.index}: {reason}")
    
    if args.format == "rich":
        console.print(f"[grey58]Parsed {len(sigs)} signatures, {len(valid_sigs)} valid, {invalid_count} invalid[/grey58]")
        console.print()
    
    groups = group_by_pubkey(valid_sigs)
    
    # Determine run mode
    if args.yes or args.fast or args.thorough:
        # Non-interactive mode
        exact_results = run_exact_phase(groups, args, known_keys)
        exact_summary = exact_results["summary_rows"]
        exact_findings = exact_results["reuse_findings"] + exact_results["const_findings"] + exact_results["catastrophic_findings"]
        
        lattice_summary = []
        lattice_findings = []
        if args.fast or args.thorough:
            lattice_summary, lattice_findings = run_lattice_phase(groups, args)
        
        poly_summary = []
        poly_findings = []
        if args.poly_recurrence and not args.no_poly:
            poly_summary, poly_findings = run_poly_recurrence_phase(groups, args)
    else:
        # Interactive mode (backward compatibility)
        (exact_summary, exact_findings, 
         lattice_summary, lattice_findings,
         poly_summary, poly_findings) = interactive_mode(groups, args)
    
    elapsed = time.time() - start_time
    
    # Count recovered keys
    all_findings = exact_findings + lattice_findings + poly_findings
    keys_recovered = len(set(f.get('private_key') for f in all_findings if f.get('private_key')))
    
    # Print summary
    if args.format == "rich":
        print_summary_table(exact_summary, lattice_summary, poly_summary, args)
        
        if keys_recovered > 0:
            console.print(f"[bold bright_red]⚠ {keys_recovered} private key(s) recovered![/bold bright_red]")
        else:
            console.print(f"[bold bright_green]✓ No private keys recovered[/bold bright_green]")
        
        console.print(f"[grey58]Elapsed: {elapsed:.2f}s[/grey58]")
        console.print()
    
    # Build results dict
    results = {
        "file": args.filepath,
        "signatures_parsed": len(sigs),
        "signatures_valid": len(valid_sigs),
        "exact_findings": exact_findings,
        "lattice_findings": lattice_findings,
        "poly_findings": poly_findings,
        "verdict": "KEYS_RECOVERED" if keys_recovered > 0 else "NO_BIAS_FOUND",
        "keys_recovered": keys_recovered,
        "elapsed_seconds": round(elapsed, 3),
    }
    
    # Output JSON if requested
    if args.format == "json" or args.output:
        output_json(results, args)
    
    # Exit code: 0 if no keys recovered, 1 if any key recovered
    sys.exit(1 if keys_recovered > 0 else 0)


if __name__ == "__main__":
    main()
