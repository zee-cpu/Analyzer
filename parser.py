# SPDX-License-Identifier: GPL-3.0-or-later
"""
Parser for RSZ.txt-format signature dumps.

Expected format (repeating blocks):

    Signature #1
    R = <hex>
    S = <hex>
    Z = <hex>
    PubKey: <hex>        (optional)
    TXID: <hex>          (optional)
    Timestamp: <int>     (optional)

PubKey is optional but important: without it, cross-key nonce-reuse and
per-key lattice grouping can't distinguish which signatures belong to the
same signer. If omitted, every signature is treated as belonging to a
single unknown/shared key group unless TXID-based grouping is requested.
"""

import re
import logging
from typing import Iterator, Optional
from curve import Signature, validate_signature

logger = logging.getLogger(__name__)


def parse_rsz_stream(filepath: str) -> Iterator[Signature]:
    """
    Streaming parser that yields Signature objects one at a time.
    Never calls f.read() - uses line iteration instead.
    Handles malformed signatures gracefully by skipping them with a warning.
    """
    index = 0
    current_block = ""
    
    try:
        with open(filepath, "r") as f:
            for line in f:
                if re.match(r"Signature\s*#\d+", line):
                    # Process previous block if any
                    if current_block:
                        sig = _parse_block(current_block, index)
                        if sig:
                            is_valid, reason = validate_signature(sig)
                            if is_valid:
                                yield sig
                                index += 1
                            else:
                                logger.warning(f"Signature #{index} validation failed: {reason}")
                    current_block = line
                else:
                    current_block += line
        
        # Process final block
        if current_block:
            sig = _parse_block(current_block, index)
            if sig:
                is_valid, reason = validate_signature(sig)
                if is_valid:
                    yield sig
                    index += 1
                else:
                    logger.warning(f"Signature #{index} validation failed: {reason}")
    
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        raise


def _parse_block(block: str, index: int) -> Optional[Signature]:
    """
    Parse a single signature block.
    Returns None if the block is malformed.
    """
    r_match = re.search(r"R\s*=\s*([a-fA-F0-9]+)", block)
    s_match = re.search(r"S\s*=\s*([a-fA-F0-9]+)", block)
    z_match = re.search(r"Z\s*=\s*([a-fA-F0-9]+)", block)

    if not (r_match and s_match and z_match):
        logger.warning(f"Signature #{index}: malformed block (missing R, S, or Z)")
        return None

    try:
        r = int(r_match.group(1), 16)
        s = int(s_match.group(1), 16)
        z = int(z_match.group(1), 16)
    except ValueError as e:
        logger.warning(f"Signature #{index}: failed to parse hex values: {e}")
        return None

    # PubKey can be hex or alphanumeric (e.g., "abc123" or "key_1")
    pubkey_match = re.search(r"PubKey\s*:\s*([a-zA-Z0-9_]+)", block)
    txid_match = re.search(r"TXID\s*:\s*([a-fA-F0-9]+)", block)
    timestamp_match = re.search(r"Timestamp\s*:\s*(\d+)", block)

    return Signature(
        r=r, s=s, z=z,
        pubkey=pubkey_match.group(1) if pubkey_match else None,
        txid=txid_match.group(1) if txid_match else None,
        timestamp=int(timestamp_match.group(1)) if timestamp_match else None,
        index=index,
    )


def parse_rsz_file(filepath: str) -> list[Signature]:
    """
    Parse all signatures from a file.
    Thin wrapper around parse_rsz_stream that collects all results.
    """
    return list(parse_rsz_stream(filepath))


def group_by_pubkey(signatures: list[Signature]) -> dict[Optional[str], list[Signature]]:
    """
    Group signatures by their claimed pubkey. Signatures with no pubkey
    field are grouped under None - the caller should treat that group as
    "unknown, possibly mixed keys" rather than assume they're all one key.
    """
    groups: dict[Optional[str], list[Signature]] = {}
    for sig in signatures:
        groups.setdefault(sig.pubkey, []).append(sig)
    return groups
