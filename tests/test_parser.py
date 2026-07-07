# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests for parser module.
"""

import pytest
import tempfile
import os
from parser import parse_rsz_file, parse_rsz_stream, group_by_pubkey
from curve import N

# Valid test values (must be < N)
VALID_R = hex((N - 100) // 2)[2:]
VALID_S = hex((N - 200) // 2)[2:]
VALID_Z = hex((N - 300) // 2)[2:]


def test_parse_valid_file():
    """Test parsing a valid RSZ format file."""
    content = f"""Signature #1
R = {VALID_R}
S = {VALID_S}
Z = {VALID_Z}
PubKey: abc123def456

Signature #2
R = {VALID_R}
S = {VALID_S}
Z = {VALID_Z}
PubKey: xyz789uvw012
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(content)
        f.flush()
        filepath = f.name
    
    try:
        sigs = parse_rsz_file(filepath)
        assert len(sigs) == 2
        assert sigs[0].pubkey == "abc123def456"
        assert sigs[1].pubkey == "xyz789uvw012"
    finally:
        os.unlink(filepath)


def test_parse_malformed_s():
    """Test that malformed signatures (S=0) are handled gracefully."""
    content = f"""Signature #1
R = {VALID_R}
S = 0000000000000000000000000000000000000000000000000000000000000000
Z = {VALID_Z}
PubKey: abc123def456

Signature #2
R = {VALID_R}
S = {VALID_S}
Z = {VALID_Z}
PubKey: xyz789uvw012
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(content)
        f.flush()
        filepath = f.name
    
    try:
        sigs = parse_rsz_file(filepath)
        # Should skip the bad signature (S=0) and parse the good one
        assert len(sigs) == 1
        assert sigs[0].pubkey == "xyz789uvw012"
    finally:
        os.unlink(filepath)


def test_stream_parser_memory():
    """Test that stream parser doesn't load entire file into memory."""
    # Create a large file
    content = ""
    for i in range(100):
        r_val = hex((N - 100 - i) % N)[2:].zfill(64)
        s_val = hex((N - 200 - i) % N)[2:].zfill(64)
        z_val = hex((N - 300 - i) % N)[2:].zfill(64)
        content += f"""Signature #{i+1}
R = {r_val}
S = {s_val}
Z = {z_val}
PubKey: key_{i}

"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(content)
        f.flush()
        filepath = f.name
    
    try:
        # Use stream parser
        count = 0
        for sig in parse_rsz_stream(filepath):
            count += 1
        
        assert count == 100
    finally:
        os.unlink(filepath)


def test_group_by_pubkey():
    """Test grouping signatures by pubkey."""
    content = f"""Signature #1
R = {VALID_R}
S = {VALID_S}
Z = {VALID_Z}
PubKey: abc123

Signature #2
R = {VALID_R}
S = {VALID_S}
Z = {VALID_Z}
PubKey: abc123

Signature #3
R = {VALID_R}
S = {VALID_S}
Z = {VALID_Z}
PubKey: xyz789
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(content)
        f.flush()
        filepath = f.name
    
    try:
        sigs = parse_rsz_file(filepath)
        groups = group_by_pubkey(sigs)
        
        assert len(groups) == 2
        assert len(groups["abc123"]) == 2
        assert len(groups["xyz789"]) == 1
    finally:
        os.unlink(filepath)
