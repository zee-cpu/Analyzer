# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests for main CLI module.
"""

import pytest
import tempfile
import os
import json
import subprocess
import sys


def test_cli_json_output():
    """Test that CLI produces valid JSON output with --format json."""
    # Create a test signature file
    content = """Signature #1
R = 1234567890abcdef
S = fedcba0987654321
Z = aaaaaabbbbbbcccc
PubKey: abc123def456

Signature #2
R = 1111111111111111
S = 2222222222222222
Z = 3333333333333333
PubKey: xyz789uvw012
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(content)
        f.flush()
        filepath = f.name
    
    try:
        # Run main.py with --format json --yes
        result = subprocess.run(
            [sys.executable, "main.py", filepath, "--format", "json", "--yes"],
            capture_output=True,
            text=True,
            cwd="/home/zee/Analyzer"
        )
        
        # Parse JSON output
        output = json.loads(result.stdout)
        
        # Validate JSON schema
        assert "file" in output
        assert "signatures_parsed" in output
        assert "signatures_valid" in output
        assert "exact_findings" in output
        assert "lattice_findings" in output
        assert "poly_findings" in output
        assert "verdict" in output
        assert "keys_recovered" in output
        assert "elapsed_seconds" in output
        
        assert output["signatures_parsed"] == 2
        assert output["signatures_valid"] == 2
    finally:
        os.unlink(filepath)


def test_cli_non_interactive():
    """Test that CLI runs non-interactively with --yes flag."""
    content = """Signature #1
R = 1234567890abcdef
S = fedcba0987654321
Z = aaaaaabbbbbbcccc
PubKey: abc123def456
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(content)
        f.flush()
        filepath = f.name
    
    try:
        # Run main.py with --yes (non-interactive)
        result = subprocess.run(
            [sys.executable, "main.py", filepath, "--yes", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd="/home/zee/Analyzer"
        )
        
        # Should complete without hanging or prompting
        assert result.returncode in (0, 1)  # 0 = no keys, 1 = keys recovered
        
        # Should produce valid JSON
        output = json.loads(result.stdout)
        assert "file" in output
    finally:
        os.unlink(filepath)


def test_cli_output_file():
    """Test that CLI writes JSON to output file with -o flag."""
    content = """Signature #1
R = 1234567890abcdef
S = fedcba0987654321
Z = aaaaaabbbbbbcccc
PubKey: abc123def456
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(content)
        f.flush()
        filepath = f.name
    
    output_file = tempfile.mktemp(suffix='.json')
    
    try:
        # Run main.py with -o output file
        result = subprocess.run(
            [sys.executable, "main.py", filepath, "--yes", "--format", "json", "-o", output_file],
            capture_output=True,
            text=True,
            cwd="/home/zee/Analyzer"
        )
        
        # Check that output file was created
        assert os.path.exists(output_file)
        
        # Verify it contains valid JSON
        with open(output_file, 'r') as f:
            output = json.load(f)
            assert "file" in output
    finally:
        os.unlink(filepath)
        if os.path.exists(output_file):
            os.unlink(output_file)
