# ECDSA Nonce Bias Analyzer & Solver

A comprehensive tool for detecting and exploiting ECDSA nonce biases through exact checks, HNP lattice reduction, and polynomial recurrence analysis.

## Features

### Phase 1: Exact Checks
- **Nonce Reuse Detection**: Identifies same-key and cross-key nonce reuse
- **Catastrophic Nonce Derivation**: Detects when nonce is derived from known values (k=z, k=r, k=d)
- **Small Constant Nonce Brute Force**: Tests small nonce values (default: 2^24)
- **Offset Detection**: Finds nonces with small offsets from hash or r-coordinate

### Phase 2: HNP Lattice Sweep
- MSB/LSB bias hypothesis testing
- LLL/BKZ lattice reduction
- Pruned lattice enumeration for improved recovery
- Modular bias detection

### Phase 3: Polynomial Recurrence
- Detects polynomial nonce recurrence patterns
- Tests unknown-coefficient recurrences

## Installation

```bash
pip install -r requirements.txt
```

### Dependencies
- `fpylll>=0.6.0` - Lattice reduction
- `cysignals>=1.11.0` - Signal handling
- `rich>=13.0.0` - Terminal output
- `ecdsa>=0.19.0` - ECDSA operations
- `sympy>=1.12` - Symbolic math
- `pytest>=7.0.0` - Testing

## Usage

### Basic Usage

```bash
# Interactive mode (prompts for each phase)
python main.py signatures.txt

# Non-interactive mode with JSON output
python main.py signatures.txt --yes --format json -o output.json

# Fast lattice sweep only
python main.py signatures.txt --fast --yes

# Thorough analysis with all phases
python main.py signatures.txt --thorough --yes
```

### CLI Options

```
positional arguments:
  filepath              Path to RSZ signature file

options:
  --fast                Run fast lattice sweep (priority bit-widths only, no BKZ)
  --thorough            Run thorough lattice sweep (full widths + BKZ + subset sampling)
  --poly-recurrence     Run polynomial recurrence phase
  --no-poly             Explicitly skip polynomial recurrence
  --format {rich,json}  Output format (default: rich)
  --yes, -y             Auto-confirm all phases; non-interactive mode
  --known-keys FILE     JSON file of known {"pubkey": "hex", "private_key": "hex"} pairs
  --output, -o FILE     Write JSON output to file
  --small-nonce-bound B Brute-force bound for small constant nonces (default: 2^24)
  --offset-bound C      Bound for k = z + c offset search (default: 2^16)
  --bkz-block-size K    BKZ block size (default: 20, min 10, max 30)
  --enumerate-radius R  Lattice enumeration radius (default: 2)
  --modular-bias-limit M Max modulus for modular bias sweep (default: 2^16)
  --max-workers N       ProcessPoolExecutor max workers (default: os.cpu_count())
```

### Input Format

Signatures should be in RSZ format:

```
Signature #1
R = <hex>
S = <hex>
Z = <hex>
PubKey: <hex>        (optional)
TXID: <hex>          (optional)
Timestamp: <int>     (optional)

Signature #2
...
```

### Output Format

#### Rich (Human-Readable)
Default terminal output with colored tables and progress indicators.

#### JSON
Structured output suitable for automation:

```json
{
  "file": "signatures.txt",
  "signatures_parsed": 100,
  "signatures_valid": 100,
  "exact_findings": {
    "reuse": [...],
    "catastrophic": [...],
    "small_nonce": [...],
    "offset": [...]
  },
  "lattice_findings": [...],
  "poly_findings": [...],
  "verdict": "COMPROMISED",
  "keys_recovered": 5,
  "elapsed_seconds": 12.34
}
```

## Catastrophic Checks

### k = z (Message Hash as Nonce)
When the message hash is used directly as the nonce:
```
d = (s - 1) * z * r^{-1} mod N
```

### k = r (Signature R-Coordinate as Nonce)
When the r-coordinate is used as the nonce:
```
d = s - z * r^{-1} mod N
```

### k = d (Private Key as Nonce)
When the private key is used as the nonce:
```
d = z * (s - r)^{-1} mod N
```

## Cross-Key Exploitation

When two different keys share the same nonce (r-collision), you can recover the unknown key if you know one:

```bash
python main.py signatures.txt --known-keys known_keys.json --yes
```

Known keys file format:
```json
[
  {"pubkey": "abc123...", "private_key": "0x1234..."},
  {"pubkey": "def456...", "private_key": "0x5678..."}
]
```

## Performance

### Small Nonce Brute Force
- 2^24 nonces: ~10minutes (parallelized)
- 2^20 nonces: ~100ms

### Lattice Reduction
- Fast mode (published incident bit-widths): ~5-10 seconds
- Thorough mode (full sweep + BKZ): ~30-60 seconds

### Polynomial Recurrence
- Depends on signature count and recurrence complexity
- Typically 10-30 seconds for 100+ signatures

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

Test coverage includes:
- Nonce reuse recovery
- Cross-key collision detection
- Catastrophic nonce derivation
- Small constant nonce detection
- Offset detection
- Parser validation
- CLI functionality

## Architecture

### Modules

- **curve.py**: ECDSA curve constants and low-level math
- **parser.py**: Streaming RSZ format parser with validation
- **exact_checks.py**: Deterministic single-signature and reuse checks
- **hnp_lattice.py**: HNP lattice reduction and enumeration
- **poly_recurrence.py**: Polynomial recurrence detection
- **subset_clustering.py**: Signature subset analysis
- **main.py**: CLI orchestration and output formatting

### Design Principles

1. **Verify Before Trust**: Every recovered key is verified against d*G == Q
2. **Defensive Programming**: All modular inverses handle failure gracefully
3. **No False Positives**: Exact checks use mathematical certainty, not statistics
4. **Streaming Parser**: Handles large files without loading into memory
5. **Type Hints**: Full Python 3.10+ type annotations

## License

This project is licensed under the GNU General Public License v3.0 or later. See LICENSE file for details.

## References

- Breitner & Heninger, "Biased Nonce Sense" (eprint.iacr.org/2019/023)
- Madhwal et al., "Chain Reactions: How Nonce Collisions in ECDSA Compromise Polygon MEV Searchers" (arXiv:2605.21498)
- Cebrian-Marquez, "Breaking ECDSA with Two Affinely Related Nonces" (2025)

## Contributing

Contributions are welcome. Please ensure:
- All tests pass: `pytest tests/ -v`
- Code follows existing style
- New features include tests
- SPDX headers are present on all files

## Disclaimer

This tool is for educational and authorized security testing only. Unauthorized access to computer systems is illegal.
