# SPDX-License-Identifier: GPL-3.0-or-later
"""
Corrected biased-signature generator for testing the analyzer.

Key fix vs. the broken version: the bias is applied to k BEFORE r is
computed from it, so r and s remain mathematically consistent. Never
truncate/modify r's string representation after the fact - that produces
signatures that don't satisfy the ECDSA equation at all, which is
indistinguishable from "no signature here" to any correct analyzer.
"""

import hashlib
import random
from ecdsa import SECP256k1, SigningKey

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = SECP256k1.generator

BIAS_BITS = 40          # how many top bits of k are forced to zero (MSB bias)
NUM_SIGS = 150

# Use a real keypair so PubKey can be included - without it, the lattice
# phase of the analyzer has nothing to verify candidates against and will
# skip these signatures entirely.
sk = SigningKey.generate(curve=SECP256k1)
private_key = sk.privkey.secret_multiplier
pubkey_hex = sk.get_verifying_key().to_string("compressed").hex()

print("=" * 70)
print("BITCOIN RSZ EXTRACTION REPORT (synthetic, intentionally biased)")
print(f"PubKey: {pubkey_hex}")
print(f"Total signatures: {NUM_SIGS}")
print("=" * 70)
print()

lines = []
for count in range(1, NUM_SIGS + 1):
    # bias applied to k itself: top BIAS_BITS bits forced to zero
    k = random.randint(0, (1 << (256 - BIAS_BITS)) - 1)

    Rx, Ry = None, None
    point = k * G
    r_val = point.x() % N

    sim_tx_data = f"mock_tx_data_{count}_{random.randint(1000,9999)}"
    z_hex = hashlib.sha256(sim_tx_data.encode()).hexdigest()
    z_val = int(z_hex, 16)

    k_inv = pow(k, -1, N)
    s_val = (k_inv * (z_val + r_val * private_key)) % N
    if s_val > N // 2:
        s_val = N - s_val  # low-s normalization, doesn't break the equation
        # NOTE: low-s means s_val = N - s_val, but the equation still holds
        # because s and -s mod N both correspond to valid signatures (this
        # IS standard practice, unlike the R truncation bug)

    txid = hashlib.sha256(f"visual_txid_{count}".encode()).hexdigest()

    lines.append(f"Signature #{count}")
    lines.append(f"  TXID: {txid}")
    lines.append(f"  R = {r_val:064x}")
    lines.append(f"  S = {s_val:064x}")
    lines.append(f"  Z = {z_hex}")
    lines.append(f"  PubKey: {pubkey_hex}")
    lines.append("")

with open("biased_test_RSZ.txt", "w") as f:
    f.write("\n".join(lines))

print(f"wrote biased_test_RSZ.txt: {NUM_SIGS} signatures, {BIAS_BITS}-bit MSB bias")
print(f"private key (for your own verification): {hex(private_key)}")
