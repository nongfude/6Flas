#!/usr/bin/env python3
"""
bench_flas.py — 6FLAS Python software prototype benchmark.

Measures per-primitive wall-clock time (ns) using timeit with baseline
subtraction, then computes speedup ratios and compares them to the
analytical model in ../eval/flas_model.py.

MAC proxy: hashlib.blake2b (native C keyed hash, same role as SipHash-2-4).
  BLAKE2b throughput ≈ 3–4 cycles/byte vs SipHash-2-4 ≈ 2.1 cycles/byte,
  so reported ratios slightly understate the C-level speedup.

AES-128-CBC via cryptography (pip install cryptography).

Run: python bench_flas.py
"""

import timeit, hashlib, hmac, json, sys

# Optional AES via cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    def _aes_cbc_512(key, data, iv):
        e = Cipher(algorithms.AES(key), modes.CBC(iv),
                   backend=default_backend()).encryptor()
        return e.update(data) + e.finalize()
    HAS_AES = True
except ImportError:
    HAS_AES = False

# ── Constants matching ../eval/flas_model.py ──────────────────────────────
COVERED  = 72    # IPv6(40B) + SRH-1SID(24B) + FLAS metadata(8B)
PAYLOAD  = 512

DATA_72  = bytes(i % 256 for i in range(COVERED))
DATA_552 = bytes(i % 256 for i in range(40 + PAYLOAD))
DATA_512 = bytes(i % 256 for i in range(PAYLOAD))
KEY_32   = bytes(range(32))
KEY_16   = bytes(range(16))
IV_16    = b'\x00' * 16

# Blake2b key must be <= 64 bytes; use first 32 bytes of domain key
BK = KEY_32

# ── Timing helpers ─────────────────────────────────────────────────────────
def _bench_ns(fn, n=500_000):
    return timeit.timeit(fn, number=n) / n * 1e9

def main():
    ITERS = 500_000

    print("Measuring baseline overhead ...", file=sys.stderr)
    t_base = _bench_ns(lambda: None, n=ITERS)

    print("Benchmarking FLAS MAC (BLAKE2b/72B) ...", file=sys.stderr)
    t_flas = _bench_ns(
        lambda: hashlib.blake2b(DATA_72, key=BK, digest_size=4).digest(),
        n=ITERS)

    print("Benchmarking SRv6-Sec (HMAC-SHA256/72B) ...", file=sys.stderr)
    t_srv6 = _bench_ns(
        lambda: hmac.new(KEY_32, DATA_72, hashlib.sha256).digest(),
        n=ITERS)

    print("Benchmarking IPsec HMAC (HMAC-SHA256/552B) ...", file=sys.stderr)
    t_hmac = _bench_ns(
        lambda: hmac.new(KEY_32, DATA_552, hashlib.sha256).digest(),
        n=ITERS)

    if HAS_AES:
        print("Benchmarking AES-128-CBC/512B ...", file=sys.stderr)
        t_aes = _bench_ns(
            lambda: _aes_cbc_512(KEY_16, DATA_512, IV_16),
            n=ITERS // 10)
    else:
        t_aes = 0.0
        print("WARNING: cryptography not installed; AES omitted from IPsec total.",
              file=sys.stderr)
        print("  pip install cryptography   to include AES.", file=sys.stderr)

    t_ipsec = t_hmac + t_aes

    # Subtract baseline (Python call overhead ~40 ns)
    def net(t): return max(t - t_base, 1.0)

    nf = net(t_flas)
    ns = net(t_srv6)
    ni = net(t_ipsec)

    ratio_srv6  = ns / nf
    ratio_ipsec = ni / nf

    # ── Human-readable summary ────────────────────────────────────────────
    print(f"\n--- Results (ns/primitive, Python {sys.version.split()[0]}) ---",
          file=sys.stderr)
    print(f"  baseline overhead  : {t_base:6.0f} ns", file=sys.stderr)
    print(f"  FLAS  (BLAKE2b/72B): {t_flas:6.0f} ns  net {nf:.0f} ns",
          file=sys.stderr)
    print(f"  SRv6-Sec(HMAC/72B) : {t_srv6:6.0f} ns  net {ns:.0f} ns",
          file=sys.stderr)
    print(f"  IPsec (HMAC+AES)   : {t_ipsec:6.0f} ns  net {ni:.0f} ns  "
          f"(AES: {'yes' if HAS_AES else 'MISSING'})", file=sys.stderr)
    print(f"\n  SRv6-Sec / FLAS : {ratio_srv6:.1f}x  (analytical model: 5.9x)",
          file=sys.stderr)
    print(f"  IPsec    / FLAS : {ratio_ipsec:.1f}x  (analytical model: 47.8x)",
          file=sys.stderr)
    print(f"\nNote: BLAKE2b ≈ 3–4 cyc/byte vs SipHash-2-4 ≈ 2.1 cyc/byte,",
          file=sys.stderr)
    print(f"  so measured ratios slightly understate C-level speedup.", file=sys.stderr)

    # ── JSON output ───────────────────────────────────────────────────────
    result = {
        "proto_bench_python": {
            "note": (
                "net ns/primitive (baseline-subtracted); BLAKE2b proxy for SipHash-2-4. "
                "C benchmark (bench_flas.c) gives exact cycle counts."
            ),
            "python_version": sys.version.split()[0],
            "mac_primitive": "blake2b-32" if not hasattr(hashlib, 'siphash24') else "siphash24",
            "aes_included": HAS_AES,
            "covered_bytes": COVERED,
            "payload_bytes": PAYLOAD,
            "iterations": ITERS,
            "ns_per_primitive_net": {
                "FLAS_MAC":    round(nf,    1),
                "SRv6-Sec":   round(ns,    1),
                "IPsec-like": round(ni,    1),
            },
            "speedup_vs_flas": {
                "SRv6-Sec": round(ratio_srv6,  1),
                "IPsec":    round(ratio_ipsec, 1),
            },
            "analytical_model_speedup": {
                "SRv6-Sec": 5.9,
                "IPsec":    47.8,
            },
        }
    }
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
