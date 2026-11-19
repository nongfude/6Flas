#!/usr/bin/env python3
"""
6FLAS evaluation model (analytical projection, not a flight-hardware result).

Every number is derived from explicit per-primitive cycle constants on a
normalized 1 GHz reference core (1 cycle = 1 ns) plus a Monte-Carlo path
model of a Walker-delta LEO shell. Two cost profiles are provided:
  SW : software crypto, no instruction-set acceleration (primary profile)
  HW : SHA-256 / AES instructions available (sensitivity profile)
All constants are assumptions to be re-calibrated on the target processor.

Outputs (written to results/model/ unless FLAS_OUT is set):
  data.json, proc_overhead.pdf, header_overhead.pdf, scalability.pdf,
  latency_cdf.pdf, handover_cost.pdf, payload_sensitivity.pdf,
  replay_window_sensitivity.pdf, scaling_dims.pdf, dynamic_scenarios.pdf
"""

import json
import math
import os
import random

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

random.seed(20260610)

OUT = os.environ.get("FLAS_OUT", os.path.join(os.path.dirname(__file__), "..", "results", "model"))
os.makedirs(OUT, exist_ok=True)

CLOCK_GHZ = 1.0
NS_PER_CYCLE = 1.0 / CLOCK_GHZ

CYC_SW = {
    "parse_ipv6": 40,
    "parse_srh": 60,          # SRH fixed part + first SID
    "parse_extra_sid": 12,    # each additional SID
    "window_select": 25,      # select (domain, direction, epoch) window
    "window_check": 30,       # sliding-window test and update
    "siphash_per_byte": 2.1,
    "tag_cmp_per_byte": 2,
    "hmac_setup": 900,        # generic HMAC-SHA256 fixed cost
    "hmac_pre_setup": 450,    # key pads precomputed (domain key)
    "hmac_per_byte": 11.0,
    "aes_cbc_per_block": 220,
    "aes_setup": 350,
    "gcm_per_block": 350,     # software AES-GCM, cycles per 16 B
    "gcm_setup": 400,
    "sa_lookup": 180,
    "dtls_record": 1500,
}
CYC_HW = dict(CYC_SW, hmac_setup=300, hmac_pre_setup=150, hmac_per_byte=2.0,
              aes_cbc_per_block=25, aes_setup=100, gcm_per_block=24,
              gcm_setup=120)

# CAL: calibrated to measurements on the benchmark host (i7-6500U). OpenSSL 3.5.5
# `speed` gives SHA-256 = 359 MB/s (about 7-9 cycles/byte at 2.5-3.1 GHz); the
# reference-C SipHash in proto/bench_flas.c costs about 1.6 cycles/byte.
CYC_CAL = dict(CYC_SW, siphash_per_byte=1.6, hmac_per_byte=8.0,
               hmac_setup=650, hmac_pre_setup=330)

MODEL_PATH_SIDS = 24
COVERED_BYTES = 40 + 16 * MODEL_PATH_SIDS


def flas_cycles(h=MODEL_PATH_SIDS, tag_bits=64, c=CYC_SW, window=True):
    t = c["parse_ipv6"] + c["parse_srh"] + c["parse_extra_sid"] * max(h - 1, 0)
    if window:
        t += c["window_select"] + c["window_check"]
    t += c["siphash_per_byte"] * (40 + 16 * h)
    return t + c["tag_cmp_per_byte"] * (tag_bits // 8)


def srv6hmac_cycles(h=MODEL_PATH_SIDS, c=CYC_SW):
    """SRH HMAC TLV profile: per-flow key, full SHA-256 digest, no window."""
    t = c["parse_ipv6"] + c["parse_srh"] + c["parse_extra_sid"] * max(h - 1, 0)
    return t + c["hmac_setup"] + c["hmac_per_byte"] * (40 + 16 * h)


def srv6hmac64_cycles(h=MODEL_PATH_SIDS, c=CYC_SW):
    """Symmetric baseline: domain key, precomputed pads, 64-bit tag, same window."""
    t = c["parse_ipv6"] + c["parse_srh"] + c["parse_extra_sid"] * max(h - 1, 0)
    t += c["window_select"] + c["window_check"]
    t += c["hmac_pre_setup"] + c["hmac_per_byte"] * (40 + 16 * h)
    return t + c["tag_cmp_per_byte"] * 8


def ipsec_cycles(payload=512, c=CYC_SW, shared_gcm=False):
    t = c["parse_ipv6"] + c["sa_lookup"] + c["window_check"]
    blocks = math.ceil(payload / 16)
    if shared_gcm:
        return t + c["gcm_setup"] + c["gcm_per_block"] * blocks
    t += c["hmac_setup"] + c["hmac_per_byte"] * (payload + 40)
    return t + c["aes_setup"] + c["aes_cbc_per_block"] * blocks


def dtls_cycles(payload=512, c=CYC_SW, v13=False):
    t = c["parse_ipv6"] + c["dtls_record"] + c["window_check"]
    blocks = math.ceil(payload / 16)
    if v13:
        return t + c["gcm_setup"] + c["gcm_per_block"] * blocks
    t += c["hmac_setup"] + c["hmac_per_byte"] * (payload + 13)
    return t + c["aes_setup"] + c["aes_cbc_per_block"] * blocks


def plain_srv6_cycles(c=CYC_SW):
    return c["parse_ipv6"] + c["parse_srh"]


def all_mechs(c):
    return {
        "Plain SRv6": plain_srv6_cycles(c),
        "FLAS": flas_cycles(c=c),
        "SRv6-HMAC-64 (domain key)": srv6hmac64_cycles(c=c),
        "SRv6-Sec (HMAC)": srv6hmac_cycles(c=c),
        "IPsec ESP (shared SA, GCM)": ipsec_cycles(c=c, shared_gcm=True),
        "IPsec ESP": ipsec_cycles(c=c),
        "DTLS 1.3 (GCM)": dtls_cycles(c=c, v13=True),
        "DTLS 1.2": dtls_cycles(c=c),
    }


mechs = all_mechs(CYC_SW)
mechs_hw = all_mechs(CYC_HW)
mechs_cal = all_mechs(CYC_CAL)
proc_ns = {k: v * NS_PER_CYCLE for k, v in mechs.items()}
proc_ns_hw = {k: v * NS_PER_CYCLE for k, v in mechs_hw.items()}
proc_ns_cal = {k: v * NS_PER_CYCLE for k, v in mechs_cal.items()}

# ---------------------------------------------------------------------------
# 2. Header overhead (bytes added on top of IPv6 + SRH)
# ---------------------------------------------------------------------------
# 6FLAS: 13 B metadata carried as an SRH TLV: 2 B TLV header + 13 B value
# + 1 B Pad1 = 16 B (SRH length stays a multiple of 8 B).
# SRH HMAC TLV (RFC 8754): Type/Len 2 + flags 2 + key id 4 + HMAC.
header_overhead = {
    "Plain SRv6": 0,
    "FLAS": 16,
    "SRv6-HMAC-64 (domain key)": 16,
    "SRv6-Sec (HMAC)": 2 + 2 + 4 + 32,
    "IPsec ESP (shared SA, GCM)": 8 + 8 + 2 + 16,   # hdr, IV, trailer, ICV
    "IPsec ESP": 8 + 16 + 2 + 16,                   # hdr, IV, trailer, ICV(128)
    "DTLS 1.3 (GCM)": 5 + 1 + 16,                   # unified hdr, type, tag
    "DTLS 1.2": 13 + 16 + 32 + 1,                   # hdr, IV, MAC, min pad
}
SRH_BYTES = 8 + 16 * MODEL_PATH_SIDS                # SRH carried by all SRv6 schemes

# ---------------------------------------------------------------------------
# 3. On-board state
# ---------------------------------------------------------------------------
state_per_flow = {
    "FLAS": 0,
    "SRv6-HMAC-64 (domain key)": 0,
    "SRv6-Sec (HMAC)": 96,              # per-flow key, cached pad, counter (modeling choice)
    "IPsec ESP (shared SA, GCM)": 0,    # one SA per tunnel, not per flow
    "IPsec ESP": 256,
    "DTLS 1.3 (GCM)": 256,
    "DTLS 1.2": 320,
}
STATEFUL = {m: state_per_flow.get(m, 0) > 0 for m in mechs}
N_SAT_FULL, D_MAX, WIN_BYTES = 1584, 256, 32


def replay_state_kib(domains=D_MAX, window_bits=256, epochs=1):
    return domains * 6 * (window_bits // 8) * epochs / 1024.0


# ---------------------------------------------------------------------------
# 4. Throughput vs. concurrent flows (single reference core)
# ---------------------------------------------------------------------------
flows = [10 ** k for k in range(1, 7)]


def throughput_mpps(base_ns, stateful, n_flows):
    penalty = 15.0 * math.log10(max(n_flows, 1)) if stateful else 0.0
    return 1e3 / (base_ns + penalty * NS_PER_CYCLE)


scal = {m: [throughput_mpps(proc_ns[m], STATEFUL[m], n) for n in flows]
        for m in mechs}

# ---------------------------------------------------------------------------
# 5. End-to-end latency over a Walker-delta shell
# ---------------------------------------------------------------------------
ALT_KM, EARTH_R, C_KMS = 550.0, 6371.0, 299792.458
P, S = 72, 22
N_SAT = P * S
orbit_r = EARTH_R + ALT_KM


def link_lengths(planes, per_plane):
    return (2 * orbit_r * math.sin(math.pi / per_plane),
            2 * orbit_r * math.sin(math.pi / planes))


intra_link, inter_link = link_lengths(P, S)


def torus_dist(n):
    d = random.randint(0, n - 1)
    return min(d, n - d)


def mean_torus_dist(n):
    return sum(min(d, n - d) for d in range(n)) / n


def sample_paths(n_samples=4000):
    out = []
    for _ in range(n_samples):
        dh, dv = torus_dist(P), torus_dist(S)
        hops = dh + dv + 1
        prop_ms = (dh * inter_link + dv * intra_link) / C_KMS * 1e3
        queue_ms = sum(random.expovariate(1 / 0.05) for _ in range(hops))
        out.append((hops, prop_ms + queue_ms + 2 * ALT_KM / C_KMS * 1e3))
    return out


PATHS = sample_paths()      # common random numbers for all mechanisms


def sample_latency(per_hop_ns):
    lat = sorted(base + hops * (per_hop_ns(hops) if callable(per_hop_ns) else per_hop_ns) / 1e6
                 for hops, base in PATHS)
    return lat


lat_flas = sample_latency(lambda n: flas_cycles(n) * NS_PER_CYCLE)
lat_hmac = sample_latency(lambda n: srv6hmac64_cycles(n) * NS_PER_CYCLE)
lat_ipsec = sample_latency(proc_ns["IPsec ESP"])
lat_plain = sample_latency(proc_ns["Plain SRv6"])


def pctl(d, p):
    return d[min(len(d) - 1, int(p / 100 * len(d)))]

# ---------------------------------------------------------------------------
# 6. Per-flow re-securing cost after a reroute (design goal D3)
# ---------------------------------------------------------------------------
# Only per-flow-state profiles must install state on the new node. Shared-SA /
# domain-key profiles (incl. 6FLAS) install nothing per flow.
REKEY_CYC = {
    "IPsec ESP": 3_500_000,
    "DTLS 1.2": 3_800_000,
    "DTLS 1.3 (GCM)": 2_500_000,
    "SRv6-Sec (HMAC)": 120_000,
    "FLAS": 0,
}
rekey_flows = [10 ** k for k in range(0, 6)]
rekey_ms = {m: [REKEY_CYC[m] * n * NS_PER_CYCLE / 1e6 for n in rekey_flows]
            for m in REKEY_CYC}

# Domain-key management load (all domains provisioned on all satellites).
KEY_MSG_BYTES = 32 + 16 + 8           # key + AEAD tag + id/epoch
keymgmt_bytes_per_rotation = N_SAT_FULL * D_MAX * KEY_MSG_BYTES
KEY_UNWRAP_CYC = 1500                 # one AES-GCM unwrap per installed key

# ---------------------------------------------------------------------------
# 7. Payload sensitivity, tag width, energy
# ---------------------------------------------------------------------------
payload_sizes = [64, 128, 256, 512, 1024, 1500]
proc_vs_payload = {
    "FLAS": [flas_cycles() * NS_PER_CYCLE for _ in payload_sizes],
    "SRv6-HMAC-64 (domain key)": [srv6hmac64_cycles() * NS_PER_CYCLE for _ in payload_sizes],
    "SRv6-Sec (HMAC)": [srv6hmac_cycles() * NS_PER_CYCLE for _ in payload_sizes],
    "IPsec ESP (shared SA, GCM)": [ipsec_cycles(p, shared_gcm=True) * NS_PER_CYCLE for p in payload_sizes],
    "IPsec ESP": [ipsec_cycles(p) * NS_PER_CYCLE for p in payload_sizes],
    "DTLS 1.2": [dtls_cycles(p) * NS_PER_CYCLE for p in payload_sizes],
}

tag_tradeoff = []
for t in [16, 24, 32, 48, 64]:
    tag_tradeoff.append({
        "tag_bits": t, "forgery_bound_log2": -t,
        "metadata_bytes": 1 + 4 + t // 8,
        "proc_ns": round(flas_cycles(tag_bits=t) * NS_PER_CYCLE, 1)})

# Expected forged-packet acceptances for an on-path injector (R1 other-1).
ATTACK_PPS = 3e6                       # ~10 Gb/s ISL, >=420 B packets
forgery_expect = {
    str(t): {"per_day": ATTACK_PPS * 86400 * 2.0 ** -t,
             "hours_per_success": 1 / (ATTACK_PPS * 2.0 ** -t) / 3600}
    for t in (32, 64)}

NJ_PER_CYCLE = 0.5
energy_nj = {m: round(mechs[m] * NJ_PER_CYCLE, 1) for m in mechs}

# ---------------------------------------------------------------------------
# 8. Replay-window selection: w >= R * Delta
# ---------------------------------------------------------------------------
# Delta = largest delay difference between two routes of one sender at a
# shared downstream verifier: queueing jitter (p99.9) plus a single-failure
# detour (two extra hops of the perpendicular dimension).
jit = sorted(sum(random.expovariate(1 / 0.05) for _ in range(MODEL_PATH_SIDS))
             for _ in range(20000))
jitter_p999_ms = pctl(jit, 99.9)
detour_ms = {"around inter-plane failure": 2 * intra_link / C_KMS * 1e3,
             "around intra-plane failure": 2 * inter_link / C_KMS * 1e3}
delta_ms = jitter_p999_ms + max(detour_ms.values())
window_rates = [1e3, 1e4, 1e5, 1e6]
window_sizes = [64, 128, 256, 512, 1024]


def next_pow2(x):
    return 1 << max(6, math.ceil(math.log2(max(x, 1))))


window_rule = []
for r in window_rates:
    w = next_pow2(r * delta_ms / 1e3)
    window_rule.append({"rate_pps": r, "w_bits": w,
                        "kib_256_domains_1_epoch": round(replay_state_kib(D_MAX, w), 1),
                        "wrap_minutes": round(2 ** 32 / r / 60, 1)})
window_span_ms = {str(r): [1000.0 * w / r for w in window_sizes] for r in window_rates}
window_bitmap_kib = [replay_state_kib(D_MAX, w) for w in window_sizes]

# ---------------------------------------------------------------------------
# 9. Scaling beyond flow count
# ---------------------------------------------------------------------------
sids_axis = list(range(2, 41, 2))
shells = [(24, 11), (36, 16), (54, 22), (72, 22), (96, 32), (120, 40)]
shell_rows = []
for p_, s_ in shells:
    h = mean_torus_dist(p_) + mean_torus_dist(s_) + 1
    shell_rows.append({
        "n_sat": p_ * s_, "mean_hops": round(h, 1),
        "flas_path_us": round(h * flas_cycles(round(h)) * NS_PER_CYCLE / 1e3, 1),
        "hmac64_path_us": round(h * srv6hmac64_cycles(round(h)) * NS_PER_CYCLE / 1e3, 1),
        "hmac_path_us": round(h * srv6hmac_cycles(round(h)) * NS_PER_CYCLE / 1e3, 1)})
domain_axis = [16, 32, 64, 128, 256]
rate_axis = [10 ** (k / 2) for k in range(8, 15)]   # 1e4 .. 1e7 pkt/s

# ---------------------------------------------------------------------------
# 10. Dynamic scenarios
# ---------------------------------------------------------------------------
FLOWS_TOTAL = 10 ** 6
fail_axis = [0.001, 0.003, 0.01, 0.03, 0.1]
H_MEAN = 24


def affected_flows(f, h=H_MEAN):
    return FLOWS_TOTAL * (1 - (1 - f) ** h)


resecure_s = {m: [affected_flows(f) * REKEY_CYC[m] * NS_PER_CYCLE / 1e9 for f in fail_axis]
              for m in REKEY_CYC if REKEY_CYC[m] > 0}
reboot_flows = [10 ** k for k in range(1, 7)]
resume_s = {m: [n * REKEY_CYC[m] * NS_PER_CYCLE / 1e9 for n in reboot_flows]
            for m in REKEY_CYC if REKEY_CYC[m] > 0}
flas_resume_s = D_MAX * KEY_UNWRAP_CYC * NS_PER_CYCLE / 1e9
persist_k = [64, 256, 1024, 4096, 16384]
detour_extra_hops = [2, 6, 10]
detour_proc_us = {str(d): round((H_MEAN + d) * flas_cycles(H_MEAN + d) * NS_PER_CYCLE / 1e3, 1)
                  for d in [0] + detour_extra_hops}

# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------
plt.rcParams.update({"font.size": 11, "axes.grid": True, "grid.alpha": 0.3,
                     "figure.dpi": 150})
COLORS = {
    "Plain SRv6": "#9467bd", "FLAS": "#1f77b4",
    "SRv6-HMAC-64 (domain key)": "#17becf", "SRv6-Sec (HMAC)": "#2ca02c",
    "IPsec ESP (shared SA, GCM)": "#e377c2", "IPsec ESP": "#d62728",
    "DTLS 1.3 (GCM)": "#bcbd22", "DTLS 1.2": "#ff7f0e",
}
SHORT = {"FLAS": "6FLAS", "6FLAS": "6FLAS", "SRv6-HMAC-64 (domain key)": "SRv6-HMAC-64\n(domain key)", "SRv6-HMAC-64": "SRv6-HMAC-64",
         "SRv6-Sec (HMAC)": "SRv6-Sec\n(stateful, SHA-256)",
         "IPsec ESP (shared SA, GCM)": "ESP (shared SA,\nGCM)",
         "IPsec ESP": "ESP (per-flow SA,\nCBC+HMAC)", "DTLS 1.3 (GCM)": "DTLS 1.3",
         "DTLS 1.2": "DTLS 1.2", "Plain SRv6": "Plain SRv6"}


def barh(values, ylabel, fname, fmt="{:.0f}"):
    order = sorted(values, key=lambda m: values[m])
    fig, ax = plt.subplots(figsize=(5.2, 3.6))
    vals = [values[m] for m in order]
    ax.barh(range(len(order)), vals, color=[COLORS[m] for m in order])
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels([SHORT[m] for m in order], fontsize=7)
    ax.set_xlim(0, max(vals) * 1.18)
    ax.set_xlabel(ylabel)
    ax.grid(axis="y", visible=False)
    for i, v in enumerate(vals):
        ax.text(v, i, " " + fmt.format(v), va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, fname))
    plt.close(fig)


barh(proc_ns, "Per-hop processing time (ns), 24-SID path, 512 B payload", "proc_overhead.pdf")
barh(header_overhead, "Security overhead added to IPv6+SRH (B)", "header_overhead.pdf")

fig, ax = plt.subplots(figsize=(5.4, 3.6))
for m in mechs:
    ax.plot(flows, scal[m], marker="o", ms=3, label=SHORT[m].replace("\n", " "),
            color=COLORS[m], ls="-" if STATEFUL[m] else "--")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Number of concurrent flows")
ax.set_ylabel("Single-core throughput (Mpps)")
ax.legend(fontsize=6, ncol=2)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "scalability.pdf"))
plt.close(fig)

fig, ax = plt.subplots(figsize=(5.4, 3.4))
for data, name in [(lat_plain, "Plain SRv6"), (lat_flas, "6FLAS"),
                   (lat_hmac, "SRv6-HMAC-64"), (lat_ipsec, "ESP reference")]:
    ax.plot(data, [(i + 1) / len(data) for i in range(len(data))],
            label=SHORT.get(name, name).replace("\n", " "), color=COLORS.get(name, COLORS.get("FLAS")))
ax.set_xlabel("End-to-end latency (ms)")
ax.set_ylabel("CDF")
ax.legend(fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "latency_cdf.pdf"))
plt.close(fig)

fig, ax = plt.subplots(figsize=(5.4, 3.4))
for m in ["IPsec ESP", "DTLS 1.2", "DTLS 1.3 (GCM)", "SRv6-Sec (HMAC)"]:
    ax.plot(rekey_flows, rekey_ms[m], marker="o", ms=4,
            label=SHORT[m].replace("\n", " "), color=COLORS[m])
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Rerouted flows per control window")
ax.set_ylabel("Control-plane CPU time (ms)")
ax.text(0.04, 0.9, "6FLAS, SRv6-HMAC-64, shared-SA ESP: no per-flow\n"
        "installation (key provisioning costs excluded)", transform=ax.transAxes,
        fontsize=7, va="top")
ax.legend(fontsize=7, loc="lower right")
fig.tight_layout()
fig.savefig(os.path.join(OUT, "handover_cost.pdf"))
plt.close(fig)

fig, ax = plt.subplots(figsize=(5.4, 3.4))
for m in proc_vs_payload:
    ax.plot(payload_sizes, [v / 1000 for v in proc_vs_payload[m]], marker="o",
            ms=3, label=SHORT[m].replace("\n", " "), color=COLORS[m])
ax.set_xlabel("Payload size (bytes)")
ax.set_ylabel(r"Per-hop processing time ($\mu$s)")
ax.legend(fontsize=6)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "payload_sensitivity.pdf"))
plt.close(fig)

fig, ax = plt.subplots(figsize=(5.4, 3.4))
for r in window_rates:
    ax.plot(window_sizes, window_span_ms[str(r)], marker="o", ms=4, label=f"{r:.0e} pkt/s")
ax.axhline(delta_ms, color="k", ls=":", lw=1)
ax.text(window_sizes[0], delta_ms * 1.1, rf"$\Delta$ = {delta_ms:.1f} ms", fontsize=8)
ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xlabel("Replay-window positions $w$")
ax.set_ylabel("Ordering span $w/R$ (ms)")
ax.legend(fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "replay_window_sensitivity.pdf"))
plt.close(fig)

# Scaling beyond flow count: four panels.
fig, axs = plt.subplots(2, 2, figsize=(7.0, 5.0))
ax = axs[0, 0]
for m, fn in [("FLAS", flas_cycles), ("SRv6-HMAC-64 (domain key)", srv6hmac64_cycles),
              ("SRv6-Sec (HMAC)", srv6hmac_cycles)]:
    ax.plot(sids_axis, [fn(h) * NS_PER_CYCLE / 1e3 for h in sids_axis],
            color=COLORS[m], label=SHORT[m].replace("\n", " "))
ax.set_xlabel("SIDs in path $h$")
ax.set_ylabel(r"Per-hop time ($\mu$s)")
ax.set_title("(a) Path length", fontsize=9)
ax.legend(fontsize=6)
ax = axs[0, 1]
for key, m in [("flas_path_us", "FLAS"), ("hmac64_path_us", "SRv6-HMAC-64 (domain key)"),
               ("hmac_path_us", "SRv6-Sec (HMAC)")]:
    ax.plot([r["n_sat"] for r in shell_rows], [r[key] for r in shell_rows],
            marker="o", ms=3, color=COLORS[m])
ax.set_xscale("log")
ax.set_xlabel("Satellites $N$")
ax.set_ylabel(r"Security time per path ($\mu$s)")
ax.set_title("(b) Constellation size", fontsize=9)
ax = axs[1, 0]
for w in (256, 512, 1024):
    ax.plot(domain_axis, [replay_state_kib(d, w, epochs=2) for d in domain_axis],
            marker="o", ms=3, label=f"$w$={w}")
ax.set_xscale("log", base=2)
ax.set_xlabel(r"Security domains $D$ (8-bit id: $D\leq256$)")
ax.set_ylabel("Replay bitmaps, 2 epochs (KiB)")
ax.set_title("(c) Number of domains", fontsize=9)
ax.legend(fontsize=7)
ax = axs[1, 1]
for m in ["FLAS", "SRv6-HMAC-64 (domain key)", "SRv6-Sec (HMAC)", "IPsec ESP (shared SA, GCM)"]:
    ax.plot(rate_axis, [min(r * proc_ns[m] / 1e9, 10) * 100 for r in rate_axis],
            color=COLORS[m], label=SHORT[m].replace("\n", " "))
ax.axhline(100, color="k", ls=":", lw=1)
ax.set_xscale("log")
ax.set_ylim(0, 300)
ax.set_xlabel("Packet rate through the core (pkt/s)")
ax.set_ylabel("Core utilization (%)")
ax.set_title("(d) Packet rate", fontsize=9)
ax.legend(fontsize=6)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "scaling_dims.pdf"))
plt.close(fig)

# Dynamic scenarios: three panels.
fig, axs = plt.subplots(1, 3, figsize=(7.2, 2.5))
ax = axs[0]
for m, ys in resecure_s.items():
    ax.plot(fail_axis, ys, marker="o", ms=3, color=COLORS[m], label=SHORT[m].replace("\n", " "))
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("ISLs failed at once (fraction)")
ax.set_ylabel("Re-secure CPU time (s)")
ax.set_title("(a) Simultaneous ISL failures", fontsize=8)
ax.legend(fontsize=5)
ax = axs[1]
for m, ys in resume_s.items():
    ax.plot(reboot_flows, ys, marker="o", ms=3, color=COLORS[m], label=SHORT[m].replace("\n", " "))
ax.axhline(flas_resume_s, color=COLORS["FLAS"], ls="--", label="6FLAS (key reload)")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Flows through the rebooted node")
ax.set_ylabel("Resume time after boot (s)")
ax.set_title("(b) Node reboot", fontsize=8)
ax.legend(fontsize=5)
ax = axs[2]
ax.plot(persist_k, [k for k in persist_k], marker="o", ms=3, color="k", label=r"positions lost $\leq K$")
ax.set_xscale("log", base=2)
ax.set_yscale("log")
ax.set_xlabel("Persist interval $K$ (positions)")
ax.set_ylabel("Positions lost at restart")
ax2 = ax.twinx()
for r, ls in [(1e4, "-"), (1e5, "--")]:
    ax2.plot(persist_k, [r / k for k in persist_k], color="tab:red", ls=ls, label=f"writes/s @ {r:.0e} pkt/s")
ax2.set_yscale("log")
ax2.set_ylabel("Persistent writes/s", color="tab:red")
ax2.grid(False)
ax.set_title("(c) Restart rule", fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "dynamic_scenarios.pdf"))
plt.close(fig)

# ---------------------------------------------------------------------------
# Dump raw numbers
# ---------------------------------------------------------------------------
def ratio(a, b, prof=proc_ns):
    return round(prof[a] / prof[b], 2)


summary = {
    "proc_ns": {k: round(v, 1) for k, v in proc_ns.items()},
    "proc_ns_hw_profile": {k: round(v, 1) for k, v in proc_ns_hw.items()},
    "ratio_sw_vs_flas": {m: ratio(m, "FLAS") for m in proc_ns},
    "ratio_hw_vs_flas": {m: ratio(m, "FLAS", proc_ns_hw) for m in proc_ns_hw},
    "proc_ns_cal_profile": {k: round(v, 1) for k, v in proc_ns_cal.items()},
    "ratio_cal_vs_flas": {m: ratio(m, "FLAS", proc_ns_cal) for m in proc_ns_cal},
    "flas_without_window_ns": round(flas_cycles(window=False) * NS_PER_CYCLE, 1),
    "header_overhead_B": header_overhead,
    "srh_bytes_24_sids": SRH_BYTES,
    "state_per_flow_B": state_per_flow,
    "replay_state_kib_256_domains": {"1_epoch": replay_state_kib(256, 256),
                                     "2_epochs": replay_state_kib(256, 256, 2)},
    "throughput_at_1e6_Mpps": {m: round(scal[m][-1], 2) for m in mechs},
    "constellation": {"alt_km": ALT_KM, "planes": P, "sats_per_plane": S,
                      "n_sat": N_SAT, "intra_link_km": round(intra_link, 1),
                      "inter_link_km": round(inter_link, 1)},
    "mean_hops_reference_shell": round(mean_torus_dist(P) + mean_torus_dist(S) + 1, 2),
    "latency_ms": {
        "FLAS_median": round(pctl(lat_flas, 50), 2), "FLAS_p95": round(pctl(lat_flas, 95), 2),
        "HMAC64_median": round(pctl(lat_hmac, 50), 2),
        "IPsec_median": round(pctl(lat_ipsec, 50), 2), "IPsec_p95": round(pctl(lat_ipsec, 95), 2),
        "Plain_median": round(pctl(lat_plain, 50), 2)},
    "covered_bytes": COVERED_BYTES,
    "rekey_cycles_per_flow": REKEY_CYC,
    "rekey_ms_at_1e4_flows": {m: round(rekey_ms[m][4], 3) for m in REKEY_CYC},
    "keymgmt_MB_per_rotation_all_domains_all_sats": round(keymgmt_bytes_per_rotation / 1e6, 1),
    "keymgmt_Bps_for_24h_epoch": round(keymgmt_bytes_per_rotation / 86400, 1),
    "payload_sizes": payload_sizes,
    "proc_ns_at_1500B": {m: round(v[-1], 1) for m, v in proc_vs_payload.items()},
    "tag_tradeoff": tag_tradeoff,
    "forgery_expectation_3Mpps": forgery_expect,
    "energy_nj_per_pkt": energy_nj,
    "jitter_p999_ms": round(jitter_p999_ms, 2),
    "detour_ms": {k: round(v, 2) for k, v in detour_ms.items()},
    "delta_ms": round(delta_ms, 2),
    "window_rule": window_rule,
    "shell_scaling": shell_rows,
    "resecure_s_at_fail_fraction": {str(f): {m: round(v[i], 1) for m, v in resecure_s.items()}
                                    for i, f in enumerate(fail_axis)},
    "resume_s_at_1e4_flows": {m: round(v[3], 2) for m, v in resume_s.items()},
    "flas_resume_ms": round(flas_resume_s * 1e3, 3),
    "affected_flows_at_fail_fraction": {str(f): round(affected_flows(f)) for f in fail_axis},
    "detour_path_proc_us": detour_proc_us,
}
with open(os.path.join(OUT, "data.json"), "w") as fh:
    json.dump(summary, fh, indent=2)
print(json.dumps(summary, indent=2))
