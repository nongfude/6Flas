#!/usr/bin/env python3
"""
FLAS evaluation model.

This script produces the quantitative results reported in the FLAS paper.
All numbers are derived from an explicit, reproducible analytical model of
per-packet security processing on a resource-constrained LEO on-board router,
combined with an event-driven model of an end-to-end path over a Walker-delta
LEO constellation. No physical satellite hardware is involved; every figure is
regenerated deterministically from the constants defined below.

The model intentionally favours transparency over false precision: each cost
term is documented and attributed, so a reader can audit or re-parameterise it.

Outputs (written to ../paper/figures/):
  - data.json                      raw numbers used in the paper text/tables
  - proc_overhead.pdf              per-packet processing time vs. baselines
  - header_overhead.pdf            per-packet byte overhead vs. baselines
  - scalability.pdf                throughput vs. concurrent flows
  - latency_cdf.pdf                end-to-end latency CDF over the constellation
"""

import json
import math
import os
import random

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

random.seed(20260610)

OUT = os.path.join(os.path.dirname(__file__), "..", "paper", "figures")
os.makedirs(OUT, exist_ok=True)

# ---------------------------------------------------------------------------
# 1. On-board router cost model (per packet, per hop)
# ---------------------------------------------------------------------------
# We model the on-board forwarding engine as a 1.0 GHz space-grade processor
# (representative of radiation-hardened LEON/RISC-V class cores), so one clock
# cycle = 1 ns. Cost of each primitive is expressed in CPU cycles based on
# well-known software-crypto microbenchmarks normalised to this core.
CLOCK_GHZ = 1.0
NS_PER_CYCLE = 1.0 / CLOCK_GHZ  # ns per cycle

# Primitive costs (cycles). Symmetric primitives dominate; AES-CBC and HMAC
# costs are taken per 16-byte block / per processed byte respectively at the
# software level, consistent with widely reported eBACS/openssl ratios on
# embedded cores.
CYC = {
    "parse_ipv6": 40,        # parse fixed IPv6 header
    "parse_srh": 60,         # parse SRH + one SID
    "flowlabel_lookup": 25,  # hash Flow Label into per-direction window table
    "siphash_per_byte": 2.1, # SipHash-2-4 MAC, cycles/byte (keyed, lightweight)
    "hmac_sha256_setup": 900,# HMAC-SHA256 fixed setup (two block hashes)
    "hmac_sha256_per_byte": 11.0,
    "aes_cbc_per_block": 220,# AES-128-CBC software, cycles / 16 B block (no AES-NI on space cores)
    "aes_setup": 350,
    "seqno_window_check": 30,# sliding-window anti-replay test+set
    "sa_lookup": 180,        # SPD/SAD lookup for IPsec (tree/hash over selectors)
    "dtls_record": 1500,     # DTLS record-layer bookkeeping per record
}

# Bytes covered by the integrity primitive (the security-relevant header span
# that FLAS authenticates: IPv6 base header + SRH + 8-byte FLAS metadata).
COVERED_BYTES = 40 + 24 + 8

# Mechanism definitions: list of (primitive, count) charged per hop.
def flas_cycles():
    c = 0
    c += CYC["parse_ipv6"]
    c += CYC["parse_srh"]
    c += CYC["flowlabel_lookup"]
    c += CYC["seqno_window_check"]
    c += CYC["siphash_per_byte"] * COVERED_BYTES   # MAC over covered span
    return c

def ipsec_cycles(payload=512):
    # IPsec ESP transport: SA lookup + HMAC over (header+payload) + AES decrypt.
    c = 0
    c += CYC["parse_ipv6"]
    c += CYC["sa_lookup"]
    c += CYC["seqno_window_check"]
    c += CYC["hmac_sha256_setup"] + CYC["hmac_sha256_per_byte"] * (payload + 40)
    blocks = math.ceil(payload / 16)
    c += CYC["aes_setup"] + CYC["aes_cbc_per_block"] * blocks
    return c

def dtls_cycles(payload=512):
    # DTLS 1.2 record processing (AEAD modelled as AES-CBC+HMAC for fairness).
    c = 0
    c += CYC["parse_ipv6"]
    c += CYC["dtls_record"]
    c += CYC["seqno_window_check"]
    c += CYC["hmac_sha256_setup"] + CYC["hmac_sha256_per_byte"] * (payload + 13)
    blocks = math.ceil(payload / 16)
    c += CYC["aes_setup"] + CYC["aes_cbc_per_block"] * blocks
    return c

def srv6sec_cycles():
    # "Lightweight SRv6 Security" baseline: HMAC-SHA256 over SRH per RFC8754
    # HMAC TLV semantics, computed per hop (worst case verification).
    c = 0
    c += CYC["parse_ipv6"]
    c += CYC["parse_srh"]
    c += CYC["hmac_sha256_setup"] + CYC["hmac_sha256_per_byte"] * COVERED_BYTES
    return c

def plain_srv6_cycles():
    c = CYC["parse_ipv6"] + CYC["parse_srh"]
    return c

mechs = {
    "Plain SRv6": plain_srv6_cycles(),
    "IPsec ESP": ipsec_cycles(),
    "DTLS 1.2": dtls_cycles(),
    "SRv6-Sec (HMAC)": srv6sec_cycles(),
    "FLAS": flas_cycles(),
}
proc_ns = {k: v * NS_PER_CYCLE for k, v in mechs.items()}

# ---------------------------------------------------------------------------
# 2. Header / byte overhead model (per packet)
# ---------------------------------------------------------------------------
# Bytes of security-specific overhead added on top of the IPv6+SRH baseline.
header_overhead = {
    "Plain SRv6": 0,
    "IPsec ESP": 8 + 16 + 12 + 2,   # ESP hdr(8)+IV(16)+ICV(12)+pad/trailer(2)
    "DTLS 1.2": 13 + 8 + 16,         # record hdr(13)+explicit nonce(8)+tag(16)
    "SRv6-Sec (HMAC)": 4 + 32,       # HMAC TLV header(4)+SHA256 digest(32)
    "FLAS": 0 + 8,                   # Flow Label reuses existing field; 8B FLAS metadata TLV
}

# ---------------------------------------------------------------------------
# 3. Per-flow on-board state model
# ---------------------------------------------------------------------------
# Bytes of mutable on-board state required per active flow.
state_per_flow = {
    "IPsec ESP": 256,        # SA: keys, selectors, replay window, counters
    "DTLS 1.2": 320,         # session: keys, epoch, replay window, cookie
    "SRv6-Sec (HMAC)": 96,   # per-flow key + counter
    "FLAS": 0,              # zero per-flow state; total on-board state is fixed 192B (6 dirs × 32B), direction-scoped
}

# ---------------------------------------------------------------------------
# 4. Throughput / scalability model
# ---------------------------------------------------------------------------
# Single forwarding core; throughput limited by per-packet processing time.
# We sweep concurrent flows; stateful schemes pay an additional state-lookup
# penalty that grows mildly (cache pressure) with the working set.
flows = [10**k for k in range(1, 7)]  # 10 .. 1e6
PKT_BITS = 512 * 8

def throughput_mpps(base_ns, stateful, n_flows):
    # cache-pressure penalty for stateful schemes: log-scaled extra cycles
    penalty = 0.0
    if stateful:
        penalty = 15.0 * math.log10(max(n_flows, 1))  # extra cycles per pkt
    t = base_ns + penalty * NS_PER_CYCLE
    return 1e3 / t  # packets per microsecond -> Mpps (since t is in ns)

stateful_map = {
    "Plain SRv6": False,
    "IPsec ESP": True,
    "DTLS 1.2": True,
    "SRv6-Sec (HMAC)": True,
    "FLAS": False,   # stateless verification: window keyed by flow label hash, O(1), no per-flow table walk
}
scal = {m: [throughput_mpps(proc_ns[m], stateful_map[m], n) for n in flows] for m in mechs}

# ---------------------------------------------------------------------------
# 5. End-to-end latency model over a Walker-delta LEO constellation
# ---------------------------------------------------------------------------
# Constellation: 550 km altitude, P=72 planes, S=22 sats/plane (Starlink-like
# shell, 1584 sats). ISL is free-space optical. We sample random src/dst pairs,
# route over a grid-like +Grid ISL topology, and accumulate propagation +
# per-hop processing + queueing.
ALT_KM = 550.0
EARTH_R = 6371.0
C_KMS = 299792.458  # speed of light km/s
P, S = 72, 22
N_SAT = P * S

# Approx inter-satellite link length: intra-plane and inter-plane spacing.
orbit_r = EARTH_R + ALT_KM
intra_link = 2 * orbit_r * math.sin(math.pi / S)      # neighbour in same plane
inter_link = 2 * orbit_r * math.sin(math.pi / P)      # neighbour cross-plane

def sample_latency(proc_ns_per_hop, n_samples=4000):
    lat = []
    for _ in range(n_samples):
        # random Manhattan-ish hop count on the P x S torus grid
        dh = min(abs(random.randint(0, P-1)), P - abs(random.randint(0, P-1)))
        dv = min(abs(random.randint(0, S-1)), S - abs(random.randint(0, S-1)))
        hops = dh + dv + 1
        prop_ms = (dh * inter_link + dv * intra_link) / C_KMS * 1.0  # ms (km / (km/s) = s -> *1e3)
        prop_ms = (dh * inter_link + dv * intra_link) / C_KMS * 1e3
        # processing: per-hop security cost; queueing modelled as light M/M/1 jitter
        proc_ms = hops * proc_ns_per_hop / 1e6
        queue_ms = sum(random.expovariate(1/0.05) for _ in range(hops))  # ~0.05 ms mean per hop
        # ground up/down link ~ 2 * (550 km / c)
        updown_ms = 2 * (ALT_KM) / C_KMS * 1e3
        lat.append(prop_ms + proc_ms + queue_ms + updown_ms)
    lat.sort()
    return lat

lat_flas = sample_latency(proc_ns["FLAS"])
lat_ipsec = sample_latency(proc_ns["IPsec ESP"])
lat_plain = sample_latency(proc_ns["Plain SRv6"])

def cdf_xy(data):
    n = len(data)
    xs = data
    ys = [(i + 1) / n for i in range(n)]
    return xs, ys

# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "font.size": 12,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "figure.dpi": 150,
})
COLORS = {
    "Plain SRv6": "#9467bd",
    "IPsec ESP": "#d62728",
    "DTLS 1.2": "#ff7f0e",
    "SRv6-Sec (HMAC)": "#2ca02c",
    "FLAS": "#1f77b4",
}
order = ["IPsec ESP", "DTLS 1.2", "SRv6-Sec (HMAC)", "Plain SRv6", "FLAS"]

# Fig: processing overhead bar
fig, ax = plt.subplots(figsize=(5.2, 3.8))
vals = [proc_ns[m] for m in order]
bars = ax.bar(range(len(order)), vals, color=[COLORS[m] for m in order])
ax.set_xticks(range(len(order)))
ax.set_xticklabels(order, rotation=0, ha="center", fontsize=7.5)
ax.set_ylim(0, max(vals) * 1.20)
ax.set_ylabel("Per-hop processing time (ns)")
for b, v in zip(bars, vals):
    ax.text(b.get_x()+b.get_width()/2, v, f"{v:.0f}", ha="center", va="bottom", fontsize=9)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "proc_overhead.pdf"))
plt.close(fig)

# Fig: header overhead bar
fig, ax = plt.subplots(figsize=(5.2, 3.8))
vals = [header_overhead[m] for m in order]
bars = ax.bar(range(len(order)), vals, color=[COLORS[m] for m in order])
ax.set_xticks(range(len(order)))
ax.set_xticklabels(order, rotation=0, ha="center", fontsize=7.5)
ax.set_ylim(0, max(vals) * 1.20)
ax.set_ylabel("Per-packet byte overhead (B)")
for b, v in zip(bars, vals):
    ax.text(b.get_x()+b.get_width()/2, v, f"{v}", ha="center", va="bottom", fontsize=9)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "header_overhead.pdf"))
plt.close(fig)

# Fig: scalability (throughput vs concurrent flows)
fig, ax = plt.subplots(figsize=(5.4, 3.4))
for m in order:
    ax.plot(flows, scal[m], marker="o", ms=4, label=m, color=COLORS[m])
ax.set_xscale("log")
ax.set_xlabel("Number of concurrent flows")
ax.set_ylabel("Single-core throughput (Mpps)")
ax.legend(fontsize=8, ncol=2)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "scalability.pdf"))
plt.close(fig)

# Fig: latency CDF
fig, ax = plt.subplots(figsize=(5.4, 3.4))
for data, name in [(lat_plain, "Plain SRv6"), (lat_flas, "FLAS"), (lat_ipsec, "IPsec ESP")]:
    xs, ys = cdf_xy(data)
    ax.plot(xs, ys, label=name, color=COLORS[name])
ax.set_xlabel("End-to-end latency (ms)")
ax.set_ylabel("CDF")
ax.legend(fontsize=9)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "latency_cdf.pdf"))
plt.close(fig)

# ---------------------------------------------------------------------------
# 6. Handover / re-keying cost under ISL churn (design goal D3)
# ---------------------------------------------------------------------------
# When orbital motion breaks an ISL, a flow is rerouted onto a new satellite.
# A stateful mechanism must migrate or re-establish its per-flow security
# association on the new node (key exchange / SA install); FLAS migrates
# nothing because the security context travels in the packet. We charge each
# scheme the control-plane work it must perform per rerouted flow.
#
# Control-plane cost per rerouted flow (in equivalent CPU cycles on the same
# 1 GHz core), drawn from the same primitive set:
#   - IPsec/DTLS: a fresh handshake (asymmetric op modelled as a fixed heavy
#     cost) + SA/session install on the new node.
#   - SRv6-Sec (HMAC): re-derive and install a per-flow key on the new node.
#   - FLAS: nothing to migrate; the new node verifies the next packet directly.
REKEY_CYC = {
    "IPsec ESP": 3_500_000,    # IKEv2-class handshake + SA install (asymmetric)
    "DTLS 1.2": 3_800_000,     # DTLS handshake (asymmetric) + session install
    "SRv6-Sec (HMAC)": 120_000,# per-flow key re-derivation + install
    "FLAS": 0,                 # stateless: no per-flow migration
}
# Handover rate model: with N satellites and an orbital period ~95 min, each
# ISL is reconfigured a few times per orbit. We sweep the number of flows that
# must be rerouted in a 1-second control window and report aggregate control
# work per node (ms of CPU time) as a function of affected-flow count.
rekey_flows = [10**k for k in range(0, 6)]  # 1 .. 1e5 rerouted flows / window
rekey_ms = {m: [REKEY_CYC[m] * n * NS_PER_CYCLE / 1e6 for n in rekey_flows]
            for m in REKEY_CYC}

# ---------------------------------------------------------------------------
# 7. Payload-size sensitivity (per-hop processing vs. packet payload)
# ---------------------------------------------------------------------------
# FLAS authenticates only the fixed 72-byte routing span, so its per-hop cost
# is independent of payload size. IPsec/DTLS authenticate (and encrypt) the
# payload, so their cost grows linearly with it. This is a key qualitative
# difference on an ISL that carries large data packets.
payload_sizes = [64, 128, 256, 512, 1024, 1500]
proc_vs_payload = {
    "FLAS": [flas_cycles() * NS_PER_CYCLE for _ in payload_sizes],
    "SRv6-Sec (HMAC)": [srv6sec_cycles() * NS_PER_CYCLE for _ in payload_sizes],
    "IPsec ESP": [ipsec_cycles(p) * NS_PER_CYCLE for p in payload_sizes],
    "DTLS 1.2": [dtls_cycles(p) * NS_PER_CYCLE for p in payload_sizes],
}

# ---------------------------------------------------------------------------
# 8. Tag-width security / overhead tradeoff
# ---------------------------------------------------------------------------
# The truncated MAC tag width t (bits) sets the single-packet forgery bound
# (2^-t) and the per-packet metadata size. We tabulate the tradeoff so the
# paper can justify the 32-bit default and show how to harden it.
tag_widths = [16, 24, 32, 48, 64]
tag_tradeoff = []
for t in tag_widths:
    meta_bytes = 1 + 3 + (t // 8)          # domain(1) + seq(3) + tag(t/8)
    covered_t = 40 + 24 + meta_bytes       # IPv6 + SRH + FLAS metadata span
    proc_ns_t = (CYC["parse_ipv6"] + CYC["parse_srh"] + CYC["flowlabel_lookup"]
                 + CYC["seqno_window_check"]
                 + CYC["siphash_per_byte"] * covered_t) * NS_PER_CYCLE
    tag_tradeoff.append({
        "tag_bits": t,
        "forgery_bound_log2": -t,
        "metadata_bytes": meta_bytes,
        "proc_ns": round(proc_ns_t, 1),
    })

# ---------------------------------------------------------------------------
# 9. Per-packet energy estimate
# ---------------------------------------------------------------------------
# Energy is a first-order constraint on a solar/battery-limited satellite.
# Using a representative space-grade core figure of ~0.5 nJ per cycle, we
# convert per-hop processing cost to energy per verified packet.
NJ_PER_CYCLE = 0.5
energy_nj = {m: round(mechs[m] * NJ_PER_CYCLE, 1) for m in mechs}

# ---------------------------------------------------------------------------
# Extra figures
# ---------------------------------------------------------------------------
# Fig: handover / re-keying control work
fig, ax = plt.subplots(figsize=(5.4, 3.4))
for m in ["IPsec ESP", "DTLS 1.2", "SRv6-Sec (HMAC)", "FLAS"]:
    ys = [max(v, 1e-6) for v in rekey_ms[m]]
    ax.plot(rekey_flows, ys, marker="o", ms=4, label=m, color=COLORS[m])
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Rerouted flows per control window")
ax.set_ylabel("Control-plane CPU time (ms)")
ax.annotate("FLAS: no per-flow migration",
            xy=(1e3, 1e-3), xytext=(20, 1e-2), fontsize=8,
            arrowprops=dict(arrowstyle="->", color=COLORS["FLAS"]))
ax.legend(fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "handover_cost.pdf"))
plt.close(fig)

# Fig: per-hop processing vs payload size
fig, ax = plt.subplots(figsize=(5.4, 3.4))
for m in ["IPsec ESP", "DTLS 1.2", "SRv6-Sec (HMAC)", "FLAS"]:
    ax.plot(payload_sizes, [v/1000 for v in proc_vs_payload[m]],
            marker="o", ms=4, label=m, color=COLORS[m])
ax.set_xlabel("Payload size (bytes)")
ax.set_ylabel("Per-hop processing time ($\\mu$s)")
ax.legend(fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(OUT, "payload_sensitivity.pdf"))
plt.close(fig)

# ---------------------------------------------------------------------------
# Dump raw numbers for the paper
# ---------------------------------------------------------------------------
def pctl(d, p):
    return d[min(len(d)-1, int(p/100*len(d)))]

summary = {
    "proc_ns": {k: round(v, 1) for k, v in proc_ns.items()},
    "proc_speedup_vs_ipsec": round(proc_ns["IPsec ESP"]/proc_ns["FLAS"], 2),
    "proc_speedup_vs_srv6sec": round(proc_ns["SRv6-Sec (HMAC)"]/proc_ns["FLAS"], 2),
    "header_overhead_B": header_overhead,
    "header_reduction_vs_ipsec_pct": round((1 - header_overhead["FLAS"]/header_overhead["IPsec ESP"])*100, 1),
    "state_per_flow_B": state_per_flow,
    "state_reduction_vs_ipsec_pct": round((1 - state_per_flow["FLAS"]/state_per_flow["IPsec ESP"])*100, 1),
    "throughput_at_1e6_Mpps": {m: round(scal[m][-1], 2) for m in mechs},
    "flas_throughput_gain_vs_ipsec_1e6": round(scal["FLAS"][-1]/scal["IPsec ESP"][-1], 2),
    "constellation": {"alt_km": ALT_KM, "planes": P, "sats_per_plane": S, "n_sat": N_SAT,
                      "intra_link_km": round(intra_link,1), "inter_link_km": round(inter_link,1)},
    "latency_ms": {
        "FLAS_median": round(pctl(lat_flas,50),2), "FLAS_p95": round(pctl(lat_flas,95),2),
        "IPsec_median": round(pctl(lat_ipsec,50),2), "IPsec_p95": round(pctl(lat_ipsec,95),2),
        "Plain_median": round(pctl(lat_plain,50),2),
    },
    "flowlabel_bits": 20,
    "flowlabel_capacity": 2**20,
    "covered_bytes": COVERED_BYTES,
    "rekey_cycles_per_flow": REKEY_CYC,
    "rekey_ms_at_1e4_flows": {m: round(rekey_ms[m][4], 3) for m in REKEY_CYC},
    "payload_sizes": payload_sizes,
    "proc_ns_at_1500B": {m: round(proc_vs_payload[m][-1], 1)
                          for m in proc_vs_payload},
    "flas_proc_payload_independent": (
        round(proc_vs_payload["FLAS"][0], 1) == round(proc_vs_payload["FLAS"][-1], 1)),
    "tag_tradeoff": tag_tradeoff,
    "energy_nj_per_pkt": energy_nj,
    "energy_ratio_ipsec_over_flas": round(energy_nj["IPsec ESP"]/energy_nj["FLAS"], 1),
}
with open(os.path.join(OUT, "data.json"), "w") as f:
    json.dump(summary, f, indent=2)

print(json.dumps(summary, indent=2))
