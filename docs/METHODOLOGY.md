# Methodology and boundaries

## Analytical model

The model uses explicit per-primitive assumptions on a normalized 1 GHz core,
a fixed seed (20260610), and a Monte-Carlo path/delay model. Software and assumed
acceleration profiles are separate. Constants need target-platform calibration.
It produces nine figure PDFs and `data.json`; these are projections, not traces.

The primary pair is 6FLAS and domain-key SRv6-HMAC-64 with equal context length,
64-bit tags, and domain-level replay assumptions. For h SIDs, input length is
40+16h bytes (424 for 24 SIDs). Shared-SA ESP/AES-GCM is a modeled coarse-grained
reference. Per-flow CBC+HMAC and DTLS 1.2 are legacy reference profiles, not
recommended modern configurations. ESP/DTLS protect payload as well as context,
so their costs are scope-different and do not establish equivalent-service gains.

Bitmap memory is D*6*w/8 bytes per epoch (48 KiB for D=256,w=256; 96 KiB for
two epochs, excluding keys/bases). Window sizing depends on aggregate sender
rate and differential delay. A 32-bit counter requires rotation before wrap.
A 24-hour provisioning-bandwidth average is not a safe epoch prescription at
all packet rates.

## Host benchmark

The benchmark uses 11 repetitions of 100000 iterations plus warmup. JSON goes
to stdout and human-readable timing to stderr. Arrays are [median,min,max].
On x86 the timer reads TSC ticks, not necessarily core cycles or nanoseconds.
Other architectures may use a fallback timer; do not interpret it as x86 TSC.

6FLAS and HMAC-64 use the same FIXED context fixture, local position/domain/
direction checks, and a replay-window update. The input and expected tags are
precomputed while a separate replay sequence increments. It does not rebuild
and authenticate a changing wire packet for every iteration, measure complete
SRv6 parsing, or measure network I/O. Historical "full frame" means the included
local check path, not an end-to-end packet-stack benchmark. Use protocol tests
to exercise changing authenticated fields.

SRv6-Sec is MAC-only. IPsec-like performs illustrative AES-128-CBC plus HMAC,
not interoperable ESP and not shared-SA AES-GCM. These are secondary rows.

## Protocol decision tests

Constructed packet structures and bundled SipHash exercise valid current/previous
epochs, duplicate/stale sequences, context/tag mutations, unknown keys,
destination/SID consistency, domain/direction checks, and one million deterministic
single-bit mutations. A consistent hop-skipping case is intentionally accepted:
authenticating a SID list is not proof that every listed endpoint was visited.

These are not flooding-throughput, multicore-contention, network-scale attack,
or satellite experiments. The replay-state code is single-threaded and does
not implement concurrent locking/atomics.

## Deployment boundaries

The mechanism authenticates routing context, not payload or individual senders
sharing a domain key. The evaluated domain has one managed sender and counter.
Multiple senders, production provisioning/revocation, compromised keys/verifiers,
full fragmentation/tunneling, repaired-path re-origination, and mixed End/End.SEC
deployment require additional work. Bundled cryptographic code is research code,
not audited production crypto. Embedded deterministic test keys are not secrets.
