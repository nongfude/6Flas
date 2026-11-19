# 6FLAS evaluation and protocol tests

Analytical evaluation, research C microbenchmark, and protocol-level tests for
6FLAS. This is not a production SRv6/End.SEC stack or a satellite implementation.
Manuscript PDFs, reviewer correspondence, credentials, and binaries are excluded.

## Reproduce

Use Python 3.10+, GCC with C11 support, and Matplotlib. Package validation uses
Python 3.14, GCC 13.2.0 (MinGW-w64), and Matplotlib 3.10.8 on Windows. These
are package-check details, not missing metadata reconstructed for historical runs.
The intended benchmark timing platform is x86/x86-64 (RDTSC timestamp counter).

From the repository root:

```bash
python -m pip install -r requirements.txt
python tools/reproduce.py --all
```

The runner compiles from source, runs protocol tests and the host benchmark,
and regenerates model figures. Results go to `results/local/`, separate from
historical results. It requires GCC on PATH but does not require make.
On Windows, `py` can replace `python` if the Python launcher is installed.

```bash
python tools/reproduce.py --tests
python tools/reproduce.py --benchmark
python tools/reproduce.py --model
python tools/reproduce.py --tests --cc /path/to/gcc
```

The model also runs directly: `python eval/flas_model.py`, writing to
`results/model/`. Set `FLAS_OUT` to choose another directory. With make
installed: `make -C proto` and `make -C proto test` build/run the C programs.

## Contents

* `eval/flas_model.py`: analytical cost/path models and nine PDF figures.
* `proto/`: benchmark, protocol tests, and bundled primitive headers.
* `tools/reproduce.py`: portable GCC-based build/run entry point.
* `results/reference/`: historical benchmark aggregate, not individual raw runs.
* `results/validation/`: fresh package-check outputs and environment metadata.
* `docs/METHODOLOGY.md`: scope, baseline definitions, and limitations.
* `docs/RESULTS.md`: provenance and interpretation of stored data.

## Interpret results correctly

The approximately 4.2x software result is an analytical projection (about
1.34 versus 5.56 microseconds), not the host timing ratio. The historical
host medians are 665 and 8279 timestamp-counter ticks per operation.
New host timings vary by machine/compiler/load; exact reproduction of those
numbers is not promised. A 24-SID MAC input is 424 bytes; tags are 64 bits.

The first two benchmark rows include local checks and replay-window work on
a fixed fixture. This is NOT packet I/O or a complete per-packet network stack.
SRv6-Sec is a separate MAC-only reference. IPsec-like is illustrative CBC/HMAC
work, not a measured shared-SA AES-GCM implementation. See the methodology.

Protocol negative tests are decision tests, not attack-throughput experiments.
Hardware-profile curves are assumed costs, not flight-hardware measurements.

Existing source attribution is retained. No new project-wide license is granted
by this package; authors should select a license and confirm redistribution
rights before explicitly licensing the repository. Test keys are public fixtures.
