# Result provenance

`reference/proto_bench_result.json` is copied unchanged from the existing local
evaluation aggregate. It names i7-6500U, GCC 13.2.0, 11 repetitions, 424 context
bytes, and 512 payload bytes for the secondary reference. It contains historical
minimum/median/maximum summaries, NOT the individual timings of the 11 runs.
No missing raw observations were invented. The original OS version and complete
historical execution logs are not recorded in this file.

`validation/` is a NEW package-check run. Its environment metadata must not be
substituted for unknown historical metadata. The regenerated `model/data.json`
is analytical, not measured. Protocol-test logs are actual program output.
Fresh benchmark values may differ from the historical paper aggregate.

`python tools/reproduce.py --all` writes `results/local/`, leaving reference
and validation outputs untouched. Preserve environment metadata alongside timings.
No independent third-party replication is claimed.
