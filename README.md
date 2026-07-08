# 6FLAS

This repository contains the analytical evaluation script and prototype
microbenchmark for 6FLAS.

The manuscript source and compiled PDFs are not included before publication.

## Reproduce analytical figures

```bash
cd eval
python flas_model.py
```

The script regenerates the analytical data used by the evaluation.

## Run the prototype benchmark

```bash
cd proto
make
./bench_flas
```

On Windows, `proto/compile_run.bat` can be used with an MSVC environment.
