CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11

bench_flas: bench_flas.c siphash.h sha256.h
	$(CC) $(CFLAGS) -o $@ bench_flas.c -lm

clean:
	rm -f bench_flas bench_flas.exe

.PHONY: clean
