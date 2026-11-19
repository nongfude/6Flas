CC      = gcc
CFLAGS  = -O3 -Wall -Wextra -std=c11

bench_flas: bench_flas.c siphash.h sha256.h
	$(CC) $(CFLAGS) -o $@ bench_flas.c -lm

negative_tests: negative_tests.c siphash.h sha256.h
	$(CC) $(CFLAGS) -Wno-unused-function -o $@ negative_tests.c

test: negative_tests
	./negative_tests

clean:
	rm -f bench_flas bench_flas.exe negative_tests negative_tests.exe

.PHONY: clean test
