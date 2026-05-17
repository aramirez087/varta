# Build the VLP base-spec conformance verifier.
#
# Usage:
#   make verify           # generates vectors.h, builds verify_vectors, runs it
#   make build            # build only
#   make clean
#
# Requires: C99 compiler, Python 3 (for vectors.h generation).

CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -Wpedantic -O2
VECTORS_JSON ?= ../../vlp-test-vectors.json

.PHONY: verify build clean

verify: build
	./verify_vectors

build: verify_vectors

verify_vectors: verify_vectors.c vlp.c vlp.h vectors.h
	$(CC) $(CFLAGS) -o $@ verify_vectors.c vlp.c

vectors.h: $(VECTORS_JSON) gen_vectors_header.py
	python3 gen_vectors_header.py $(VECTORS_JSON) > $@

clean:
	rm -f verify_vectors vectors.h
