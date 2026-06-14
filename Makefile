# MF-SPV — reproduction entry point (06_EVALUATION_DESIGN.md §8).
# Zero external dependencies; everything below is the Go toolchain only.
#
# Reviewer path:  make test  ->  make reproduce  ->  open claims.csv
# On Windows without make, run the equivalent `go ...` commands (see ARTIFACT.md).

GO ?= go

.PHONY: all test test-short reproduce mutate eval bench fmt vet shuffle clean

all: fmt vet test mutate ## fmt, vet, full test, mutation gate

test: ## full functional + adversarial + evaluation suite (Artifacts Evaluated — Functional)
	$(GO) test -count=1 ./...

test-short: ## fast subset
	$(GO) test -short -count=1 ./...

shuffle: ## order-independence (06 §3.4)
	$(GO) test -shuffle=on -count=1 ./...

reproduce: ## regenerate environment.json + claims.csv and print tagged M/D/S results (Results Reproduced)
	$(GO) run ./cmd/mfspv -eval

eval: reproduce ## alias

mutate: ## security-critical mutation-testing gate, 17/17 must be killed (06 §4.4/§10)
	$(GO) run ./cmd/mutate

bench: ## scaling + capacity + one full push payment
	$(GO) run ./cmd/mfspv

fmt: ## gofmt check (must print nothing)
	@gofmt -l . && echo "gofmt: clean"

vet:
	$(GO) vet ./...

clean:
	rm -f environment.json claims.csv mfspv mfspv.exe
