# Artifact Appendix — MF-SPV

This artifact accompanies the MF-SPV paper (`PAPER.md`) and is structured for ACM
artifact evaluation per `06_EVALUATION_DESIGN.md §8`. It is a single, self-contained
Go module with **zero external dependencies** (builds and runs offline).

## Badges targeted

- **Artifacts Available.** Public repository; archive to a citable DOI (Zenodo) and
  record the commit hash in `environment.json` (emitted by the reproduce step).
- **Artifacts Evaluated — Functional.** `go test ./...` builds and passes offline,
  deterministically and order-independently (`go test -shuffle=on ./...`).
- **Results Reproduced.** A single entry point regenerates every table/figure from
  raw measurements with fixed seeds and prints each result tagged
  M(easured) / D(erived) / S(imulated); `claims.csv` maps each claim to its test.

## Requirements

- Go 1.26+ (the only requirement). No network, no other tools.
- Commodity x86-64 or arm64; multi-core helps the throughput measurement but is not
  required. ~200 MB disk, ~1 GB RAM.

## One-command reproduction

```sh
# Linux/macOS (or any host with make):
make all          # fmt + vet + full test + mutation gate
make reproduce    # emit environment.json + claims.csv, tagged M/D/S

# Portable (Git Bash on Windows included), no make:
bash scripts/reproduce.sh

# Or the pure-Go path, works everywhere:
go test ./... && go run ./cmd/mutate && go run ./cmd/mfspv -eval
```

## Reviewer path (claim-by-claim)

1. `go test -count=1 ./...` → **Functional** (75 tests pass).
2. `go test -shuffle=on -count=1 ./...` → order-independent (06 §3.4).
3. `go run ./cmd/mutate` → security gate: **17/17 mutants killed, score 1.000** (06 §4.4/§10).
4. `go run ./cmd/mfspv -eval` → writes `environment.json` + `claims.csv` and prints
   the scaling table / capacity tagged M/D/S → **Reproduced**.
5. Open `claims.csv` and confirm each claim ID maps to a passing test.

## Expected runtime (commodity hardware)

| Step | Approx. time |
|---|---|
| `go test ./...` (full) | ~30 s |
| `go test -short ./...` | ~5 s |
| `go run ./cmd/mutate` (17 mutants) | ~2 min |
| `go run ./cmd/mfspv -eval` | ~3 s |

## What each result is (tags)

- **Measured (M):** per-core SHA-256d rate; edge verification latency/throughput;
  all rejection/forgery outcomes; KAT/differential/property/Monte-Carlo results.
- **Derived (D):** header dataset/year; sealing capacity (hashes/s, core-equivalents)
  from the measured per-hash cost; subtree counts.
- **Simulated (S):** depth law and proof sizes from real (feasibly-sized) trees,
  with the integer law checked by exact equality across the 10⁶–10¹² grid.

Projections to 10⁶–10¹² tx/s are **Derived**, not end-to-end measured; a single
machine cannot build a 6×10¹³-leaf block. See `PAPER.md §1 status`, `§8`, and
`06_EVALUATION_DESIGN.md §7` (threats to validity).

## Honest scope (not evaluated here)

- Real Teranode at scale (the adapter uses an in-memory `MockNode` that builds real
  Merkle/accumulator structures; wiring to a pinned Teranode revision is the
  outstanding integration step).
- Side-channel resistance of the `math/big` secp256k1 signer (same secp256k1 curve;
  constant-time hardening is a deployment task).
- Wide-area IPv6-multicast alert propagation (the evidence-gating logic is tested).
- End-to-end 0-conf latency (bounded by the orthogonal double-spend layer).

See `SECURITY.md` for the adversarial audit (RT-1…RT-7) and confirmed-safe surfaces.

## License

Set by the author before archival (`CITATION.cff` `license:` and a `LICENSE` file).
Not imposed by this artifact.
