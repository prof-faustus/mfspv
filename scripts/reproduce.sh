#!/usr/bin/env bash
# MF-SPV reproduction (06_EVALUATION_DESIGN.md §8) — portable, no `make` needed.
# Works in Git Bash on Windows and on Linux/macOS. Go toolchain only.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1/5 gofmt =="
test -z "$(gofmt -l .)" && echo "gofmt: clean"

echo "== 2/5 go vet =="
go vet ./...

echo "== 3/5 full test suite (Functional badge) =="
go test -count=1 ./...

echo "== 4/5 mutation gate (06 §4.4/§10) =="
go run ./cmd/mutate

echo "== 5/5 reproduce results -> environment.json, claims.csv (Reproduced badge) =="
go run ./cmd/mfspv -eval

echo
echo "Done. Open claims.csv to audit each claim -> falsifying test."
