#!/bin/bash
# Quick local compilation using Docker's Go toolchain.
# No local Go installation required.
# Output binary: ./bin/open-filerep (Linux x86-64)

set -e

mkdir -p "$(pwd)/bin"

docker run --rm \
  -v "$(pwd)/src:/src" \
  -v "$(pwd)/bin:/bin" \
  -w /src \
  golang:alpine \
  go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /bin/open-filerep .

echo "Built: bin/open-filerep"
