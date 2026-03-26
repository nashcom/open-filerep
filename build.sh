#!/bin/bash
# Build the open-filerep container image.
# Usage: ./build.sh [options]
#
# Options:
#   -image <name>   Override image name (default: nashcom/open-filerep)
#   -docker <cmd>   Override container command (default: docker)

set -e

IMAGE="nashcom/open-filerep"
DOCKER="docker"
DOCKERFILE="container/Dockerfile"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -image)  IMAGE="$2";  shift 2 ;;
        -docker) DOCKER="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Building: $IMAGE"
echo "Commit  : $GIT_COMMIT"
echo "File    : $DOCKERFILE"
echo

START=$(date +%s)

$DOCKER build \
    --progress=plain \
    --build-arg GIT_COMMIT="$GIT_COMMIT" \
    -t "$IMAGE:latest" \
    -f "$DOCKERFILE" \
    .

END=$(date +%s)
echo
echo "Done in $((END - START))s — image: $IMAGE:latest"
