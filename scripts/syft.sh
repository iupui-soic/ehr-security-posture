#!/usr/bin/env bash
# Wrapper that runs Anchore Syft via its official Docker image so no Go toolchain
# is needed on the host. The current directory is mounted read-only at /work so
# Syft can scan a local clone, e.g.:
#   scripts/syft.sh dir:/work/clones/openmrs -o cyclonedx-json
# Passing a remote target (e.g. github:owner/repo) also works without a mount.
set -euo pipefail

IMAGE="${SYFT_IMAGE:-anchore/syft:latest}"
MOUNT_DIR="${SYFT_MOUNT_DIR:-$(pwd)}"

exec docker run --rm \
  -v "${MOUNT_DIR}:/work:ro" \
  "${IMAGE}" "$@"
