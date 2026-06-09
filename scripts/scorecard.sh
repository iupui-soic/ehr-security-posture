#!/usr/bin/env bash
# Wrapper that runs OpenSSF Scorecard via its official Docker image so no Go
# toolchain is needed on the host. All args are passed through, e.g.:
#   scripts/scorecard.sh --repo=github.com/openmrs/openmrs-core --format=json
# Requires GITHUB_TOKEN (or GITHUB_AUTH_TOKEN) in the environment.
set -euo pipefail

IMAGE="${SCORECARD_IMAGE:-gcr.io/openssf/scorecard:stable}"
TOKEN="${GITHUB_AUTH_TOKEN:-${GITHUB_TOKEN:-}}"

if [[ -z "${TOKEN}" ]]; then
  echo "scorecard.sh: GITHUB_TOKEN / GITHUB_AUTH_TOKEN not set" >&2
  exit 1
fi

# --rm: ephemeral; pass the token via env, never on the command line.
exec docker run --rm \
  -e "GITHUB_AUTH_TOKEN=${TOKEN}" \
  "${IMAGE}" "$@"
