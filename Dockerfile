# =============================================================================
# Dockerfile — fully self-contained pipeline image (reproducibility artifact).
#
# On the dev host we instead run python via a venv and scorecard/syft via their
# official images (see scripts/scorecard.sh, scripts/syft.sh) because no Go
# toolchain is installed. This image bakes everything into one place so the
# pipeline is reproducible from a clean machine. Pin versions to match
# config/snapshot.yaml.
# =============================================================================
ARG SCORECARD_VERSION=stable
ARG SYFT_VERSION=latest

FROM gcr.io/openssf/scorecard:${SCORECARD_VERSION} AS scorecard
FROM anchore/syft:${SYFT_VERSION} AS syft

FROM python:3.11-slim

# scorecard + syft are static binaries; lift them out of their distroless images.
COPY --from=scorecard /scorecard /usr/local/bin/scorecard
COPY --from=syft /syft /usr/local/bin/syft

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip install --no-cache-dir -e .

COPY . .

ENTRYPOINT ["make"]
CMD ["help"]
