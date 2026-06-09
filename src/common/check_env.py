"""Pre-flight check for the acquire stage: credentials + snapshot validity.

Run via ``make check-env`` (a prerequisite of ``make acquire``). Exits non-zero
if a required credential or the snapshot date is missing, so the pipeline fails
loudly rather than silently producing rate-limited / empty data.
"""
from __future__ import annotations

import os
import sys

from . import config
from .logging import get_logger

log = get_logger("check_env")


def main() -> int:
    snap = config.load_snapshot()
    ok = True

    if snap.date in ("", "TBD"):
        log.error("snapshot_date is unset (TBD) in config/snapshot.yaml")
        ok = False
    else:
        log.info("snapshot_date = %s", snap.date)

    for var in snap.required_env:
        # GITHUB_AUTH_TOKEN is an accepted alias for GITHUB_TOKEN.
        present = bool(os.environ.get(var) or
                       (var == "GITHUB_TOKEN" and os.environ.get("GITHUB_AUTH_TOKEN")))
        if present:
            log.info("required env %s: set", var)
        else:
            log.error("required env %s: MISSING (copy .env.example -> .env)", var)
            ok = False

    for var in snap.optional_env:
        log.info("optional env %s: %s", var, "set" if os.environ.get(var) else "(unset)")

    log.info("systems in sample: %s", ", ".join(s.id for s in config.load_systems()))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
