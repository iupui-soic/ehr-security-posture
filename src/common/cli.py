"""Shared command-line flags for pipeline modules."""
from __future__ import annotations

import argparse


def parse_common_args(description: str = "") -> argparse.Namespace:
    p = argparse.ArgumentParser(description=description)
    p.add_argument(
        "--refresh",
        action="store_true",
        help="re-fetch even if a dated raw response already exists (default: skip)",
    )
    p.add_argument(
        "--only",
        metavar="SYSTEM_ID",
        default=None,
        help="restrict to a single system id (e.g. openmrs) for debugging",
    )
    return p.parse_args()
