"""Repo-identifier parsing shared across acquire modules.

``config/systems.yaml`` lists repos in two shapes:
  * GitHub:   ``owner/name``                      (host implied = github.com)
  * Codeberg: ``codeberg.org/owner/name``         (host explicit)

This module normalises them and derives the forms each tool needs (clone URL,
Scorecard target, API path, a filesystem-safe slug for raw filenames).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Repo:
    host: str          # github.com | codeberg.org
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def host_full(self) -> str:
        return f"{self.host}/{self.owner}/{self.name}"

    @property
    def slug(self) -> str:
        """Filesystem-safe id for raw/interim filenames."""
        return f"{self.host}__{self.owner}__{self.name}".replace(".", "_")

    @property
    def clone_url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.name}.git"

    @property
    def scorecard_target(self) -> str:
        # Scorecard supports github.com (and gitlab.com); Gitea/Codeberg is not
        # a supported remote -> caller marks those checks not_assessable.
        return self.host_full

    @property
    def is_github(self) -> bool:
        return self.host == "github.com"

    @property
    def is_codeberg(self) -> bool:
        return self.host == "codeberg.org"


_KNOWN_HOSTS = {"github.com", "codeberg.org", "gitlab.com"}


def parse_repo(repo_str: str) -> Repo:
    s = repo_str.strip().strip("/")
    if s.startswith("http://") or s.startswith("https://"):
        s = s.split("://", 1)[1]
    if s.endswith(".git"):
        s = s[:-4]
    parts = s.split("/")
    if parts[0] in _KNOWN_HOSTS:
        host = parts[0]
        owner, name = parts[1], parts[2]
    else:
        # bare owner/name -> default to GitHub
        host = "github.com"
        owner, name = parts[0], parts[1]
    return Repo(host=host, owner=owner, name=name)
