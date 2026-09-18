"""Offline threat-intelligence lists, verified against a SHA-256 manifest before use.

The enclave never fetches intelligence. Lists arrive through an approved one-way
transfer together with `manifest.json`; a mismatch refuses to load.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from enclave.core.exceptions import ModelIntegrityError
from enclave.core.logging import get_logger

log = get_logger(__name__)

MANIFEST = "manifest.json"
JA3_FILE = "ja3_blocklist.txt"
JA4_FILE = "ja4_blocklist.txt"
DOMAIN_FILE = "domain_blocklist.txt"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entries(path: Path) -> frozenset[str]:
    if not path.is_file():
        return frozenset()
    values = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        token = line.split("#", 1)[0].strip().split()
        if token:
            values.add(token[0].lower())
    return frozenset(values)


@dataclass(frozen=True)
class Intel:
    ja3: frozenset[str] = field(default_factory=frozenset)
    ja4: frozenset[str] = field(default_factory=frozenset)
    domains: frozenset[str] = field(default_factory=frozenset)
    source: str = "none"

    @classmethod
    def load(cls, directory: Path) -> Intel:
        manifest_path = directory / MANIFEST
        if not manifest_path.is_file():
            log.warning("no intelligence manifest; running without blocklists",
                        extra={"intel_dir": str(directory)})
            return cls()
        manifest: dict[str, str] = json.loads(manifest_path.read_text(encoding="utf-8"))["files"]
        for name, expected in manifest.items():
            actual = _sha256(directory / name)
            if actual != expected:
                raise ModelIntegrityError(f"{name} hash {actual[:12]}… does not match manifest")
        intel = cls(
            ja3=_entries(directory / JA3_FILE),
            ja4=_entries(directory / JA4_FILE),
            domains=_entries(directory / DOMAIN_FILE),
            source=f"{directory} ({len(manifest)} files verified)",
        )
        log.info("intelligence loaded", extra={"ja3": len(intel.ja3), "ja4": len(intel.ja4),
                                               "domains": len(intel.domains)})
        return intel


def write_manifest(directory: Path) -> Path:
    files = {
        p.name: _sha256(p)
        for p in sorted(directory.iterdir())
        if p.is_file() and p.name != MANIFEST
    }
    path = directory / MANIFEST
    path.write_text(json.dumps({"files": files}, indent=2) + "\n", encoding="utf-8")
    return path
