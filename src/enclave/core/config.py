"""Run-time configuration, validated at the boundary before anything starts."""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field, IPvAnyAddress, IPvAnyNetwork, ValidationError, field_validator

from enclave.core.constants import (
    ASSET_DEFAULT_CRITICALITY,
    ASSET_MAX_CRITICALITY,
    ASSET_MIN_CRITICALITY,
)
from enclave.core.exceptions import ConfigError


class AssetEntry(BaseModel):
    ip: IPvAnyAddress
    name: Annotated[str, Field(min_length=1, max_length=120)]
    zone: Annotated[str, Field(min_length=1, max_length=40)]
    criticality: Annotated[int, Field(ge=ASSET_MIN_CRITICALITY, le=ASSET_MAX_CRITICALITY)]


class Settings(BaseModel):
    sensor_id: Annotated[str, Field(min_length=1, max_length=64)] = "enclave-sensor-01"
    internal_networks: list[IPvAnyNetwork] = Field(
        default_factory=lambda: [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12",
                                                                   "192.168.0.0/16")]
    )
    assets: list[AssetEntry] = Field(default_factory=list)
    allowlist: list[IPvAnyAddress] = Field(default_factory=list)
    intel_dir: Path = Path("intel")
    alert_log: Path = Path("var/alerts.jsonl")
    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def _level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR"}
        if value.upper() not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return value.upper()

    @classmethod
    def load(cls, path: Path | None) -> Settings:
        if path is None:
            return cls()
        try:
            return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError as exc:
            raise ConfigError(f"Config file not found: {path}") from exc
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ConfigError(f"Config file {path} is invalid: {exc}") from exc


class NetworkContext:
    """Answers 'is this address ours / how critical / allowlisted?' quickly."""

    def __init__(self, settings: Settings) -> None:
        self._networks = list(settings.internal_networks)
        self._assets = {str(a.ip): a for a in settings.assets}
        self._allow = {str(ip) for ip in settings.allowlist}
        self.is_internal = lru_cache(maxsize=65_536)(self._is_internal)

    def _is_internal(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr.version == net.version and addr in net for net in self._networks)

    def asset(self, ip: str) -> AssetEntry | None:
        return self._assets.get(ip)

    def criticality(self, ip: str) -> int:
        asset = self._assets.get(ip)
        return asset.criticality if asset else ASSET_DEFAULT_CRITICALITY

    def is_allowlisted(self, *ips: str) -> bool:
        return any(ip in self._allow for ip in ips)
