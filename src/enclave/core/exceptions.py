"""Typed errors. Each carries a machine-readable code and a human-readable message."""

from __future__ import annotations


class EnclaveError(Exception):
    code = "enclave_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConfigError(EnclaveError):
    code = "config_invalid"


class IngestError(EnclaveError):
    code = "ingest_failed"


class UnsupportedCaptureError(IngestError):
    code = "capture_unsupported"


class ParseError(IngestError):
    code = "parse_failed"


class ModelIntegrityError(EnclaveError):
    """A model or intelligence file does not match its recorded SHA-256."""

    code = "model_integrity"


class EgressAttemptError(EnclaveError):
    """Raised if any component tries to open a connection outside the enclave."""

    code = "egress_forbidden"
