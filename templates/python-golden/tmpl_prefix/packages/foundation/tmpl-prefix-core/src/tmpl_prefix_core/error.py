"""Structured application error taxonomy."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Mapping

ErrorKind = Literal[
    "invalid_input",
    "not_found",
    "conflict",
    "config",
    "unavailable",
    "internal",
]


class AppError(Exception):
    """Structured error carrying a machine-readable kind and serializable details."""

    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        *,
        cause: Exception | None = None,
        details: Mapping[str, object] | None = None,
    ) -> None:
        """Initialize an application error.

        Args:
            kind: Machine-readable error category.
            message: Human-readable summary of the error.
            cause: Optional underlying exception that triggered this error.
            details: Optional structured key-value context for diagnostics.
        """
        super().__init__(message)
        self.kind: ErrorKind = kind
        self.message: str = message
        self.cause: Exception | None = cause
        self.details: dict[str, object] = dict(details) if details is not None else {}

    def __str__(self) -> str:
        """Format the error with its kind prefix."""
        if self.cause is not None:
            return f"[{self.kind}] {self.message} (caused by: {self.cause})"
        return f"[{self.kind}] {self.message}"

    def to_dict(self) -> dict[str, object]:
        """Serialize the error into a JSON-compatible dictionary."""
        payload: dict[str, object] = {
            "kind": self.kind,
            "message": self.message,
            "details": dict(self.details),
        }
        if self.cause is not None:
            payload["cause"] = str(self.cause)
        return payload


TmplPrefixError = AppError
