"""Accounts domain value objects and entities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, NewType

from tmpl_prefix_core import AppError

AccountId = NewType("AccountId", str)
Email = NewType("Email", str)
AccountStatus = Literal["active", "deactivated"]


def parse_account_id(raw: str) -> AccountId:
    """Validate and normalize an account identifier.

    Args:
        raw: Candidate account identifier string.

    Returns:
        Validated ``AccountId``.

    Raises:
        AppError: With ``kind="invalid_input"`` if the identifier is blank.
    """
    cleaned = raw.strip()
    if not cleaned:
        raise AppError(
            kind="invalid_input",
            message="Account ID must not be empty",
            details={"field": "account_id"},
        )
    return AccountId(cleaned)


def parse_email(raw: str) -> Email:
    """Validate and normalize an email address.

    Args:
        raw: Candidate email string.

    Returns:
        Lowercase validated ``Email``.

    Raises:
        AppError: With ``kind="invalid_input"`` if the email address is malformed.
    """
    cleaned = raw.strip().lower()
    local, sep, domain = cleaned.partition("@")
    if (
        not sep
        or "@" in domain
        or not local
        or not domain
        or "." not in domain
        or domain.startswith(".")
        or domain.endswith(".")
    ):
        raise AppError(
            kind="invalid_input",
            message=f"Invalid email address: '{raw}'",
            details={"field": "email", "value": raw},
        )
    return Email(cleaned)


@dataclass(frozen=True, slots=True)
class Account:
    """Immutable domain entity representing a registered user account."""

    id: AccountId
    email: Email
    display_name: str
    status: AccountStatus = "active"


TmplPrefixAccount = Account
