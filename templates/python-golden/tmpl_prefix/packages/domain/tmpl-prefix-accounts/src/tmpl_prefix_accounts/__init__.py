"""Accounts domain model, repository port, service, and runtime component."""

from __future__ import annotations

from tmpl_prefix_accounts.component import (
    AccountsComponent,
)
from tmpl_prefix_accounts.model import (
    Account,
    AccountId,
    AccountStatus,
    Email,
    parse_account_id,
    parse_email,
)
from tmpl_prefix_accounts.port import (
    AccountRepository,
)
from tmpl_prefix_accounts.service import (
    AccountService,
)

__all__ = [
    "Account",
    "AccountId",
    "AccountRepository",
    "AccountService",
    "AccountStatus",
    "AccountsComponent",
    "Email",
    "parse_account_id",
    "parse_email",
]
