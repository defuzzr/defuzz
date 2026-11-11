"""In-memory implementation of the AccountRepository port.

Production persistence adapters in ``packages/adapters/`` implement the same
``AccountRepository`` protocol from the accounts package by opting into the workspace
catalogue entries ``asyncpg>=0.30,<1`` and ``sqlalchemy>=2.0,<3`` and wiring the
new adapter in ``tmpl_prefix_server.wiring``.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from tmpl_prefix_accounts import (
    Account,
    AccountId,
    AccountRepository,
    Email,
)
from tmpl_prefix_core import AppError

if TYPE_CHECKING:
    from collections.abc import Sequence


class InMemoryAccountRepository(AccountRepository):
    """Concurrency-safe dict-backed implementation of ``AccountRepository``."""

    def __init__(self) -> None:
        """Initialize an empty repository with an asyncio lock."""
        self._lock = asyncio.Lock()
        self._by_id: dict[AccountId, Account] = {}

    async def save(self, account: Account) -> None:
        """Save an account while enforcing email uniqueness across distinct IDs."""
        async with self._lock:
            for existing_id, existing in self._by_id.items():
                if existing.email == account.email and existing_id != account.id:
                    msg = f"Email '{account.email}' is already bound to account '{existing_id}'"
                    raise AppError(
                        kind="conflict",
                        message=msg,
                        details={
                            "email": account.email,
                            "existing_id": existing_id,
                            "account_id": account.id,
                        },
                    )
            self._by_id[account.id] = account

    async def find_by_id(self, account_id: AccountId) -> Account | None:
        """Return the account matching ``account_id`` if present."""
        async with self._lock:
            return self._by_id.get(account_id)

    async def find_by_email(self, email: Email) -> Account | None:
        """Return the account matching ``email`` if present."""
        async with self._lock:
            for account in self._by_id.values():
                if account.email == email:
                    return account
            return None

    async def list_all(self) -> Sequence[Account]:
        """Return a snapshot list of all stored accounts."""
        async with self._lock:
            return list(self._by_id.values())


TmplPrefixInMemoryAccountRepository = (
    # Public prefixed alias for the stable implementation.
    InMemoryAccountRepository
)
