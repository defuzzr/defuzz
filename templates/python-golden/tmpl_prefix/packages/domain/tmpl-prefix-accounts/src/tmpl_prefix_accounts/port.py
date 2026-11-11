"""Repository port for persisting and querying accounts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from tmpl_prefix_accounts.model import (
        Account,
        AccountId,
        Email,
    )


@runtime_checkable
class AccountRepository(Protocol):
    """Outbound persistence port for ``Account`` entities."""

    async def save(self, account: Account) -> None:
        """Persist a new or updated account."""
        ...

    async def find_by_id(self, account_id: AccountId) -> Account | None:
        """Look up an account by its unique identifier."""
        ...

    async def find_by_email(self, email: Email) -> Account | None:
        """Look up an account by its normalized email address."""
        ...

    async def list_all(self) -> Sequence[Account]:
        """Return all stored accounts in deterministic order."""
        ...


TmplPrefixAccountRepository = (
    # Public prefixed alias for the stable implementation.
    AccountRepository
)
