"""Domain service orchestrating account registration and lifecycle rules."""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import TYPE_CHECKING

from tmpl_prefix_accounts.model import (
    Account,
    AccountId,
    parse_account_id,
    parse_email,
)
from tmpl_prefix_core import AppError

if TYPE_CHECKING:
    from tmpl_prefix_accounts.port import (
        AccountRepository,
    )


class AccountService:
    """Pure domain service enforcing account invariants over an AccountRepository."""

    def __init__(self, repo: AccountRepository) -> None:
        """Initialize the service with a repository port implementation."""
        self._repo = repo

    async def register(
        self,
        email: str,
        display_name: str,
        *,
        account_id: str | None = None,
    ) -> Account:
        """Register a new active account.

        Args:
            email: Raw email address string.
            display_name: Human-readable display name.
            account_id: Optional explicit account ID (auto-generated if omitted).

        Returns:
            Newly created ``Account``.

        Raises:
            AppError: If input is invalid (``invalid_input``) or email is taken (``conflict``).
        """
        validated_email = parse_email(email)
        cleaned_name = display_name.strip()
        if not cleaned_name:
            raise AppError(
                kind="invalid_input",
                message="Display name must not be empty",
                details={"field": "display_name"},
            )

        existing = await self._repo.find_by_email(validated_email)
        if existing is not None:
            raise AppError(
                kind="conflict",
                message=f"Account with email '{validated_email}' already exists",
                details={"email": validated_email, "existing_id": existing.id},
            )

        resolved_id = (
            parse_account_id(account_id)
            if account_id is not None
            else AccountId(f"acc-{uuid.uuid4().hex[:12]}")
        )
        account = Account(
            id=resolved_id,
            email=validated_email,
            display_name=cleaned_name,
            status="active",
        )
        await self._repo.save(account)
        return account

    async def get(self, account_id: AccountId | str) -> Account:
        """Retrieve an account by ID or raise a not_found AppError."""
        resolved_id = parse_account_id(str(account_id))
        account = await self._repo.find_by_id(resolved_id)
        if account is None:
            raise AppError(
                kind="not_found",
                message=f"Account '{resolved_id}' not found",
                details={"account_id": resolved_id},
            )
        return account

    async def deactivate(self, account_id: AccountId | str) -> Account:
        """Transition an existing account to deactivated status."""
        current = await self.get(account_id)
        updated = replace(current, status="deactivated")
        await self._repo.save(updated)
        return updated

    async def list_active(self) -> list[Account]:
        """Return all currently active accounts."""
        all_accounts = await self._repo.list_all()
        return [acct for acct in all_accounts if acct.status == "active"]


TmplPrefixAccountService = AccountService
