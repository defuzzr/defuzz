"""Unit tests for the workspace using an inline fake repository."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tmpl_prefix_accounts import (
    Account,
    AccountId,
    AccountRepository,
    AccountsComponent,
    AccountService,
    Email,
)
from tmpl_prefix_accounts.component import (
    TmplPrefixAccountsComponent,
)
from tmpl_prefix_accounts.service import (
    TmplPrefixAccountService,
)
from tmpl_prefix_core import AppError, Context

if TYPE_CHECKING:
    from collections.abc import Sequence


class _NoopLogger:
    """Minimal logger double for component tests."""

    def debug(self, message: str, **fields: object) -> None:
        _ = (message, fields)

    def info(self, message: str, **fields: object) -> None:
        _ = (message, fields)

    def warning(self, message: str, **fields: object) -> None:
        _ = (message, fields)

    def error(self, message: str, **fields: object) -> None:
        _ = (message, fields)

    def bind(self, **fields: object) -> _NoopLogger:
        _ = fields
        return self


class _FakeAccountRepository(AccountRepository):
    """Inline fake repository for domain unit tests."""

    def __init__(self) -> None:
        self._items: dict[AccountId, Account] = {}

    async def save(self, account: Account) -> None:
        self._items[account.id] = account

    async def find_by_id(self, account_id: AccountId) -> Account | None:
        return self._items.get(account_id)

    async def find_by_email(self, email: Email) -> Account | None:
        for acct in self._items.values():
            if acct.email == email:
                return acct
        return None

    async def list_all(self) -> Sequence[Account]:
        return list(self._items.values())


async def test_register_get_deactivate_and_list_active() -> None:
    """Verify full account lifecycle through AccountService."""
    repo = _FakeAccountRepository()
    svc = TmplPrefixAccountService(repo)
    assert isinstance(svc, AccountService)

    alice = await svc.register("Alice@Example.com", "Alice Smith", account_id="acc-1")
    bob = await svc.register("bob@example.com", "Bob Jones", account_id="acc-2")

    assert alice.email == "alice@example.com"
    assert alice.status == "active"

    fetched = await svc.get("acc-1")
    assert fetched == alice

    deactivated = await svc.deactivate("acc-2")
    assert deactivated.status == "deactivated"

    active = await svc.list_active()
    assert active == [alice]
    _ = bob


async def test_register_rejects_duplicate_email_and_invalid_input() -> None:
    """Verify domain error kinds for duplicate email, bad email, and blank name."""
    repo = _FakeAccountRepository()
    svc = AccountService(repo)
    await svc.register("user@example.com", "First User")

    with pytest.raises(AppError) as dup_exc:
        await svc.register("USER@example.com", "Second User")
    assert dup_exc.value.kind == "conflict"

    with pytest.raises(AppError) as bad_email:
        await svc.register("not-an-email", "Valid Name")
    assert bad_email.value.kind == "invalid_input"

    with pytest.raises(AppError) as bad_name:
        await svc.register("valid@example.com", "   ")
    assert bad_name.value.kind == "invalid_input"

    with pytest.raises(AppError) as missing:
        await svc.get("nonexistent")
    assert missing.value.kind == "not_found"


async def test_accounts_component_lifecycle() -> None:
    """Verify AccountsComponent reports health accurately before and after start."""
    svc = AccountService(_FakeAccountRepository())
    comp = TmplPrefixAccountsComponent(svc)
    assert isinstance(comp, AccountsComponent)
    assert comp.name == "accounts"
    assert comp.service is svc

    before = await comp.health()
    assert before.status == "unhealthy"

    ctx = Context(
        environment="test",
        service_name="tmpl-prefix-test",
        logger=_NoopLogger(),
    )
    await comp.start(ctx)
    during = await comp.health()
    assert during.status == "healthy"

    await comp.stop()
    after = await comp.health()
    assert after.status == "unhealthy"
