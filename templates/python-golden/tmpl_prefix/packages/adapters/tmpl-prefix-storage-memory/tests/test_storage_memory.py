"""Unit tests for the workspace adapter."""

from __future__ import annotations

import pytest

from tmpl_prefix_accounts import (
    Account,
    AccountId,
    AccountRepository,
    parse_email,
)
from tmpl_prefix_core import AppError
from tmpl_prefix_storage_memory import (
    InMemoryAccountRepository,
)
from tmpl_prefix_storage_memory import (
    repository as r,
)


async def test_in_memory_repository_crud_and_duplicate_email_rejection() -> None:
    """Verify save, lookup, list_all, and duplicate email conflict detection."""
    repository_type = (
        # Exercise the public prefixed alias.
        r.TmplPrefixInMemoryAccountRepository
    )
    repo = repository_type()
    assert isinstance(repo, InMemoryAccountRepository)
    assert isinstance(repo, AccountRepository)

    acct_1 = Account(
        id=AccountId("acc-1"),
        email=parse_email("one@example.com"),
        display_name="User One",
    )
    await repo.save(acct_1)

    found_id = await repo.find_by_id(AccountId("acc-1"))
    assert found_id == acct_1

    found_email = await repo.find_by_email(parse_email("ONE@example.com"))
    assert found_email == acct_1

    # Updating the same account ID with the same email succeeds.
    updated_1 = Account(
        id=AccountId("acc-1"),
        email=parse_email("one@example.com"),
        display_name="User One Updated",
        status="deactivated",
    )
    await repo.save(updated_1)
    assert await repo.find_by_id(AccountId("acc-1")) == updated_1

    # Saving a different account ID with the same email raises conflict.
    acct_2_dup = Account(
        id=AccountId("acc-2"),
        email=parse_email("one@example.com"),
        display_name="Duplicate Email User",
    )
    with pytest.raises(AppError) as exc_info:
        await repo.save(acct_2_dup)
    assert exc_info.value.kind == "conflict"

    all_items = await repo.list_all()
    assert list(all_items) == [updated_1]
