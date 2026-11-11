"""Runtime lifecycle component wrapping the accounts domain service."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tmpl_prefix_core import (
    Component,
    Context,
    Health,
)

if TYPE_CHECKING:
    from tmpl_prefix_accounts.service import (
        AccountService,
    )


class AccountsComponent(Component):
    """Runtime lifecycle component for the accounts domain module."""

    def __init__(self, service: AccountService) -> None:
        """Initialize the component with its domain service."""
        self._service = service
        self._started = False

    @property
    def name(self) -> str:
        """Return the unique component name."""
        return "accounts"

    @property
    def service(self) -> AccountService:
        """Return the underlying AccountService."""
        return self._service

    async def start(self, ctx: Context) -> None:
        """Mark the accounts component as started."""
        ctx.logger.info("accounts component started", component=self.name)
        self._started = True

    async def stop(self) -> None:
        """Mark the accounts component as stopped."""
        self._started = False

    async def health(self) -> Health:
        """Return healthy when started, unhealthy otherwise."""
        if not self._started:
            return Health(status="unhealthy", reason="accounts component not started")
        return Health(status="healthy")


TmplPrefixAccountsComponent = (
    # Public prefixed alias for the stable implementation.
    AccountsComponent
)
