"""Argparse command-line interface wired against the accounts domain service."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import TYPE_CHECKING

from tmpl_prefix_accounts import (
    AccountsComponent,
    AccountService,
)
from tmpl_prefix_cli.cli.output import (
    emit_error,
    emit_json,
)
from tmpl_prefix_config import load_settings
from tmpl_prefix_core import (
    AppError,
    Context,
    Registry,
)
from tmpl_prefix_storage_memory import (
    InMemoryAccountRepository,
)
from tmpl_prefix_telemetry import (
    init as init_logger,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


class TmplPrefixCliRunner:
    """Stateful CLI execution harness sharing an account service and registry."""

    def __init__(self, *, env: Mapping[str, str] | None = None) -> None:
        """Initialize the CLI runner with settings, repository, and service."""
        self._settings = load_settings(env)
        self._logger = init_logger(
            level=self._settings.log.level,
            service_name=self._settings.service_name,
        )
        self._context = Context(
            environment=self._settings.environment,
            service_name=self._settings.service_name,
            logger=self._logger,
        )
        self._repo = InMemoryAccountRepository()
        self._service = AccountService(self._repo)
        self._registry = Registry()
        self._registry.register(AccountsComponent(self._service))

    async def execute(self, argv: Sequence[str]) -> int:
        """Parse and execute a single CLI command."""
        parser = _build_parser()
        args = parser.parse_args(list(argv))

        try:
            await self._registry.start(self._context)
            try:
                if args.command == "health":
                    report = await self._registry.report()
                    emit_json(report)
                    return 0 if self._registry.is_serving() else 1

                if args.command == "accounts":
                    if args.accounts_command == "register":
                        acct = await self._service.register(args.email, args.name)
                        emit_json(
                            {
                                "id": acct.id,
                                "email": acct.email,
                                "display_name": acct.display_name,
                                "status": acct.status,
                            },
                        )
                        return 0
                    if args.accounts_command == "list":
                        active = await self._service.list_active()
                        emit_json(
                            {
                                "accounts": [
                                    {
                                        "id": acct.id,
                                        "email": acct.email,
                                        "display_name": acct.display_name,
                                        "status": acct.status,
                                    }
                                    for acct in active
                                ],
                            },
                        )
                        return 0
            finally:
                await self._registry.stop()
        except AppError as exc:
            emit_error(exc.to_dict())
            return 1

        return 1


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level and subcommand argument parsers."""
    prog_name = "tmpl_prefix".replace("_", "-")
    parser = argparse.ArgumentParser(
        prog=prog_name,
        description="Workspace administration interface.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("health", help="Inspect component registry health.")

    accounts_parser = subparsers.add_parser("accounts", help="Manage user accounts.")
    accounts_sub = accounts_parser.add_subparsers(
        dest="accounts_command",
        required=True,
    )

    register_parser = accounts_sub.add_parser(
        "register",
        help="Register a new active account.",
    )
    register_parser.add_argument("email", help="Account email address.")
    register_parser.add_argument("name", help="Account display name.")

    accounts_sub.add_parser("list", help="List all active accounts.")
    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    runner: TmplPrefixCliRunner | None = None,
) -> int:
    """Run the CLI with the given arguments and return an exit code."""
    active_runner = runner
    if active_runner is None:
        active_runner = TmplPrefixCliRunner(
            env=env,
        )
    args_list = list(argv) if argv is not None else []
    return asyncio.run(active_runner.execute(args_list))


def main() -> None:
    """Console script entrypoint."""
    sys.exit(run(sys.argv[1:]))
