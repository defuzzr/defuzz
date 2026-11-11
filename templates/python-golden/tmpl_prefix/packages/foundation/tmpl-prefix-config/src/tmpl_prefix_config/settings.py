"""Settings models and environment loader built on pydantic-settings."""

from __future__ import annotations

from contextvars import ContextVar
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from tmpl_prefix_core import AppError

if TYPE_CHECKING:
    from collections.abc import Mapping

HttpAdapter = Literal["fastapi", "stdlib"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
EnvironmentName = Literal["development", "staging", "production", "test"]

ENV_PREFIX: str = "TMPL_PREFIX_"
ENV_DELIMITER: str = "__"

_ENV_OVERRIDE: ContextVar[Mapping[str, str] | None] = ContextVar(
    "_ENV_OVERRIDE",
    default=None,
)


class HttpSettings(BaseModel):
    """HTTP server binding and adapter selection settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=0, le=65535)
    adapter: HttpAdapter = "fastapi"


class LogSettings(BaseModel):
    """Structured logging configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    level: LogLevel = "INFO"


class Settings(BaseSettings):
    """Root application settings loaded from defaults, .env, and environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="TMPL_PREFIX_",
        env_nested_delimiter="__",
        env_file=".env",
        extra="forbid",
        frozen=True,
    )

    environment: EnvironmentName = "development"
    service_name: str = "tmpl-prefix-service"
    http: HttpSettings = HttpSettings()
    log: LogSettings = LogSettings()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Use only explicit init kwargs when an in-memory env mapping is supplied."""
        _ = settings_cls
        if _ENV_OVERRIDE.get() is not None:
            return (init_settings,)
        return (init_settings, env_settings, dotenv_settings, file_secret_settings)


def _parse_env_mapping(env: Mapping[str, str]) -> dict[str, object]:
    """Extract prefixed environment keys into a nested dictionary."""
    root: dict[str, object] = {}
    prefix_upper = ENV_PREFIX.upper()
    for raw_key, value in env.items():
        key_upper = raw_key.upper()
        if not key_upper.startswith(prefix_upper):
            continue
        stripped = key_upper[len(prefix_upper) :].lower()
        if not stripped:
            continue
        parts = [part for part in stripped.split(ENV_DELIMITER) if part]
        if not parts:
            continue
        cursor: dict[str, object] = root
        for part in parts[:-1]:
            existing = cursor.get(part)
            if not isinstance(existing, dict):
                nested: dict[str, object] = {}
                cursor[part] = nested
                cursor = nested
            else:
                cursor = existing
        cursor[parts[-1]] = value
    return root


def _format_validation_error(exc: ValidationError) -> AppError:
    """Convert a Pydantic ValidationError into a structured config AppError."""
    invalid_fields: list[str] = []
    error_items: list[dict[str, str]] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"])
        msg = err["msg"]
        invalid_fields.append(loc)
        error_items.append({"field": loc, "message": msg, "type": err["type"]})

    fields_summary = ", ".join(invalid_fields)
    return AppError(
        kind="config",
        message=f"Invalid configuration for field(s): {fields_summary}",
        cause=exc,
        details={
            "fields": invalid_fields,
            "errors": error_items,
        },
    )


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Load and validate application settings.

    Args:
        env: Optional explicit environment variable mapping for deterministic
            testing without reading or mutating ``os.environ``.

    Returns:
        Validated ``Settings`` object.

    Raises:
        AppError: With ``kind="config"`` listing every invalid field if validation fails.
    """
    try:
        if env is None:
            return Settings()
        parsed = _parse_env_mapping(env)
        token = _ENV_OVERRIDE.set(env)
        try:
            return Settings.model_validate(parsed)
        finally:
            _ENV_OVERRIDE.reset(token)
    except ValidationError as exc:
        raise _format_validation_error(exc) from exc


TmplPrefixHttpSettings = HttpSettings
TmplPrefixLogSettings = LogSettings
TmplPrefixSettings = Settings
