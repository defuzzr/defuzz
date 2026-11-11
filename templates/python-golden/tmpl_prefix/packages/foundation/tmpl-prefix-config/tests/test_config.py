"""Unit tests for the workspace layered settings."""

from __future__ import annotations

import pytest

from tmpl_prefix_config import (
    ENV_PREFIX,
    Settings,
    load_settings,
)
from tmpl_prefix_config.settings import (
    TmplPrefixSettings,
)
from tmpl_prefix_core import AppError


def test_default_settings() -> None:
    """Verify default configuration values when no overrides are present."""
    settings = load_settings({})
    assert isinstance(settings, Settings)
    assert isinstance(
        settings,
        TmplPrefixSettings,
    )
    assert settings.environment == "development"
    expected_service = "tmpl-prefix-service"
    assert settings.service_name == expected_service
    assert settings.http.host == "127.0.0.1"
    assert settings.http.port == 8080
    assert settings.http.adapter == "fastapi"
    assert settings.log.level == "INFO"


def test_load_settings_with_nested_env_overrides() -> None:
    """Verify nested delimiter parsing via explicit env dictionary."""
    service_name = "tmpl-prefix-api"
    env = {
        f"{ENV_PREFIX}ENVIRONMENT": "production",
        f"{ENV_PREFIX}SERVICE_NAME": service_name,
        f"{ENV_PREFIX}HTTP__HOST": "127.0.0.2",
        f"{ENV_PREFIX}HTTP__PORT": "9090",
        f"{ENV_PREFIX}HTTP__ADAPTER": "stdlib",
        f"{ENV_PREFIX}LOG__LEVEL": "DEBUG",
        "UNRELATED_ENV_VAR": "ignored",
    }
    settings = load_settings(env)
    assert settings.environment == "production"
    expected_service = "tmpl-prefix-api"
    assert settings.service_name == expected_service
    assert settings.http.host == "127.0.0.2"
    assert settings.http.port == 9090
    assert settings.http.adapter == "stdlib"
    assert settings.log.level == "DEBUG"


def test_load_settings_lists_every_invalid_field_on_error() -> None:
    """Verify invalid fields are aggregated into one config AppError."""
    env = {
        f"{ENV_PREFIX}HTTP__PORT": "not-a-number",
        f"{ENV_PREFIX}HTTP__ADAPTER": "invalid-adapter",
        f"{ENV_PREFIX}LOG__LEVEL": "NO_SUCH_LEVEL",
    }
    with pytest.raises(AppError) as exc_info:
        load_settings(env)

    err = exc_info.value
    assert err.kind == "config"
    assert "http.port" in err.message
    assert "http.adapter" in err.message
    assert "log.level" in err.message
    fields = err.details.get("fields")
    assert isinstance(fields, list)
    assert "http.port" in fields
    assert "http.adapter" in fields
    assert "log.level" in fields


def test_load_settings_rejects_unknown_extra_keys() -> None:
    """Verify extra='forbid' rejects unknown configuration keys."""
    env = {
        f"{ENV_PREFIX}UNKNOWN_KEY": "surprise",
    }
    with pytest.raises(AppError) as exc_info:
        load_settings(env)
    assert exc_info.value.kind == "config"
    assert "unknown_key" in exc_info.value.message
