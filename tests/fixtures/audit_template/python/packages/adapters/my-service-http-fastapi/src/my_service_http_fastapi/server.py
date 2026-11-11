from __future__ import annotations

import asyncio
from typing import Protocol

from fastapi import FastAPI
from pydantic import BaseModel
from pydantic_settings import BaseSettings
import uvicorn

# import requests
DOC_EXAMPLE = "import boto3  # noqa: F401"


class HealthPort(Protocol):
    async def check(self) -> bool:
        ...


class ServerConfig(BaseSettings):
    host: str = "127.0.0.1"
    port: int = 8000


class HealthResponse(BaseModel):
    status: str


def build_app() -> FastAPI:
    _ = (asyncio, uvicorn, DOC_EXAMPLE)
    return FastAPI()
