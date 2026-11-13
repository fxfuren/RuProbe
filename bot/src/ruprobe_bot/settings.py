"""Настройки бота: читаются из окружения через pydantic-settings."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Конфигурация процесса бота.

    Значения по умолчанию рассчитаны на запуск внутри docker-сети: агент
    доступен по имени сервиса, база лежит на volume.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    bot_token: str = Field(default="", alias="BOT_TOKEN")
    agent_url: str = Field(default="http://agent:8080", alias="AGENT_URL")
    db_path: Path = Field(default=Path("/data/ruprobe.sqlite3"), alias="DB_PATH")

    # Точка наблюдения. По docs/tspu-model.md это первичный ключ измерения,
    # а не метаданные, поэтому значения обязательны и хранятся отдельной строкой.
    region: str = Field(default="default", alias="REGION")
    operator: str = Field(default="default", alias="OPERATOR")
    observation_name: str = Field(default="local agent", alias="OBSERVATION_NAME")

    # Сколько ждать готовности задания и как часто опрашивать агент.
    poll_interval_s: float = Field(default=1.5, alias="POLL_INTERVAL_S")
    poll_timeout_s: float = Field(default=600.0, alias="POLL_TIMEOUT_S")
    agent_timeout_ms: int = Field(default=5000, alias="AGENT_TIMEOUT_MS")
    throughput_bytes: int = Field(default=1 << 20, alias="THROUGHPUT_BYTES")

    # Прогресс через черновик: черновик живёт 30 секунд, поэтому обновляем чаще.
    draft_interval_s: float = Field(default=4.0, alias="DRAFT_INTERVAL_S")

    # Ограничения rich-сообщений из docs/stack.md: 32768 символов, 500 блоков.
    max_rich_chars: int = 32768
    max_rich_blocks: int = 500
    max_table_rows: int = 40

    @property
    def database_url(self) -> str:
        return f"sqlite+aiosqlite:///{self.db_path}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
