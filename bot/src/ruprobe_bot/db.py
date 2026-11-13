"""Подключение к SQLite в режиме WAL.

Пункт 13 плана: `PRAGMA journal_mode=WAL` и `busy_timeout` обязательны при
инициализации соединения. Без них параллельные пробы дают `database is locked`.
Базу трогает только Python — Go про неё не знает.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import Base, ObservationPoint
from .settings import Settings

# Таймаут ожидания освобождения блокировки. 5 секунд — заметно больше, чем
# длится запись одного результата, и достаточно, чтобы пережить всплеск.
BUSY_TIMEOUT_MS = 5000


class Database:
    """Владелец engine и фабрики сессий."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.engine: AsyncEngine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_pre_ping=True,
        )
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self._register_pragmas()

    def _register_pragmas(self) -> None:
        """Навешивает PRAGMA на каждое новое соединение.

        Через событие, а не один раз при старте: SQLAlchemy создаёт соединения
        по мере надобности, и настройка «только для первого» не защищает.
        """

        @event.listens_for(self.engine.sync_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record):  # noqa: ANN001
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA synchronous=NORMAL")
            finally:
                cursor.close()

    async def create_all(self) -> None:
        """Создаёт схему напрямую. В проде используется Alembic."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()

    def session(self) -> AsyncSession:
        return self.session_factory()

    async def ensure_observation_point(self) -> ObservationPoint:
        """Возвращает точку наблюдения из настроек, создавая её при первом запуске."""
        async with self.session() as session:
            stmt = select(ObservationPoint).where(
                ObservationPoint.region == self._settings.region,
                ObservationPoint.operator == self._settings.operator,
                ObservationPoint.name == self._settings.observation_name,
            )
            point = (await session.execute(stmt)).scalar_one_or_none()
            if point is None:
                point = ObservationPoint(
                    region=self._settings.region,
                    operator=self._settings.operator,
                    name=self._settings.observation_name,
                )
                session.add(point)
                await session.commit()
                await session.refresh(point)
            return point


async def session_scope(db: Database) -> AsyncIterator[AsyncSession]:
    """Контекстный менеджер сессии с откатом при ошибке."""
    async with db.session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
