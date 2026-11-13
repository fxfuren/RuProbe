"""Тесты БД: PRAGMA обязательны, иначе параллельные пробы дадут database is locked."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import text

from ruprobe_bot.db import BUSY_TIMEOUT_MS, Database
from ruprobe_bot.models import CheckStatus
from ruprobe_bot.service import create_check, mark_stale_checks_failed
from ruprobe_bot.models import ObservationPoint, TargetKind


@pytest.fixture()
def settings(tmp_path):
    from ruprobe_bot.settings import Settings

    return Settings(BOT_TOKEN="test", DB_PATH=tmp_path / "test.sqlite3")


async def test_wal_and_busy_timeout_are_set(settings):
    db = Database(settings)
    try:
        await db.create_all()
        async with db.session() as session:
            journal = (await session.execute(text("PRAGMA journal_mode"))).scalar()
            busy = (await session.execute(text("PRAGMA busy_timeout"))).scalar()
            foreign_keys = (await session.execute(text("PRAGMA foreign_keys"))).scalar()
        assert str(journal).lower() == "wal"
        assert int(busy) == BUSY_TIMEOUT_MS
        assert int(foreign_keys) == 1
    finally:
        await db.dispose()


async def test_pragmas_apply_to_every_new_connection(settings):
    """PRAGMA навешиваются на connect, а не один раз при старте."""
    from sqlalchemy import event

    db = Database(settings)
    try:
        await db.create_all()
        seen_connections: list[int] = []

        @event.listens_for(db.engine.sync_engine, "connect")
        def _track(dbapi_connection, _record):  # noqa: ANN001
            seen_connections.append(id(dbapi_connection))

        # Разные соединения из пула должны одинаково сообщать WAL.
        results = []
        for _ in range(3):
            async with db.engine.connect() as conn:
                results.append((await conn.execute(text("PRAGMA journal_mode"))).scalar())
        assert all(str(r).lower() == "wal" for r in results)
    finally:
        await db.dispose()


async def test_observation_point_is_reused_not_duplicated(settings):
    db = Database(settings)
    try:
        await db.create_all()
        first = await db.ensure_observation_point()
        second = await db.ensure_observation_point()
        assert first.id == second.id
    finally:
        await db.dispose()


async def test_stale_checks_are_marked_failed(settings):
    """Пункт 18 плана: зависшие проверки помечаются упавшими при старте."""
    db = Database(settings)
    try:
        await db.create_all()
        point = await db.ensure_observation_point()
        check_id = await create_check(
            db,
            target_value="example.com",
            target_kind=TargetKind.DOMAIN,
            observation_point_id=point.id,
        )

        marked = await mark_stale_checks_failed(db)
        assert marked == 1

        from ruprobe_bot.models import Check

        async with db.session() as session:
            check = await session.get(Check, check_id)
            assert check is not None
            assert check.status is CheckStatus.FAILED
            assert check.finished_at is not None
            assert "перезапуск" in (check.error or "")

        # Повторный вызов ничего не меняет: упавшая проверка уже не pending.
        assert await mark_stale_checks_failed(db) == 0
    finally:
        await db.dispose()


async def test_parallel_writes_do_not_lock(settings):
    """busy_timeout + WAL должны переживать параллельную запись."""
    db = Database(settings)
    try:
        await db.create_all()
        point = await db.ensure_observation_point()

        async def writer(index: int) -> None:
            await create_check(
                db,
                target_value=f"target{index}.example",
                target_kind=TargetKind.DOMAIN,
                observation_point_id=point.id,
            )

        await asyncio.gather(*(writer(i) for i in range(10)))

        from ruprobe_bot.models import Check
        from sqlalchemy import func, select

        async with db.session() as session:
            total = (await session.execute(select(func.count(Check.id)))).scalar()
        assert total == 10
    finally:
        await db.dispose()
