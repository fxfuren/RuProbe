"""RuProbe — Telegram-бот проверки доступности.

Точка входа процесса. Порядок запуска важен:

1. применить PRAGMA и создать/проверить схему;
2. пометить зависшие проверки упавшими — до того, как бот начнёт принимать
   сообщения, иначе пользователь увидит «проверка идёт» для проверки,
   которой уже не существует;
3. поднять long polling.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.fsm.storage.memory import MemoryStorage

from .agent_client import AgentClient, AgentError
from .db import Database
from .handlers import build_router
from .service import mark_stale_checks_failed
from .settings import get_settings

log = logging.getLogger("ruprobe")


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("aiogram.event").setLevel(logging.WARNING)


async def wait_for_agent(settings, *, attempts: int = 30, delay: float = 2.0) -> None:
    """Ждёт готовности агента.

    Без этого первый же запрос пользователя упадёт, если бот стартовал быстрее
    агента: depends_on гарантирует только порядок запуска контейнеров, а не
    готовность сервиса внутри.
    """
    async with AgentClient(settings.agent_url) as agent:
        for attempt in range(1, attempts + 1):
            try:
                info = await agent.health()
                log.info("agent is ready: %s", info.get("status"))
                return
            except AgentError as exc:
                log.warning("agent not ready (%d/%d): %s", attempt, attempts, exc)
                await asyncio.sleep(delay)
    log.error("agent did not become ready; continuing anyway")


async def async_main() -> None:
    settings = get_settings()
    if not settings.bot_token:
        log.error("BOT_TOKEN is empty — задайте его в .env")
        raise SystemExit(2)

    db = Database(settings)
    await db.create_all()

    stale = await mark_stale_checks_failed(db)
    if stale:
        log.info("marked %d stale checks as failed", stale)

    await wait_for_agent(settings)

    bot = Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(),
    )
    dispatcher = Dispatcher(storage=MemoryStorage())
    dispatcher.include_router(build_router(db, settings))

    try:
        await bot.delete_webhook(drop_pending_updates=False)
        log.info(
            "starting polling; observation point = %s / %s",
            settings.region,
            settings.operator,
        )
        await dispatcher.start_polling(bot)
    finally:
        await bot.session.close()
        await db.dispose()


def main() -> None:
    configure_logging()
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        log.info("stopped by user")


if __name__ == "__main__":
    main()
