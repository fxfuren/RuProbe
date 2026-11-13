"""Хендлеры бота: команды, FSM ввода цели, запуск проверки.

Долгая работа (проба) не блокирует хендлер: он создаёт запись проверки и
запускает задачу, а прогресс идёт через черновик rich-сообщения. Черновик живёт
30 секунд, поэтому обновляется заметно чаще, а финальный результат приходит
обычным sendRichMessage.
"""

from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message

from .agent_client import AgentClient, JobSnapshot
from .db import Database
from .keyboards import MAIN_MENU, quick_targets
from .models import TargetKind
from .rendering import (
    InputRichBlockParagraph,
    InputRichMessage,
    build_rich_message,
    build_short_report,
    enforce_limits,
)
from .service import DEFAULT_PROBES, CheckReport, create_check, run_check
from .settings import Settings

log = logging.getLogger(__name__)

router = Router(name="ruprobe")


class ProbeFlow(StatesGroup):
    waiting_target = State()


HELP_TEXT = (
    "RuProbe проверяет доступность цели с точки наблюдения «регион + оператор».\n\n"
    "Что можно вводить:\n"
    "• домен — example.com\n"
    "• адрес — 1.1.1.1\n"
    "• подсеть — 192.0.2.0/29\n"
    "• диапазон — 1.2.3.4-1.2.3.20\n\n"
    "Агент выполняет набор зондов: DNS (системный, публичный, DoH), TCP, "
    "проверку SNI с ClientHello, контрольную пробу с другим SNI, полный TLS, "
    "замер пропускной способности, UDP/QUIC и ICMP.\n\n"
    "Результат — вероятностная классификация по сигнатурам, а не утверждение "
    "о причине. Классы: блокировка по адресу/порту, блокировка по SNI, "
    "деградация пропускной способности, вмешательство в DNS, "
    "недоступность не по ТСПУ."
)


def build_router(db: Database, settings: Settings) -> Router:
    """Собирает роутер с доступом к БД и настройкам."""

    @router.message(CommandStart())
    async def handle_start(message: Message, state: FSMContext) -> None:
        await state.clear()
        await message.answer(
            "RuProbe. Отправьте цель — домен, IP, подсеть или диапазон — "
            "и я проверю её с текущей точки наблюдения.\n\n"
            f"Точка наблюдения: {settings.region} / {settings.operator}",
            reply_markup=MAIN_MENU,
        )
        await message.answer("Примеры целей:", reply_markup=quick_targets())

    @router.message(Command("help"))
    @router.message(F.text == "Помощь")
    async def handle_help(message: Message) -> None:
        await message.answer(HELP_TEXT)

    @router.message(Command("check"))
    async def handle_check_command(message: Message, state: FSMContext) -> None:
        parts = (message.text or "").split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            await state.set_state(ProbeFlow.waiting_target)
            await message.answer("Отправьте цель: домен, IP, подсеть или диапазон.")
            return
        await _start_probe(message, parts[1].strip(), db, settings, state)

    @router.message(F.text == "Проверить")
    async def handle_check_button(message: Message, state: FSMContext) -> None:
        await state.set_state(ProbeFlow.waiting_target)
        await message.answer("Отправьте цель: домен, IP, подсеть или диапазон.")

    @router.callback_query(F.data.startswith("quick:"))
    async def handle_quick(callback: CallbackQuery, state: FSMContext) -> None:
        target = (callback.data or "").split(":", 1)[1]
        if callback.message is not None:
            await _start_probe(callback.message, target, db, settings, state)
        await callback.answer()

    @router.message(ProbeFlow.waiting_target)
    async def handle_target(message: Message, state: FSMContext) -> None:
        target = (message.text or "").strip()
        if not target:
            await message.answer("Пустая цель. Отправьте домен, IP, подсеть или диапазон.")
            return
        await _start_probe(message, target, db, settings, state)

    @router.message()
    async def handle_fallback(message: Message, state: FSMContext) -> None:
        target = (message.text or "").strip()
        if not target:
            await message.answer("Не понял сообщение. Используйте /help.")
            return
        await _start_probe(message, target, db, settings, state)

    return router


async def _start_probe(
    message: Message,
    target: str,
    db: Database,
    settings: Settings,
    state: FSMContext,
) -> None:
    """Создаёт проверку и запускает фоновую задачу."""
    await state.clear()
    bot = message.bot
    if bot is None or message.chat is None:
        return

    point = await db.ensure_observation_point()
    kind = _target_kind(target)
    check_id = await create_check(
        db,
        target_value=target,
        target_kind=kind,
        observation_point_id=point.id,
        chat_id=message.chat.id,
    )

    status_message = await message.answer(f"Проверяю {target}…")
    observation = point.label()

    task = asyncio.create_task(
        _run_and_report(
            bot=bot,
            db=db,
            settings=settings,
            check_id=check_id,
            target=target,
            observation=observation,
            chat_id=message.chat.id,
            status_message_id=status_message.message_id,
        )
    )
    # Без этого исключение фоновой задачи теряется в логе asyncio без контекста
    # проверки, и связать падение с конкретным check_id будет нечем.
    task.add_done_callback(_log_task_failure)


def _log_task_failure(task: asyncio.Task) -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("background probe task failed", exc_info=exc)


async def _run_and_report(
    *,
    bot: Bot,
    db: Database,
    settings: Settings,
    check_id: int,
    target: str,
    observation: str,
    chat_id: int,
    status_message_id: int,
) -> None:
    """Прогоняет проверку, обновляя прогресс черновиком и завершая отчётом."""
    last_draft = 0.0
    loop = asyncio.get_running_loop()

    async def on_progress(snapshot: JobSnapshot) -> None:
        nonlocal last_draft
        now = loop.time()
        if now - last_draft < settings.draft_interval_s:
            return
        last_draft = now
        text = _draft_text(target, snapshot)
        try:
            await bot.send_rich_message_draft(
                chat_id=chat_id,
                draft_id=status_message_id,
                rich_message=_draft_message(text),
            )
        except Exception:  # noqa: BLE001 — черновик необязателен, падать нельзя
            log.debug("draft update failed", exc_info=True)

    async with AgentClient(
        settings.agent_url,
        default_timeout_ms=settings.agent_timeout_ms,
        throughput_bytes=settings.throughput_bytes,
    ) as agent:
        report = await run_check(
            db,
            agent,
            settings,
            targets=[target],
            observation_point_id=0,
            check_id=check_id,
            probes=_probes_for(target),
            on_progress=on_progress,
        )

    await _deliver_report(
        bot=bot,
        report=report,
        observation=observation,
        chat_id=chat_id,
        status_message_id=status_message_id,
    )


async def _deliver_report(
    *,
    bot: Bot,
    report: CheckReport,
    observation: str,
    chat_id: int,
    status_message_id: int,
) -> None:
    """Отправляет результат: короткий — обычным сообщением, подробный — rich."""
    try:
        await bot.delete_message(chat_id=chat_id, message_id=status_message_id)
    except Exception:  # noqa: BLE001
        log.debug("could not delete status message", exc_info=True)

    if report.status.value != "done" or len(report.reports) != 1:
        await bot.send_message(chat_id=chat_id, text=build_short_report(report, observation=observation))

    if report.status.value != "done":
        return

    message = enforce_limits(build_rich_message(report, observation=observation))
    try:
        await bot.send_rich_message(chat_id=chat_id, rich_message=message)
    except Exception:  # noqa: BLE001
        # Rich-сообщение может быть недоступно конкретному клиенту API или
        # отклонено по лимитам — тогда отдаём текстовую сводку.
        log.warning("rich message failed, falling back to text", exc_info=True)
        await bot.send_message(chat_id=chat_id, text=build_short_report(report, observation=observation))


def _draft_message(text: str):
    from .rendering import InputRichBlockParagraph, InputRichMessage

    return InputRichMessage(blocks=[InputRichBlockParagraph(text=text)])


def _draft_text(target: str, snapshot: JobSnapshot) -> str:
    progress = snapshot.progress
    if progress.total:
        return f"Проверяю {target}: {progress.completed} из {progress.total} ({progress.percent}%)"
    return f"Проверяю {target}…"


def _target_kind(raw: str) -> TargetKind:
    """Вид цели для записи в БД. Агент определит его точнее сам."""
    if "/" in raw:
        return TargetKind.CIDR
    if "-" in raw and not raw.startswith("-"):
        return TargetKind.RANGE
    if raw.replace(".", "").isdigit():
        return TargetKind.NET
    return TargetKind.DOMAIN


def _probes_for(target: str) -> list[str]:
    """Набор зондов зависит от вида цели: DNS и SNI бессмысленны для голого IP,
    а перебор соседей нужен именно для адресов."""
    probes = list(DEFAULT_PROBES)
    if _target_kind(target) is TargetKind.NET:
        probes = [p for p in probes if p not in {"dns", "doh"}]
        probes.append("neighbors")
    return probes
