"""Рендеринг отчётов: rich messages с таблицей и сносками.

Лимиты Bot API 10.3 (docs/stack.md, раздел 2.2): 32768 UTF-8 символов,
500 блоков, до 20 колонок в таблице. Отчёт собирается как `blocks` —
самый предсказуемый вариант, потому что не требует экранирования разметки:
узлы конструируются типизированно, а не парсятся из строки.

Формулировки намеренно осторожные: бот сообщает класс, уверенность, сигнатуры,
точку наблюдения и время — но не утверждает причину.
"""

from __future__ import annotations

from datetime import datetime

from aiogram.types import (
    InputRichBlockDivider,
    InputRichBlockParagraph,
    InputRichBlockSectionHeading,
    InputRichBlockTable,
    InputRichMessage,
    RichBlockTableCell,
    RichTextBold,
    RichTextCode,
    RichTextItalic,
)

from .classifier import class_label
from .models import VerdictClass
from .service import CheckReport, TargetReport

__all__ = [
    "DISCLAIMER",
    "InputRichBlockDivider",
    "InputRichBlockParagraph",
    "InputRichMessage",
    "STRONG_CONFIDENCE",
    "build_rich_message",
    "build_short_report",
    "dominant_class",
    "enforce_limits",
    "message_char_count",
]

# С какой уверенности класс подаётся как основной вывод.
STRONG_CONFIDENCE = 0.6

# Маркер перед классом: даёт быстрый визуальный скан без чтения текста.
_CLASS_MARK = {
    VerdictClass.BLOCK_L3L4: "✕",
    VerdictClass.BLOCK_SNI: "✕",
    VerdictClass.DEGRADATION: "~",
    VerdictClass.DNS_INTERFERENCE: "?",
    VerdictClass.UNAVAILABLE_OTHER: "—",
}

DISCLAIMER = (
    "Класс описывает наблюдаемые сигнатуры, а не установленную причину: "
    "недоступность и «недоступность из-за ТСПУ» — разные вещи, и трафик может "
    "не доходить до фильтра вовсе."
)


def _cell(text: object, *, header: bool = False, align: str = "left") -> RichBlockTableCell:
    """Ячейка таблицы. align и valign обязательны в схеме Bot API 10.3."""
    return RichBlockTableCell(text=text, align=align, valign="middle", is_header=header or None)


def _table(rows: list[list[RichBlockTableCell]]) -> InputRichBlockTable:
    return InputRichBlockTable(cells=rows, is_striped=True, is_compact=True)


def _fmt_rtt(value: float | None) -> str:
    if value is None:
        return "—"
    if value >= 1000:
        return f"{value / 1000:.1f} с"
    return f"{value:.0f} мс"


def _fmt_throughput(value: float | None) -> str:
    if value is None:
        return "—"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f} Мбит/с"
    if value >= 1000:
        return f"{value / 1000:.0f} Кбит/с"
    return f"{value:.0f} бит/с"


def _transport_note(report: TargetReport) -> str:
    """RST и timeout — разные события, и в отчёте они тоже разные строки."""
    if report.reset_received:
        return "RST"
    if report.timeout_happened:
        return "таймаут"
    return "—"


def build_rich_message(report: CheckReport, *, observation: str) -> InputRichMessage:
    """Собирает InputRichMessage для sendRichMessage."""
    blocks: list[object] = [
        InputRichBlockSectionHeading(text="RuProbe — отчёт о проверке", size=2),
    ]

    stamp = report.finished_at or report.started_at or datetime.now()
    blocks.append(
        InputRichBlockParagraph(
            text=[
                RichTextBold(text="Точка наблюдения: "),
                observation,
                f"  ·  {stamp.strftime('%d.%m.%Y %H:%M:%S')} UTC",
            ]
        )
    )

    if report.status.value != "done":
        blocks.append(
            InputRichBlockParagraph(
                text=[
                    RichTextBold(text="Проверка не завершена. "),
                    report.error or "причина не указана",
                ]
            )
        )
        return InputRichMessage(blocks=blocks)  # type: ignore[arg-type]

    if not report.reports:
        blocks.append(
            InputRichBlockParagraph(text="Агент вернул пустой список результатов.")
        )
        return InputRichMessage(blocks=blocks)  # type: ignore[arg-type]

    dominant = dominant_class(report.reports)
    blocks.append(
        InputRichBlockParagraph(
            text=[RichTextBold(text="Основной вывод: "), class_label(dominant)]
        )
    )
    blocks.append(InputRichBlockDivider())

    # --- таблица -------------------------------------------------------------
    rows: list[list[RichBlockTableCell]] = [
        [
            _cell(RichTextBold(text="Цель"), header=True),
            _cell(RichTextBold(text="Класс"), header=True),
            _cell(RichTextBold(text="Увер."), header=True),
            _cell(RichTextBold(text="RTT"), header=True),
            _cell(RichTextBold(text="Передача"), header=True),
            _cell(RichTextBold(text="Транспорт"), header=True),
        ]
    ]
    limit = _max_rows()
    shown = report.reports[:limit]
    for item in shown:
        rows.append(_row_for(item))
    blocks.append(_table(rows))

    hidden = len(report.reports) - len(shown)
    if hidden > 0:
        blocks.append(
            InputRichBlockParagraph(
                text=RichTextItalic(
                    text=f"В таблице показаны {len(shown)} из {len(report.reports)} целей; "
                    "полный набор сохранён в базе."
                )
            )
        )

    # --- сигнатуры -----------------------------------------------------------
    blocks.append(InputRichBlockDivider())
    blocks.append(InputRichBlockSectionHeading(text="Сработавшие сигнатуры", size=3))
    for item in shown:
        blocks.append(
            InputRichBlockParagraph(
                text=[
                    RichTextBold(text=f"{item.target} — "),
                    RichTextItalic(text=class_label(item.classification.klass)),
                ]
            )
        )
        if item.classification.signals:
            for signal in item.classification.signals:
                blocks.append(
                    InputRichBlockParagraph(
                        text=[
                            RichTextCode(text=signal.code),
                            f" — {signal.description}",
                        ]
                    )
                )
        else:
            blocks.append(
                InputRichBlockParagraph(text="Сигнатур не найдено.")
            )

    blocks.append(InputRichBlockDivider())
    blocks.append(InputRichBlockParagraph(text=RichTextItalic(text=DISCLAIMER)))
    return InputRichMessage(blocks=blocks)  # type: ignore[arg-type]


def _max_rows() -> int:
    from .settings import get_settings

    return get_settings().max_table_rows


def _row_for(item: TargetReport) -> list[RichBlockTableCell]:
    klass = item.classification.klass
    return [
        _cell(RichTextCode(text=item.target)),
        _cell(f"{_CLASS_MARK.get(klass, '?')} {class_label(klass)}"),
        _cell(f"{item.classification.confidence:.0%}", align="center"),
        _cell(_fmt_rtt(item.rtt_ms), align="right"),
        _cell(_fmt_throughput(item.throughput_bps), align="right"),
        _cell(_transport_note(item), align="center"),
    ]


def dominant_class(reports: list[TargetReport]) -> VerdictClass:
    """Класс с наибольшим суммарным весом — как основной вывод."""
    scores: dict[VerdictClass, float] = {}
    for item in reports:
        klass = item.classification.klass
        scores[klass] = scores.get(klass, 0.0) + max(item.classification.confidence, 0.1)
    if not scores:
        return VerdictClass.UNAVAILABLE_OTHER
    return max(scores.items(), key=lambda kv: kv[1])[0]


def message_char_count(message: InputRichMessage) -> int:
    """Оценивает длину отчёта в символах: нужна для проверки лимита 32768."""
    total = 0
    stack: list[object] = [message.model_dump(exclude_none=True)]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            total += len(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return total


def enforce_limits(
    message: InputRichMessage, *, max_chars: int | None = None, max_blocks: int | None = None
) -> InputRichMessage:
    """Приводит отчёт к лимитам rich-сообщения, не ломая структуру.

    Обрезка идёт по блокам с конца, но последний блок — всегда disclaimer:
    усечённый отчёт без оговорки читался бы как полный.
    """
    from .settings import get_settings

    settings = get_settings()
    max_chars = max_chars if max_chars is not None else settings.max_rich_chars
    max_blocks = max_blocks if max_blocks is not None else settings.max_rich_blocks

    blocks = list(message.blocks or [])

    if len(blocks) > max_blocks:
        blocks = blocks[: max_blocks - 1] + blocks[-1:]

    while len(blocks) > 3 and _count(blocks) > max_chars:
        # Убираем предпоследний блок: последний — disclaimer.
        del blocks[-2]

    if _count(blocks) > max_chars:
        blocks = [
            InputRichBlockSectionHeading(text="RuProbe — отчёт", size=2),
            InputRichBlockParagraph(
                text="Отчёт слишком велик для одного сообщения. Данные сохранены в базе."
            ),
        ]

    return InputRichMessage(blocks=blocks)  # type: ignore[arg-type]


def _count(blocks: list[object]) -> int:
    total = 0
    stack: list[object] = []
    for block in blocks:
        stack.append(block.model_dump(exclude_none=True) if hasattr(block, "model_dump") else block)
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            total += len(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return total


def build_short_report(report: CheckReport, *, observation: str) -> str:
    """Короткая сводка для sendMessage: одна цель или краткий итог."""
    if report.status.value != "done":
        return f"Проверка не завершена: {report.error or 'причина не указана'}"

    if not report.reports:
        return "Агент вернул пустой результат."

    if len(report.reports) == 1:
        item = report.reports[0]
        parts = [
            f"{item.target} — {class_label(item.classification.klass)} "
            f"(уверенность {item.classification.confidence:.0%})"
        ]
        if item.rtt_ms is not None:
            parts.append(f"RTT {_fmt_rtt(item.rtt_ms)}")
        if item.reset_received:
            parts.append("получен RST")
        elif item.timeout_happened:
            parts.append("ответа не было до таймаута")
        return " | ".join(parts)

    counts: dict[VerdictClass, int] = {}
    for item in report.reports:
        counts[item.classification.klass] = counts.get(item.classification.klass, 0) + 1
    summary = "; ".join(
        f"{class_label(k)}: {v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])
    )
    return f"Проверено целей: {len(report.reports)}. {summary}"
