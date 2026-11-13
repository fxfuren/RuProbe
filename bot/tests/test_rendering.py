"""Тесты рендеринга: лимиты rich-сообщений и осторожность формулировок.

Пункт валидации из плана: rich-сообщение с таблицей не превышает 32768 символов
и 500 блоков.
"""

from __future__ import annotations

from datetime import datetime, timezone

from aiogram.types import InputRichMessage

from ruprobe_bot.classifier import Classification, class_label
from ruprobe_bot.models import CheckStatus, VerdictClass
from ruprobe_bot.rendering import (
    DISCLAIMER,
    build_rich_message,
    build_short_report,
    dominant_class,
    enforce_limits,
    message_char_count,
)
from ruprobe_bot.service import CheckReport, TargetReport


def make_report(count: int, klass: VerdictClass = VerdictClass.BLOCK_SNI) -> CheckReport:
    reports = []
    for i in range(count):
        reports.append(
            TargetReport(
                target=f"10.0.0.{i % 250}",
                kind="net",
                classification=Classification(
                    klass=klass,
                    confidence=0.75,
                    signals=[],
                ),
                rtt_ms=1234.5,
                reset_received=False,
                timeout_happened=True,
                throughput_bps=6553.0,
                retransmits=3,
            )
        )
    return CheckReport(
        check_id=1,
        status=CheckStatus.DONE,
        observation="Регион / Оператор",
        reports=reports,
        started_at=datetime(2026, 11, 11, 21, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 11, 11, 21, 1, tzinfo=timezone.utc),
    )


def test_rich_message_stays_within_limits():
    report = make_report(30)
    message = build_rich_message(report, observation=report.observation)
    assert isinstance(message, InputRichMessage)
    assert len(message.blocks or []) <= 500
    assert message_char_count(message) <= 32768


def test_rich_message_fits_even_with_many_targets():
    report = make_report(400)
    message = enforce_limits(build_rich_message(report, observation=report.observation))
    assert len(message.blocks or []) <= 500
    assert message_char_count(message) <= 32768


def test_single_input_field_is_set():
    """У InputRichMessage заполняется ровно одно из markdown/html/blocks."""
    message = build_rich_message(make_report(3), observation="R / O")
    filled = [f for f in ("markdown", "html", "blocks") if getattr(message, f, None)]
    assert filled == ["blocks"]


def test_report_keeps_rst_and_timeout_apart():
    report = make_report(1)
    report.reports[0].reset_received = True
    report.reports[0].timeout_happened = False
    text = str(build_rich_message(report, observation="R / O").model_dump())
    assert "RST" in text

    report.reports[0].reset_received = False
    report.reports[0].timeout_happened = True
    text = str(build_rich_message(report, observation="R / O").model_dump())
    assert "таймаут" in text


def test_report_never_asserts_a_cause():
    """Формулировка не должна утверждать причину — только сигнатуры."""
    report = make_report(2)
    dumped = str(build_rich_message(report, observation="R / O").model_dump())
    # Disclaimer присутствует дословно.
    assert DISCLAIMER in dumped
    for forbidden in ("заблокирован РКН", "точно заблокирован", "установлена причина"):
        assert forbidden not in dumped


def test_failed_check_report_is_rendered():
    report = CheckReport(
        check_id=1,
        status=CheckStatus.FAILED,
        observation="R / O",
        error="Агент потерял задание",
    )
    message = build_rich_message(report, observation=report.observation)
    dumped = str(message.model_dump())
    assert "Агент потерял задание" in dumped


def test_short_report_for_single_target():
    report = make_report(1)
    report.reports[0].reset_received = True
    text = build_short_report(report, observation="R / O")
    assert "10.0.0.0" in text
    assert "RST" in text


def test_short_report_for_failed_check():
    report = CheckReport(check_id=1, status=CheckStatus.FAILED, observation="", error="timeout")
    assert "timeout" in build_short_report(report, observation="")


def test_dominant_class_picks_weightiest():
    reports = [
        TargetReport(
            target="a",
            kind="net",
            classification=Classification(klass=VerdictClass.BLOCK_SNI, confidence=0.9),
        ),
        TargetReport(
            target="b",
            kind="net",
            classification=Classification(klass=VerdictClass.DEGRADATION, confidence=0.2),
        ),
    ]
    assert dominant_class(reports) is VerdictClass.BLOCK_SNI


def test_every_class_has_a_label():
    for klass in VerdictClass:
        assert class_label(klass)
