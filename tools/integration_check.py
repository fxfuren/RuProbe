"""Интеграционный прогон без Telegram: агент → классификация → запись в БД.

Проверяются три сценария из раздела 8 плана:
живой домен, заведомо недоступный адрес, диапазон /29.

Запуск: python tools/integration_check.py
Требует поднятый агент (AGENT_URL, по умолчанию http://127.0.0.1:8080).
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Консоль Windows по умолчанию cp1252 и падает на кириллице в описаниях сигнатур.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bot" / "src"))

from ruprobe_bot.agent_client import AgentClient  # noqa: E402
from ruprobe_bot.db import Database  # noqa: E402
from ruprobe_bot.models import CheckStatus  # noqa: E402
from ruprobe_bot.rendering import build_rich_message, build_short_report, enforce_limits  # noqa: E402
from ruprobe_bot.service import (  # noqa: E402
    create_check,
    mark_stale_checks_failed,
    run_check,
)
from ruprobe_bot.models import TargetKind  # noqa: E402
from ruprobe_bot.settings import Settings  # noqa: E402


SCENARIOS = [
    ("example.com", TargetKind.DOMAIN, ["dns", "doh", "tcp", "sni", "sni_control", "tls_full", "throughput", "icmp"]),
    ("192.0.2.1", TargetKind.NET, ["tcp", "tcp_alt_ports", "sni", "tls_full", "icmp", "neighbors"]),
    ("198.51.100.0/29", TargetKind.CIDR, ["tcp", "icmp"]),
]


async def main() -> int:
    db_path = Path(os.getenv("DB_PATH", str(Path(__file__).resolve().parents[1] / ".tmp" / "integration.sqlite3")))
    settings = Settings(
        BOT_TOKEN="integration",
        AGENT_URL=os.getenv("AGENT_URL", "http://127.0.0.1:8080"),
        DB_PATH=db_path,
        AGENT_TIMEOUT_MS=4000,
        POLL_TIMEOUT_S=180,
        POLL_INTERVAL_S=0.5,
    )

    db = Database(settings)
    await db.create_all()
    stale = await mark_stale_checks_failed(db)
    print(f"stale checks marked failed at startup: {stale}")

    point = await db.ensure_observation_point()
    failures = 0

    async with AgentClient(
        settings.agent_url,
        default_timeout_ms=settings.agent_timeout_ms,
        throughput_bytes=1 << 19,
    ) as agent:
        health = await agent.health()
        print(f"agent health: {health.get('status')}")

        for target, kind, probes in SCENARIOS:
            check_id = await create_check(
                db,
                target_value=target,
                target_kind=kind,
                observation_point_id=point.id,
            )

            def on_progress(snapshot) -> None:  # noqa: ANN001
                if snapshot.progress.total > 1:
                    print(f"  progress: {snapshot.progress.completed}/{snapshot.progress.total}")

            report = await run_check(
                db,
                agent,
                settings,
                targets=[target],
                observation_point_id=point.id,
                check_id=check_id,
                probes=probes,
                on_progress=on_progress,
            )

            print(f"\n=== {target} ({kind.value}) -> {report.status.value} ===")
            if report.status is not CheckStatus.DONE:
                print(f"  error: {report.error}")
                failures += 1
                continue

            for item in report.reports:
                print(
                    f"  {item.target}: {item.classification.klass.value} "
                    f"({item.classification.confidence:.0%}), rtt={item.rtt_ms}, "
                    f"rst={item.reset_received}, timeout={item.timeout_happened}, "
                    f"bps={item.throughput_bps}"
                )
                for signal in item.classification.signals:
                    print(f"      - {signal.code}: {signal.description}")

            print("  short:", build_short_report(report, observation=point.label()))
            message = enforce_limits(build_rich_message(report, observation=point.label()))
            blocks = len(message.blocks or [])
            print(f"  rich blocks: {blocks}")
            if blocks > 500:
                print("  FAIL: too many blocks")
                failures += 1

    # Рестарт агента посреди проверки: задание должно быть потеряно, а не висеть.
    print("\n=== scenario: agent loses job mid-check ===")
    check_id = await create_check(
        db,
        target_value="203.0.113.1",
        target_kind=TargetKind.NET,
        observation_point_id=point.id,
    )
    from ruprobe_bot.agent_client import AgentJobLost

    async with AgentClient(settings.agent_url) as agent:
        try:
            await agent.job("does-not-exist")
            print("  FAIL: expected AgentJobLost")
            failures += 1
        except AgentJobLost:
            print("  OK: unknown job raises AgentJobLost, bot marks the check failed")

    stale = await mark_stale_checks_failed(db)
    print(f"  stale checks marked failed after simulated restart: {stale}")
    if stale != 1:
        print("  FAIL: the pending check was not marked failed")
        failures += 1

    await db.dispose()
    print(f"\nfailures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
