"""Сервисный слой: связывает агент, БД и классификатор.

Здесь же две обязанности из плана, которые легко забыть:

* пункт 18: при старте помечать зависшие проверки как упавшие. Агент теряет
  in-flight задания при рестарте, и без этого в Telegram навсегда повиснут
  прогресс-сообщения;
* запись результата и вердикта в одной транзакции, чтобы не было результатов
  без классификации.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select, update

from .agent_client import AgentClient, AgentError, AgentJobLost, JobSnapshot
from .classifier import Classification, classify
from .db import Database
from .registry import RegistryHit, registry_note_for
from .models import (
    Check,
    CheckStatus,
    ProbeResult,
    Target,
    TargetKind,
    Verdict,
    VerdictClass,
)
from .settings import Settings

# Наборы зондов по виду цели (план фикса 177.3.213.44, фаза 1).
# DOMAIN — полный набор; NET — без dns/doh/sni/sni_control/throughput:
# SNI с IP как SNI невалиден, throughput без живого сервиса — шум.
# tcp_alt_ports и udp нужны для IP: без них нельзя развести правило
# по порту и правило по адресу, и не проверяется блокировка транспорта.
DOMAIN_PROBES = ["dns", "doh", "tcp", "tcp_alt_ports", "sni", "sni_control", "tls_full", "throughput", "udp", "icmp", "neighbors"]
NET_PROBES = ["tcp", "tcp_alt_ports", "udp", "icmp", "neighbors"]
# Для CIDR/RANGE соседи не нужны на каждую цель: они берутся один раз
# на префикс, иначе шум.
CIDR_PROBES = ["tcp", "tcp_alt_ports", "udp", "icmp"]
RANGE_PROBES = ["tcp", "tcp_alt_ports", "udp", "icmp"]
# Совместимость: DEFAULT_PROBES — набор для домена.
DEFAULT_PROBES = DOMAIN_PROBES


def probes_for(kind: TargetKind) -> list[str]:
    """Набор зондов по виду цели — единый источник (фаза 1 плана)."""
    if kind is TargetKind.NET:
        return list(NET_PROBES)
    if kind is TargetKind.CIDR:
        return list(CIDR_PROBES)
    if kind is TargetKind.RANGE:
        return list(RANGE_PROBES)
    return list(DOMAIN_PROBES)


@dataclass(slots=True)
class TargetReport:
    """Результат по одной цели батча, готовый к рендерингу."""

    target: str
    kind: str
    classification: Classification
    rtt_ms: float | None = None
    reset_received: bool = False
    timeout_happened: bool = False
    tls_reset_received: bool = False
    tls_timeout_happened: bool = False
    throughput_bps: float | None = None
    retransmits: int | None = None
    neighbors_alive: int = 0
    neighbors_dead: int = 0
    neighbors_probed: int = 0
    icmp_method: str = ""
    skipped_probes: list[str] = field(default_factory=list)
    registry_note: str = ""
    raw: dict = field(default_factory=dict)


@dataclass(slots=True)
class CheckReport:
    """Итог проверки целиком."""

    check_id: int
    status: CheckStatus
    observation: str
    reports: list[TargetReport] = field(default_factory=list)
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


def classify_target_kind(raw: str, agent_kind: str) -> TargetKind:
    """Сопоставляет вид цели из агента нашей модели."""
    mapping = {
        "domain": TargetKind.DOMAIN,
        "net": TargetKind.NET,
        "range": TargetKind.RANGE,
        "cidr": TargetKind.CIDR,
    }
    return mapping.get(agent_kind, TargetKind.NET)


async def mark_stale_checks_failed(db: Database) -> int:
    """Помечает незавершённые проверки как упавшие.

    Вызывается один раз при старте бота. Любая проверка в статусе pending/running
    после рестарта процесса потеряна: ни опроса, ни прогресс-сообщения для неё
    больше не будет.
    """
    now = datetime.now(timezone.utc)
    async with db.session() as session:
        stmt = (
            update(Check)
            .where(Check.status.in_([CheckStatus.PENDING, CheckStatus.RUNNING]))
            .values(
                status=CheckStatus.FAILED,
                error="Проверка прервана перезапуском бота или агента",
                finished_at=now,
            )
        )
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount or 0


async def get_or_create_target(session, raw: str, kind: TargetKind) -> Target:
    stmt = select(Target).where(Target.kind == kind, Target.value == raw)
    target = (await session.execute(stmt)).scalar_one_or_none()
    if target is None:
        target = Target(kind=kind, value=raw)
        session.add(target)
        await session.flush()
    return target


async def create_check(
    db: Database,
    *,
    target_value: str,
    target_kind: TargetKind,
    observation_point_id: int,
    chat_id: int | None = None,
) -> int:
    """Создаёт запись проверки в статусе pending и возвращает её id."""
    async with db.session() as session:
        target = await get_or_create_target(session, target_value, target_kind)
        check = Check(
            observation_point_id=observation_point_id,
            target_id=target.id,
            status=CheckStatus.PENDING,
            chat_id=chat_id,
        )
        session.add(check)
        await session.commit()
        await session.refresh(check)
        return check.id


async def mark_check_running(db: Database, check_id: int, agent_job_id: str, message_id: int | None) -> None:
    async with db.session() as session:
        check = await session.get(Check, check_id)
        if check is None:
            return
        check.status = CheckStatus.RUNNING
        check.agent_job_id = agent_job_id
        if message_id is not None:
            check.message_id = message_id
        await session.commit()


async def fail_check(db: Database, check_id: int, error: str) -> None:
    async with db.session() as session:
        check = await session.get(Check, check_id)
        if check is None:
            return
        check.status = CheckStatus.FAILED
        check.error = error
        check.finished_at = datetime.now(timezone.utc)
        await session.commit()


async def save_results(
    db: Database, check_id: int, snapshot: JobSnapshot, registry_hit: RegistryHit | None = None
) -> list[TargetReport]:
    """Классифицирует факты и сохраняет результаты вместе с вердиктами."""
    reports: list[TargetReport] = []

    async with db.session() as session:
        check = await session.get(Check, check_id)
        if check is None:
            raise ValueError(f"check {check_id} not found")

        for item in snapshot.results:
            raw = item.get("facts") or {}
            # Реестр — аннотация, не сигнал: в факты кладётся как отдельный ключ,
            # классификатор весов от него не получает.
            if registry_hit is not None:
                raw = {
                    **raw,
                    "registry": {
                        "listed": registry_hit.listed,
                        "source": registry_hit.source,
                        "prefix": registry_hit.prefix,
                        "known": registry_hit.known,
                    },
                }
            classification = classify(raw)
            tcp = raw.get("tcp") or {}
            throughput = raw.get("throughput") or {}
            icmp = raw.get("icmp") or {}
            neighbors = raw.get("neighbors") or {}
            tls_full = raw.get("tls_full") or {}
            sni = raw.get("sni") or {}

            # RST/timeout берём не только из tcp, но и OR по sni/tls_full:
            # RST и молчаливый drop на TLS-слое терять нельзя (план, дефект 3.6).
            reset_received = bool(
                tcp.get("reset_received")
                or sni.get("reset_received")
                or tls_full.get("reset_received")
            )
            timeout_happened = bool(
                tcp.get("timeout_happened")
                or sni.get("silent_drop")
                or tls_full.get("timeout_happened")
            )

            probe_result = ProbeResult(
                check_id=check_id,
                target_value=item.get("target", "unknown"),
                target_kind=item.get("kind", "unknown"),
                rtt_ms=_first_rtt(tcp, raw),
                reset_received=reset_received,
                timeout_happened=timeout_happened,
                throughput_bps=throughput.get("throughput_bps"),
                retransmits=throughput.get("retransmits"),
                raw=raw,
            )
            session.add(probe_result)
            await session.flush()

            session.add(
                Verdict(
                    probe_result_id=probe_result.id,
                    klass=classification.klass,
                    confidence=classification.confidence,
                    signals=classification.signals_as_dicts(),
                    notes=classification.notes or None,
                )
            )

            skipped = [
                line.removeprefix("skipped: ").split(":")[0].strip()
                for line in item.get("errors") or []
                if line.startswith("skipped: ")
            ]
            reports.append(
                TargetReport(
                    target=probe_result.target_value,
                    kind=probe_result.target_kind,
                    classification=classification,
                    rtt_ms=probe_result.rtt_ms,
                    reset_received=bool(tcp.get("reset_received")),
                    timeout_happened=bool(tcp.get("timeout_happened")),
                    tls_reset_received=bool(tls_full.get("reset_received") or sni.get("reset_received")),
                    tls_timeout_happened=bool(tls_full.get("timeout_happened") or sni.get("silent_drop")),
                    throughput_bps=probe_result.throughput_bps,
                    retransmits=probe_result.retransmits,
                    neighbors_alive=int(neighbors.get("alive") or 0),
                    neighbors_dead=int(neighbors.get("dead") or 0),
                    neighbors_probed=int(neighbors.get("probed") or 0),
                    icmp_method=str(icmp.get("method") or ""),
                    skipped_probes=skipped,
                    registry_note=registry_note_for(
                        registry_hit, classification.klass.value
                    ),
                    raw=raw,
                )
            )

        check.status = CheckStatus.DONE
        check.finished_at = datetime.now(timezone.utc)
        check.summary = _build_summary(reports)
        await session.commit()

    return reports


def _first_rtt(tcp: dict, raw: dict) -> float | None:
    """RTT берём у TCP, а при его отсутствии — у ICMP.

    Отсутствие значения не подменяется нулём: ноль означал бы «мгновенно»,
    а это другое утверждение.
    """
    if tcp.get("rtt_ms"):
        return float(tcp["rtt_ms"])
    icmp = raw.get("icmp") or {}
    if icmp.get("rtt_ms"):
        return float(icmp["rtt_ms"])
    return None


def _build_summary(reports: list[TargetReport]) -> str:
    counts: dict[str, int] = {}
    for report in reports:
        key = report.classification.klass.value
        counts[key] = counts.get(key, 0) + 1
    parts = [f"{klass}: {count}" for klass, count in sorted(counts.items())]
    return "; ".join(parts) if parts else "нет результатов"


async def run_check(
    db: Database,
    agent: AgentClient,
    settings: Settings,
    *,
    targets: list[str],
    observation_point_id: int,
    check_id: int,
    probes: list[str] | None = None,
    port: int | None = None,
    registry_hit: RegistryHit | None = None,
    on_progress: Callable[[JobSnapshot], object] | None = None,
) -> CheckReport:
    """Полный цикл: задание → опрос → классификация → запись."""
    probes = probes or DEFAULT_PROBES
    target_kind = classify_target_kind(targets[0], _guess_kind(targets[0]))

    started = datetime.now(timezone.utc)
    try:
        job_id, snapshot = await agent.run_job(
            targets,
            probes=probes,
            timeout_ms=settings.agent_timeout_ms,
            port=port,
            neighbor_limit=settings.neighbor_limit,
            neighbor_scope=settings.neighbor_scope,
            poll_interval=settings.poll_interval_s,
            poll_timeout=settings.poll_timeout_s,
            on_progress=on_progress,
        )
    except AgentJobLost as exc:
        # Агент перезапустился посреди проверки. Это ожидаемый сценарий, и его
        # надо честно показать как провал, а не ждать вечно.
        await fail_check(db, check_id, f"Агент потерял задание: {exc}")
        return CheckReport(
            check_id=check_id,
            status=CheckStatus.FAILED,
            observation="",
            error=str(exc),
            started_at=started,
            finished_at=datetime.now(timezone.utc),
        )
    except AgentError as exc:
        await fail_check(db, check_id, str(exc))
        return CheckReport(
            check_id=check_id,
            status=CheckStatus.FAILED,
            observation="",
            error=str(exc),
            started_at=started,
            finished_at=datetime.now(timezone.utc),
        )

    await mark_check_running(db, check_id, job_id, message_id=None)
    reports = await save_results(db, check_id, snapshot, registry_hit=registry_hit)

    return CheckReport(
        check_id=check_id,
        status=CheckStatus.DONE,
        observation="",
        reports=reports,
        started_at=started,
        finished_at=datetime.now(timezone.utc),
    )


def _guess_kind(raw: str) -> str:
    """Локальная догадка о виде цели: нужна только для записи в БД."""
    if "/" in raw:
        return "cidr"
    if "-" in raw:
        return "range"
    if raw.replace(".", "").isdigit():
        return "net"
    return "domain"


__all__ = [
    "DEFAULT_PROBES",
    "DOMAIN_PROBES",
    "NET_PROBES",
    "CIDR_PROBES",
    "RANGE_PROBES",
    "probes_for",
    "CheckReport",
    "TargetReport",
    "classify_target_kind",
    "create_check",
    "fail_check",
    "mark_check_running",
    "mark_stale_checks_failed",
    "run_check",
    "save_results",
    "VerdictClass",
]
