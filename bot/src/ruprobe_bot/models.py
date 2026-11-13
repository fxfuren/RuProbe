"""Модели данных RuProbe (SQLAlchemy 2.0, декларативный стиль).

Сущности соответствуют docs/tspu-model.md: наблюдение, цель, проверка,
результат пробы, вердикт, подписка.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Базовый класс с общим набором типов."""

    type_annotation_map = {dict: JSON, list: JSON}


class TargetKind(str, enum.Enum):
    NET = "net"
    DOMAIN = "domain"
    RANGE = "range"
    CIDR = "cidr"


class CheckStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class VerdictClass(str, enum.Enum):
    """Четыре класса отказа из docs/tspu-model.md плюс «не по ТСПУ»."""

    BLOCK_L3L4 = "block_l3l4"
    BLOCK_SNI = "block_sni"
    DEGRADATION = "degradation"
    DNS_INTERFERENCE = "dns_interference"
    UNAVAILABLE_OTHER = "unavailable_other"


class ObservationPoint(Base):
    """Точка наблюдения (регион + оператор).

    По docs/tspu-model.md это не метаданные, а первичный ключ измерения:
    один и тот же ресурс штатно ведёт себя по-разному у разных операторов.
    """

    __tablename__ = "observation_points"
    __table_args__ = (
        UniqueConstraint("region", "operator", "name", name="uq_observation_point"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    region: Mapped[str] = mapped_column(String(128), nullable=False)
    operator: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    checks: Mapped[list["Check"]] = relationship(back_populates="observation_point")

    def label(self) -> str:
        return f"{self.region} / {self.operator}"


class Target(Base):
    """Нормализованная цель проверки."""

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_target_kind_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[TargetKind] = mapped_column(Enum(TargetKind, native_enum=False), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    checks: Mapped[list["Check"]] = relationship(back_populates="target")


class Check(Base):
    """Один запуск проверки: объединяет результаты по всем целям батча."""

    __tablename__ = "checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    observation_point_id: Mapped[int] = mapped_column(
        ForeignKey("observation_points.id"), nullable=False
    )
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    status: Mapped[CheckStatus] = mapped_column(
        Enum(CheckStatus, native_enum=False), nullable=False, default=CheckStatus.PENDING
    )
    # Внешний идентификатор задания у агента. Отдельным полем, потому что агент
    # теряет состояние при рестарте, и это надо уметь отличать от наших ошибок.
    agent_job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chat_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    observation_point: Mapped[ObservationPoint] = relationship(back_populates="checks")
    target: Mapped[Target] = relationship(back_populates="checks")
    results: Mapped[list["ProbeResult"]] = relationship(
        back_populates="check", cascade="all, delete-orphan"
    )


class ProbeResult(Base):
    """Структурированный результат пробы по одной цели.

    Отдельные поля для RST и timeout, а не «ошибка»: модель прямо требует
    различать эти события, потому что молчаливый drop — приоритетная сигнатура
    умной блокировки, а мгновенный RST — скорее аномалия.
    """

    __tablename__ = "probe_results"
    __table_args__ = (
        Index("ix_probe_results_check_target", "check_id", "target_value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("checks.id"), nullable=False)
    target_value: Mapped[str] = mapped_column(String(512), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")

    rtt_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    reset_received: Mapped[bool] = mapped_column(default=False)
    timeout_happened: Mapped[bool] = mapped_column(default=False)
    throughput_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    retransmits: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # raw — все факты зондов без потерь: классификатор работает по нему,
    # а поля выше нужны только для быстрых выборок и отчётов.
    raw: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    check: Mapped[Check] = relationship(back_populates="results")
    verdicts: Mapped[list["Verdict"]] = relationship(
        back_populates="probe_result", cascade="all, delete-orphan"
    )


class Verdict(Base):
    """Вероятностная классификация с набором сработавших сигнатур.

    Модель запрещает детерминированный вердикт: ТСПУ борется с ложными
    срабатываниями и постоянно обновляет списки, поэтому бот сообщает класс,
    уверенность, сигнатуры и точку наблюдения — но не «причину».
    """

    __tablename__ = "verdicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    probe_result_id: Mapped[int] = mapped_column(ForeignKey("probe_results.id"), nullable=False)
    klass: Mapped[VerdictClass] = mapped_column(
        Enum(VerdictClass, native_enum=False), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    signals: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    probe_result: Mapped[ProbeResult] = relationship(back_populates="verdicts")


class Subscription(Base):
    """Регулярные проверки. Таблица заведена под будущее; планировщик вне рамок."""

    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    schedule: Mapped[str] = mapped_column(String(64), nullable=False, default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
