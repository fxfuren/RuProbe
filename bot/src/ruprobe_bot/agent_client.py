"""Клиент Go-агента: создать задание, опрашивать статус с backoff.

Контракт описан в разделе 3 плана. Клиент намеренно не делает ретраев самой
пробы: повтор — это новое измерение, и решать о нём должен вызывающий код.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx


class AgentError(RuntimeError):
    """Агент недоступен или ответил ошибкой."""


class AgentJobLost(AgentError):
    """Агент не знает такое задание.

    Отдельный тип, потому что исход принципиально отличается от сетевой ошибки:
    агент перезапустился, in-flight задание потеряно, и проверку нужно помечать
    упавшей, а не «ещё идёт». Иначе прогресс-сообщение в Telegram повиснет навсегда.
    """


@dataclass(slots=True)
class JobProgress:
    completed: int = 0
    total: int = 0

    @property
    def percent(self) -> int:
        if self.total <= 0:
            return 0
        return min(100, int(self.completed * 100 / self.total))


@dataclass(slots=True)
class JobSnapshot:
    job_id: str
    status: str
    progress: JobProgress = field(default_factory=JobProgress)
    results: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def is_done(self) -> bool:
        return self.status in {"done", "failed"}


class AgentClient:
    """Тонкая обёртка над HTTP-контрактом агента."""

    def __init__(
        self,
        base_url: str,
        *,
        default_timeout_ms: int = 5000,
        throughput_bytes: int = 1 << 20,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._default_timeout_ms = default_timeout_ms
        self._throughput_bytes = throughput_bytes
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "AgentClient":
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self._base_url, timeout=30.0)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Ленивая инициализация: клиент можно использовать и без контекста.
            self._client = httpx.AsyncClient(base_url=self._base_url, timeout=30.0)
        return self._client

    async def health(self) -> dict[str, Any]:
        try:
            response = await self.client.get("/health")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise AgentError(f"agent health failed: {exc}") from exc

    async def submit_batch(
        self,
        targets: list[str],
        *,
        probes: list[str] | None = None,
        timeout_ms: int | None = None,
        port: int | None = None,
        throughput_bytes: int | None = None,
        neighbor_limit: int | None = None,
        expand_limit: int | None = None,
    ) -> str:
        """Создаёт задание и возвращает его идентификатор."""
        payload: dict[str, Any] = {
            "targets": targets,
            "timeout_ms": timeout_ms or self._default_timeout_ms,
            "throughput_bytes": throughput_bytes or self._throughput_bytes,
        }
        if probes:
            payload["probes"] = probes
        if port:
            payload["port"] = port
        if neighbor_limit:
            payload["neighbor_limit"] = neighbor_limit
        if expand_limit:
            payload["expand_limit"] = expand_limit

        try:
            response = await self.client.post("/probe/batch", json=payload)
        except httpx.HTTPError as exc:
            raise AgentError(f"agent unreachable: {exc}") from exc

        if response.status_code == 404:
            raise AgentJobLost("agent does not expose /probe/batch")
        if response.status_code >= 400:
            raise AgentError(f"agent rejected batch: {response.status_code} {response.text[:200]}")
        return response.json()["job_id"]

    async def job(self, job_id: str) -> JobSnapshot:
        """Читает состояние задания. 404 превращается в AgentJobLost."""
        try:
            response = await self.client.get(f"/jobs/{job_id}")
        except httpx.HTTPError as exc:
            raise AgentError(f"agent unreachable: {exc}") from exc

        if response.status_code == 404:
            raise AgentJobLost(f"job {job_id} lost by agent")
        if response.status_code >= 400:
            raise AgentError(f"agent error: {response.status_code} {response.text[:200]}")

        data = response.json()
        progress = data.get("progress") or {}
        return JobSnapshot(
            job_id=data.get("job_id", job_id),
            status=data.get("status", "unknown"),
            progress=JobProgress(
                completed=int(progress.get("completed", 0)),
                total=int(progress.get("total", 0)),
            ),
            results=data.get("results") or [],
            error=data.get("error"),
        )

    async def run_job(
        self,
        targets: list[str],
        *,
        probes: list[str] | None = None,
        timeout_ms: int | None = None,
        port: int | None = None,
        poll_interval: float = 1.5,
        poll_timeout: float = 600.0,
        on_progress: Any = None,
    ) -> tuple[str, JobSnapshot]:
        """Создаёт задание и ждёт его завершения.

        Опрос с линейным backoff до потолка: короткий первый интервал даёт
        отзывчивый прогресс на маленьких целях, рост интервала не молотит
        агент на длинных диапазонах.
        """
        job_id = await self.submit_batch(
            targets, probes=probes, timeout_ms=timeout_ms, port=port
        )

        loop = asyncio.get_running_loop()
        deadline = loop.time() + poll_timeout
        interval = poll_interval

        while True:
            snapshot = await self.job(job_id)
            if on_progress is not None:
                result = on_progress(snapshot)
                if asyncio.iscoroutine(result):
                    await result
            if snapshot.is_done:
                return job_id, snapshot
            if loop.time() >= deadline:
                raise AgentError(f"job {job_id} did not finish within {poll_timeout:.0f}s")
            await asyncio.sleep(interval)
            interval = min(interval * 1.25, 4.0)
