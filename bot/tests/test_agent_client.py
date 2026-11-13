"""Тесты клиента агента: контракт, потеря задания, отсутствие ретраев пробы."""

from __future__ import annotations

import httpx
import pytest

from ruprobe_bot.agent_client import AgentClient, AgentError, AgentJobLost


def _client(handler) -> AgentClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://agent:8080")
    return AgentClient("http://agent:8080", client=http)


async def test_submit_batch_sends_expected_payload():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = request.url.path
        seen["json"] = __import__("json").loads(request.content)
        return httpx.Response(202, json={"job_id": "abc", "total": 2})

    client = _client(handler)
    job_id = await client.submit_batch(["example.com"], probes=["tcp"], timeout_ms=2500)
    assert job_id == "abc"
    assert seen["url"] == "/probe/batch"
    assert seen["json"]["targets"] == ["example.com"]
    assert seen["json"]["probes"] == ["tcp"]
    assert seen["json"]["timeout_ms"] == 2500


async def test_missing_job_raises_agent_job_lost():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "job not found"})

    client = _client(handler)
    with pytest.raises(AgentJobLost):
        await client.job("gone")


async def test_unreachable_agent_raises_agent_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = _client(handler)
    with pytest.raises(AgentError):
        await client.job("abc")


async def test_run_job_polls_until_done_and_reports_progress():
    calls = {"job": 0}
    progress: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/probe/batch":
            return httpx.Response(202, json={"job_id": "j1", "total": 3})
        calls["job"] += 1
        if calls["job"] < 2:
            return httpx.Response(
                200,
                json={
                    "job_id": "j1",
                    "status": "running",
                    "progress": {"completed": 1, "total": 3},
                    "results": [],
                },
            )
        return httpx.Response(
            200,
            json={
                "job_id": "j1",
                "status": "done",
                "progress": {"completed": 3, "total": 3},
                "results": [{"target": "example.com", "kind": "domain", "facts": {}}],
            },
        )

    client = _client(handler)

    def on_progress(snapshot) -> None:  # noqa: ANN001
        progress.append(snapshot.progress.completed)

    job_id, snapshot = await client.run_job(
        ["example.com"], poll_interval=0.01, on_progress=on_progress
    )
    assert job_id == "j1"
    assert snapshot.is_done
    assert snapshot.progress.percent == 100
    assert progress == [1, 3]


async def test_run_job_times_out_without_retrying_the_probe():
    """Повтор — это новое измерение, поэтому клиент не пересоздаёт задание."""
    batches = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/probe/batch":
            batches["count"] += 1
            return httpx.Response(202, json={"job_id": "j1", "total": 1})
        return httpx.Response(
            200,
            json={"job_id": "j1", "status": "running", "progress": {"completed": 0, "total": 1}},
        )

    client = _client(handler)
    with pytest.raises(AgentError, match="did not finish"):
        await client.run_job(["example.com"], poll_interval=0.01, poll_timeout=0.05)
    assert batches["count"] == 1


async def test_health_error_is_agent_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = _client(handler)
    with pytest.raises(AgentError):
        await client.health()
