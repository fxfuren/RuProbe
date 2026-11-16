"""Тесты классификатора: каждый из четырёх классов должен распознаваться.

Синтетические наборы фактов повторяют наблюдаемые сигнатуры из
docs/tspu-model.md, раздел 2. Проверяется не только класс, но и то, что
вердикт остаётся вероятностным (уверенность ниже 1.0).
"""

from __future__ import annotations

import pytest

from ruprobe_bot.classifier import classify
from ruprobe_bot.models import VerdictClass


def test_dns_interference_from_substitution():
    raw = {
        "dns": {
            "query": "blocked.example",
            "answers": [
                {"resolver": "system", "status": "ok", "addresses": ["10.0.0.1"]},
                {"resolver": "1.1.1.1:53", "status": "ok", "addresses": ["93.184.216.34"]},
            ],
            "mismatch": True,
            "substituted": True,
        }
    }
    result = classify(raw)
    assert result.klass is VerdictClass.DNS_INTERFERENCE
    assert result.confidence > 0.5
    codes = {s.code for s in result.signals}
    assert "dns_substitution" in codes


def test_dns_refused_is_dns_interference():
    raw = {
        "dns": {
            "query": "blocked.example",
            "answers": [
                {"resolver": "system", "status": "refused", "addresses": []},
            ],
            "mismatch": False,
            "substituted": False,
        }
    }
    result = classify(raw)
    assert result.klass is VerdictClass.DNS_INTERFERENCE
    assert any(s.code == "dns_refused" for s in result.signals)


def test_dns_ok_is_not_classified_as_interference():
    """Домен резолвится одинаково у всех — этот слой чист, классифицировать нечего."""
    raw = {
        "dns": {
            "query": "example.com",
            "answers": [
                {"resolver": "system", "status": "ok", "addresses": ["1.2.3.4"]},
                {"resolver": "1.1.1.1:53", "status": "ok", "addresses": ["1.2.3.4"]},
            ],
            "mismatch": False,
            "substituted": False,
        },
        "tcp": {"connected": True, "reset_received": False, "timeout_happened": False, "rtt_ms": 20.0},
        "tls_full": {"tls_handshake": True, "http_status": 200},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.UNAVAILABLE_OTHER
    assert result.confidence < 0.5


def test_block_sni_from_silent_drop_with_working_control():
    raw = {
        "dns": {
            "query": "blocked.example",
            "answers": [{"resolver": "system", "status": "ok", "addresses": ["1.2.3.4"]}],
            "mismatch": False,
            "substituted": False,
        },
        "tcp": {"connected": True, "reset_received": False, "timeout_happened": False, "rtt_ms": 25.0},
        "sni": {
            "handshake_started": True,
            "server_responded": False,
            "silent_drop": True,
            "reset_received": False,
            "close_notify": False,
        },
        "sni_control": {"server_responded": True, "silent_drop": False},
        "tls_full": {"tls_handshake": False, "timeout_happened": True, "reset_received": False},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.BLOCK_SNI
    codes = {s.code for s in result.signals}
    assert {"sni_silent_drop", "control_sni_ok", "no_rst"} <= codes
    assert result.confidence >= 0.7


def test_block_l3l4_all_ports_dead():
    raw = {
        "tcp": {"connected": False, "reset_received": False, "timeout_happened": True, "rtt_ms": 3000.0},
        "tcp_alt_ports": [
            {"port": 80, "connected": False, "timeout_happened": True, "reset_received": False},
            {"port": 8080, "connected": False, "timeout_happened": True, "reset_received": False},
            {"port": 8443, "connected": False, "timeout_happened": True, "reset_received": False},
        ],
        "icmp": {"alive": True, "rtt_ms": 12.0, "packet_loss": 0.0},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.BLOCK_L3L4
    codes = {s.code for s in result.signals}
    assert {"syn_no_answer", "all_ports_dead", "icmp_alive"} <= codes


def test_rst_on_connect_alone_is_not_l3l4_block():
    """Мгновенный RST — скорее аномалия, чем штатное поведение ТСПУ."""
    raw = {
        "tcp": {"connected": False, "reset_received": True, "timeout_happened": False, "rtt_ms": 3.0},
        "tcp_alt_ports": [
            {"port": 80, "connected": True, "timeout_happened": False, "reset_received": False},
        ],
        "icmp": {"alive": True, "rtt_ms": 10.0, "packet_loss": 0.0},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.UNAVAILABLE_OTHER
    assert any(s.code == "rst_on_connect" for s in result.signals)
    assert any(s.code == "port_selective" for s in result.signals)


def test_degradation_from_low_throughput_with_working_handshake():
    raw = {
        "tls_full": {"tls_handshake": True, "http_status": 200},
        "throughput": {
            "bytes_requested": 1 << 20,
            "bytes_received": 4096,
            "duration_ms": 5000.0,
            "throughput_bps": 6_553.0,
            "retransmits": 2,
            "timed_out": True,
            "sawtooth": True,
        },
        "icmp": {"alive": True, "rtt_ms": 15.0, "packet_loss": 0.0},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.DEGRADATION
    codes = {s.code for s in result.signals}
    assert {"low_throughput", "transfer_stalled", "short_request_ok"} <= codes


def test_healthy_target_is_unavailable_other():
    raw = {
        "tcp": {"connected": True, "timeout_happened": False, "reset_received": False, "rtt_ms": 15.0},
        "tls_full": {"tls_handshake": True, "http_status": 200},
        "throughput": {
            "bytes_requested": 1 << 20,
            "bytes_received": 1 << 20,
            "duration_ms": 900.0,
            "throughput_bps": 9_300_000.0,
            "retransmits": 0,
            "timed_out": False,
            "sawtooth": False,
        },
        "icmp": {"alive": True, "rtt_ms": 12.0, "packet_loss": 0.0},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.UNAVAILABLE_OTHER
    assert result.confidence <= 0.35


def test_empty_facts_do_not_crash():
    result = classify({})
    assert result.klass is VerdictClass.UNAVAILABLE_OTHER
    assert result.confidence <= 1.0


@pytest.mark.parametrize(
    "raw",
    [
        {"tcp": {"connected": False, "timeout_happened": True}},
        {"tls_full": {"timeout_happened": True}, "tcp": {"connected": True}},
    ],
)
def test_confidence_never_reaches_certainty(raw):
    """Модель запрещает детерминированный вердикт: уверенность всегда < 1."""
    result = classify(raw)
    assert 0.0 <= result.confidence < 1.0


def test_dead_network_is_unavailable_other_not_block():
    """Все мёртво: tcp timeout, icmp dead, neighbors 0/16 -> UNAVAILABLE_OTHER."""
    raw = {
        "tcp": {"connected": False, "reset_received": False, "timeout_happened": True},
        "tcp_alt_ports": [
            {"port": 80, "connected": False, "timeout_happened": True},
            {"port": 8080, "connected": False, "timeout_happened": True},
            {"port": 8443, "connected": False, "timeout_happened": True},
        ],
        "icmp": {"alive": False, "method": "icmp", "timeout_happened": True, "packet_loss": 1.0},
        "neighbors": {"probed": 16, "alive": 0, "dead": 16, "alive_ratio": 0.0},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.UNAVAILABLE_OTHER
    assert result.confidence <= 0.65
    assert any(s.code == "network_unreachable" for s in result.signals)


def test_icmp_alive_all_ports_dead_is_block_l3l4():
    raw = {
        "tcp": {"connected": False, "reset_received": False, "timeout_happened": True},
        "tcp_alt_ports": [
            {"port": 80, "connected": False, "timeout_happened": True},
            {"port": 8080, "connected": False, "timeout_happened": True},
            {"port": 8443, "connected": False, "timeout_happened": True},
        ],
        "icmp": {"alive": True, "method": "icmp", "rtt_ms": 10.0, "packet_loss": 0.0},
        "neighbors": {"probed": 16, "alive": 14, "dead": 2, "alive_ratio": 0.875},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.BLOCK_L3L4
    assert result.confidence >= 0.7


def test_one_port_alive_others_dead_is_port_selective_or_unavailable():
    """Один порт жив, остальные мертвы -> BLOCK_L3L4 с port_selective либо UNAVAILABLE_OTHER при RST."""
    alive_raw = {
        "tcp": {"connected": False, "reset_received": False, "timeout_happened": True},
        "tcp_alt_ports": [
            {"port": 80, "connected": True, "timeout_happened": False},
            {"port": 8080, "connected": False, "timeout_happened": True},
            {"port": 8443, "connected": False, "timeout_happened": True},
        ],
        "icmp": {"alive": True, "method": "icmp", "packet_loss": 0.0},
    }
    result = classify(alive_raw)
    assert result.klass is VerdictClass.BLOCK_L3L4
    assert any(s.code == "port_selective" for s in result.signals)

    rst_raw = dict(alive_raw)
    rst_raw["tcp"] = {"connected": False, "reset_received": True, "timeout_happened": False}
    result2 = classify(rst_raw)
    assert result2.klass is VerdictClass.UNAVAILABLE_OTHER


def test_rst_on_443_with_other_ports_alive_is_unavailable_other():
    raw = {
        "tcp": {"connected": False, "reset_received": True, "timeout_happened": False},
        "tcp_alt_ports": [
            {"port": 80, "connected": True},
            {"port": 8080, "connected": True},
            {"port": 8443, "connected": True},
        ],
        "icmp": {"alive": True, "method": "icmp", "packet_loss": 0.0},
    }
    result = classify(raw)
    assert result.klass is VerdictClass.UNAVAILABLE_OTHER


def test_block_l3l4_without_alt_ports_is_capped_and_annotated():
    raw = {
        "tcp": {"connected": False, "reset_received": False, "timeout_happened": True},
        "icmp": {"alive": True, "method": "icmp", "rtt_ms": 10.0, "packet_loss": 0.0},
    }
    result = classify(raw)
    assert result.confidence <= 0.55
    assert "альтернативные порты" in (result.notes or "")


def test_icmp_tcp_fallback_does_not_boost_l3l4():
    raw = {
        "tcp": {"connected": False, "reset_received": False, "timeout_happened": True},
        "icmp": {
            "alive": False,
            "method": "tcp_fallback",
            "error": "icmp unavailable: no raw socket",
            "timeout_happened": True,
            "packet_loss": 1.0,
        },
        "neighbors": {"probed": 16, "alive": 12, "dead": 4, "alive_ratio": 0.75},
    }
    result = classify(raw)
    assert not any(s.code == "icmp_alive" for s in result.signals)
    assert any(s.code == "icmp_fallback_used" for s in result.signals)
    if result.klass is VerdictClass.BLOCK_L3L4:
        assert result.confidence <= 0.55


def test_throughput_ignored_without_tls_handshake():
    raw = {
        "tcp": {"connected": True, "timeout_happened": False, "reset_received": False},
        "tls_full": {"tls_handshake": False, "timeout_happened": True},
        "throughput": {
            "bytes_requested": 1 << 20,
            "bytes_received": 0,
            "throughput_bps": 0.0,
            "timed_out": True,
            "sawtooth": True,
            "retransmits": 2,
        },
    }
    result = classify(raw)
    assert result.klass is not VerdictClass.DEGRADATION
    assert not any(s.code == "low_throughput" for s in result.signals)


def test_sni_skipped_for_ip_is_annotated():
    raw = {
        "tcp": {"connected": True, "timeout_happened": False, "reset_received": False, "rtt_ms": 15.0},
        "udp": {"responded": True},
        "icmp": {"alive": True, "method": "icmp"},
        "neighbors": {"probed": 16, "alive": 16, "dead": 0, "alive_ratio": 1.0},
    }
    result = classify(raw)
    assert "sni_skipped_for_ip" in (result.notes or "")
