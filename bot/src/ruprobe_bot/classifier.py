"""Классификатор: сигнатуры → класс отказа + уверенность.

Правила выведены из docs/tspu-model.md, раздел 2. Принципиальные ограничения:

* вердикт **вероятностный**; бот не утверждает причину (раздел 5.4 модели);
* класс `unavailable_other` — полноценный результат, а не «не смогли решить»:
  недоступность и «недоступность из-за ТСПУ» — разные вещи;
* контрольные пробы повышают уверенность, но их отсутствие не делает
  классификацию недействительной — только менее надёжной.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import VerdictClass

# Порог, ниже которого скорость передачи считается деградацией, а не нормой.
# Обоснование: capacity 2–10 дропает пакеты вероятностно, TCP маскирует это
# под перегрузку, и «в разы медленнее» на коротком замере — уже сигнал.
DEGRADED_BPS = 512 * 1024
# Заметная потеря пакетов на ICMP при живом TCP — характерный признак
# вероятностного дропа.
DEGRADED_LOSS = 0.2


@dataclass(slots=True)
class Signal:
    """Одна сработавшая сигнатура: код, человеческое описание, вес."""

    code: str
    description: str
    weight: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "description": self.description, "weight": self.weight}


@dataclass(slots=True)
class Classification:
    klass: VerdictClass
    confidence: float
    signals: list[Signal] = field(default_factory=list)
    notes: str = ""

    def signals_as_dicts(self) -> list[dict[str, Any]]:
        return [s.as_dict() for s in self.signals]


def classify(raw: dict[str, Any]) -> Classification:
    """Классифицирует набор фактов одного ProbeResult.

    `raw` — это Facts из ответа агента: ключи dns, doh, tcp, tcp_alt_ports,
    sni, sni_control, tls_full, throughput, udp, icmp, neighbors.
    """
    dns = raw.get("dns") or {}
    doh = raw.get("doh") or {}
    tcp = raw.get("tcp") or {}
    alt_ports = raw.get("tcp_alt_ports") or []
    sni = raw.get("sni") or {}
    sni_control = raw.get("sni_control") or {}
    tls_full = raw.get("tls_full") or {}
    throughput = raw.get("throughput") or {}
    icmp = raw.get("icmp") or {}
    neighbors = raw.get("neighbors") or {}

    signals: list[Signal] = []

    # --- 2.4 DNS-вмешательство ------------------------------------------------
    dns_signals = _dns_signals(dns, doh, signals)
    if dns_signals is not None:
        return dns_signals

    # --- живость сети ---------------------------------------------------------
    network_dead = bool(icmp) and not icmp.get("alive") and bool(neighbors) and not neighbors.get("alive")
    if network_dead:
        signals.append(
            Signal("network_unreachable", "ICMP и соседние адреса недоступны: похоже на проблему сети, а не фильтра", 0.5)
        )

    # --- 2.2 умная блокировка по SNI -----------------------------------------
    # Приоритетная сигнатура: SYN-ACK получен, ClientHello ушёл, дальше тишина.
    silent_drop = bool(sni.get("silent_drop"))
    control_ok = bool(sni_control.get("server_responded"))
    tcp_ok = bool(tcp.get("connected"))

    if silent_drop and tcp_ok:
        signals.append(
            Signal("sni_silent_drop", "SYN-ACK получен, ClientHello отправлен, ответа нет до таймаута", 0.45)
        )
        if control_ok:
            signals.append(
                Signal("control_sni_ok", "Тот же адрес с другим SNI отвечает: блокировка по домену, а не по адресу", 0.35)
            )
        if not tls_full.get("tls_handshake") and tls_full.get("timeout_happened"):
            signals.append(
                Signal("full_handshake_timeout", "Полный TLS-handshake не завершился, обрыв молчаливый", 0.1)
            )
        if not sni.get("reset_received"):
            signals.append(
                Signal("no_rst", "RST не отправлен — согласуется с проектом ТСПУ, где send RST off включён", 0.1)
            )
        return _finalize(VerdictClass.BLOCK_SNI, signals)

    # --- 2.3 деградация протокола --------------------------------------------
    degraded = _degradation_check(throughput, icmp, tls_full, signals)
    if degraded is not None:
        return degraded

    # --- 2.1 тупая блокировка по L3/L4 ---------------------------------------
    if not tcp_ok:
        if tcp.get("timeout_happened"):
            signals.append(Signal("syn_no_answer", "SYN ушёл, ответа нет: соединение не устанавливается", 0.4))
        if tcp.get("reset_received"):
            signals.append(
                Signal("rst_on_connect", "Мгновенный RST на попытке соединения — скорее аномалия, чем штатное поведение ТСПУ", 0.2)
            )
        all_ports_dead = alt_ports and all(not p.get("connected") for p in alt_ports)
        if all_ports_dead:
            signals.append(
                Signal("all_ports_dead", "Все проверенные порты недоступны: правило по адресу, а не по порту", 0.3)
            )
        any_port_alive = any(p.get("connected") for p in alt_ports)
        if any_port_alive:
            signals.append(
                Signal("port_selective", "Часть портов отвечает: похоже на правило по порту", 0.25)
            )
        if icmp.get("alive"):
            signals.append(Signal("icmp_alive", "ICMP отвечает: сеть жива, фильтруется TCP", 0.15))
        if neighbors and neighbors.get("alive") and neighbors.get("dead"):
            signals.append(
                Signal("partial_neighborhood", "Часть соседних адресов недоступна: возможен запрет префикса", 0.2)
            )

        if signals:
            klass = VerdictClass.BLOCK_L3L4
            if tcp.get("reset_received") and not all_ports_dead:
                # RST на одном порту без подтверждения по другим — не «тупая блокировка».
                klass = VerdictClass.UNAVAILABLE_OTHER
            return _finalize(klass, signals, base=0.15)
        return Classification(
            klass=VerdictClass.UNAVAILABLE_OTHER,
            confidence=0.2,
            signals=[Signal("no_data", "Недостаточно фактов для классификации", 0.0)],
            notes="Зонды не дали различимых сигнатур.",
        )

    # TCP устанавливается, но ничего не отвечает дальше и нет SNI-сигнатуры.
    if tcp_ok and not tls_full.get("tls_handshake") and not silent_drop:
        if tls_full.get("timeout_happened"):
            signals.append(
                Signal("handshake_timeout", "TCP-хендшейк проходит, TLS — нет, исход по таймауту", 0.3)
            )
        if tls_full.get("reset_received"):
            signals.append(
                Signal("handshake_rst", "RST во время handshake: возможен HTTPS-Reset по списку", 0.3)
            )
        if signals:
            return _finalize(VerdictClass.UNAVAILABLE_OTHER, signals, base=0.2)

    return Classification(
        klass=VerdictClass.UNAVAILABLE_OTHER,
        confidence=0.2 if not signals else 0.35,
        signals=signals or [Signal("no_data", "Недостаточно фактов для классификации", 0.0)],
        notes="Классификация не подтверждена: цель отвечает, сигнатур отказа не найдено.",
    )


def _dns_signals(
    dns: dict[str, Any], doh: dict[str, Any], signals: list[Signal]
) -> Classification | None:
    """Возвращает классификацию DNS-вмешательства, если сигнатуры есть."""
    answers = dns.get("answers") or []
    if not answers:
        return None

    statuses = {a.get("status") for a in answers}
    local = next((a for a in answers if a.get("resolver") == "system"), None)
    local_ok = bool(local and local.get("status") == "ok" and local.get("addresses"))

    if dns.get("substituted"):
        signals.append(
            Signal("dns_substitution", "Резолверы отдают разные адреса: возможна подмена ответа", 0.5)
        )
    if dns.get("mismatch") and not dns.get("substituted"):
        signals.append(
            Signal("dns_mismatch", "Ответы резолверов расходятся — самостоятельный сигнал", 0.3)
        )
    if "nxdomain" in statuses:
        signals.append(Signal("dns_nxdomain", "Резолвер вернул NXDOMAIN", 0.3))
    if "refused" in statuses:
        signals.append(Signal("dns_refused", "Резолвер отклонил запрос (REFUSED)", 0.3))
    if "servfail" in statuses:
        signals.append(Signal("dns_servfail", "Разрешение не удалось (SERVFAIL)", 0.3))
    if "timeout" in statuses:
        signals.append(Signal("dns_timeout", "Часть резолверов не ответила: возможен перехват порта 53", 0.3))

    doh_answers = doh.get("answers") or []
    doh_ok = any(a.get("status") == "ok" and a.get("addresses") for a in doh_answers)
    if doh_ok and not local_ok:
        signals.append(
            Signal("doh_differs", "DoH отвечает, локальный резолвер — нет: вмешательство на пути резолвера", 0.35)
        )

    if not signals:
        return None

    # Правило выхода: DNS-слой классифицируется как вмешательство, если есть
    # либо содержательное расхождение (подмена), либо локальный резолвер не смог
    # ответить, а внешние ответили. Простое «локальный ответил ok» ничего не
    # оправдывает: локальный резолвер мог отдать заглушку, и именно расхождение
    # адресов это и показывает.
    if not dns.get("mismatch") and not dns.get("substituted") and local_ok:
        return None
    return _finalize(VerdictClass.DNS_INTERFERENCE, signals, base=0.15)


def _degradation_check(
    throughput: dict[str, Any],
    icmp: dict[str, Any],
    tls_full: dict[str, Any],
    signals: list[Signal],
) -> Classification | None:
    """Класс 2.3 — деградация capacity. Без зонда throughput не видна."""
    if not throughput:
        return None

    bps = throughput.get("throughput_bps") or 0.0
    received = throughput.get("bytes_received") or 0
    requested = throughput.get("bytes_requested") or 0
    retransmits = throughput.get("retransmits") or 0
    timed_out = bool(throughput.get("timed_out"))
    sawtooth = bool(throughput.get("sawtooth"))

    # Соединение и handshake проходят, короткий запрос отвечает — и именно
    # поэтому деградацию легко пропустить.
    handshake_ok = bool(tls_full.get("tls_handshake"))
    short_ok = bool(tls_full.get("http_status"))

    if bps and bps < DEGRADED_BPS:
        signals.append(
            Signal("low_throughput", f"Пропускная способность {bps / 1024:.0f} Кбит/с ниже ожидаемой", 0.4)
        )
    if timed_out and requested and received < requested:
        signals.append(
            Signal("transfer_stalled", "Передача не завершилась в отведённое время", 0.35)
        )
    if sawtooth:
        signals.append(Signal("sawtooth_window", "Пилообразный профиль передачи: похоже на потери и повторные передачи", 0.25))
    if retransmits > 0:
        signals.append(
            Signal("retransmits", f"Признаки повторных передач ({retransmits})", min(0.15 * retransmits, 0.3))
        )
    if handshake_ok and short_ok and (signals and (bps < DEGRADED_BPS or timed_out)):
        signals.append(
            Signal("short_request_ok", "Короткий запрос отвечает, длинная передача страдает", 0.2)
        )
    if icmp.get("alive") and icmp.get("packet_loss", 0) < 0.05 and timed_out:
        signals.append(Signal("icmp_normal", "ICMP в норме при страдающей передаче данных", 0.15))

    if not signals:
        return None
    if all(s.code in {"retransmits"} for s in signals):
        # Одни повторные передачи без падения скорости — слабый сигнал.
        return None
    return _finalize(VerdictClass.DEGRADATION, signals, base=0.15)


def _finalize(
    klass: VerdictClass, signals: list[Signal], base: float = 0.15
) -> Classification:
    """Считает уверенность как насыщающуюся сумму весов сигнатур.

    Сумма весов, а не максимум: одиночная сигнатура почти никогда не даёт
    достаточной уверенности, и это осознанно — модель требует вероятностной
    оценки, а не вердикта.
    """
    total = base + sum(s.weight for s in signals)
    confidence = max(0.0, min(0.95, total))
    return Classification(klass=klass, confidence=round(confidence, 2), signals=signals)


# Человекочитаемые подписи классов. Формулировки намеренно осторожные.
CLASS_LABELS: dict[VerdictClass, str] = {
    VerdictClass.BLOCK_L3L4: "блокировка по адресу/порту/транспорту",
    VerdictClass.BLOCK_SNI: "блокировка по признакам протокола (SNI)",
    VerdictClass.DEGRADATION: "деградация пропускной способности",
    VerdictClass.DNS_INTERFERENCE: "вмешательство в разрешение имён",
    VerdictClass.UNAVAILABLE_OTHER: "недоступность не по ТСПУ",
}


def class_label(klass: VerdictClass) -> str:
    return CLASS_LABELS.get(klass, klass.value)
