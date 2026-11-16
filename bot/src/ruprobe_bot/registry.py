"""Реестр блокировок (antifilter.network) как предфильтр прогона.

Семантика из плана 1794939000000:

* сначала смотрим базу: адрес в реестре → «с высокой вероятностью в бане»,
  проверка зондами продолжается, чтобы подтвердить фактом сети;
* membership — аннотация и пометка в отчёте, но НЕ сигнал классификатора:
  веса сигнатур и уверенность реестр не меняет;
* реестр никогда не блокирует прогон: список не скачался → работаем без него,
  пометка «реестр недоступен».
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

log = logging.getLogger(__name__)


@dataclass(slots=True)
class RegistryHit:
    """Результат проверки цели по реестру."""

    listed: bool
    source: str | None = None
    prefix: str | None = None
    # False — список не загружен (не скачался, пуст, или цель не IPv4):
    # ответить по реестру нельзя, и это не «не в реестре».
    known: bool = False
    checked_at: datetime | None = None
    # Возраст списка в секундах на момент проверки.
    list_age_s: int | None = None


class BlockRegistry:
    """Локальная копия списков префиксов с фоновым обновлением.

    Списки antifilter.network — простой текст: один префикс на строку.
    В памяти держим отсортированный список IPv4Network: линейный поиск по
    ~21k суммаризированных сетей занимает единицы миллисекунд, чего достаточно
    для одной цели на проверку.
    """

    def __init__(
        self,
        *,
        urls: list[str],
        cache_path: Path | None = None,
        refresh_s: int = 3600,
        timeout_s: float = 30.0,
    ) -> None:
        self._urls = [u for u in urls if u]
        self._cache_path = cache_path
        self._refresh_s = max(refresh_s, 60)
        self._timeout_s = timeout_s
        self._networks: list[ipaddress.IPv4Network] = []
        self._loaded_at: float | None = None
        self._source: str | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    # --- загрузка ------------------------------------------------------------

    async def refresh(self) -> bool:
        """Скачивает списки. Возвращает True при успехе.

        Список загружается целиком или не применяется вовсе: частичный
        реестр хуже отсутствующего, потому что даёт ложные «не в реестре».
        """
        networks: list[ipaddress.IPv4Network] = []
        used: list[str] = []
        async with httpx.AsyncClient(timeout=self._timeout_s, follow_redirects=True) as client:
            for url in self._urls:
                try:
                    response = await client.get(url)
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    log.warning("registry download failed: %s: %s", url, exc)
                    return False
                parsed = _parse_list(response.text)
                if not parsed:
                    log.warning("registry list empty or unparsable: %s", url)
                    return False
                networks.extend(parsed)
                used.append(url.rsplit("/", 1)[-1])

        await self._install(networks, source="+".join(used))
        if self._cache_path is not None:
            await self._save_cache(networks, self._source or "")
        return True

    async def _install(self, networks: list[ipaddress.IPv4Network], source: str) -> None:
        self._networks = sorted(set(networks), key=lambda n: (int(n.network_address), int(n.netmask)))
        self._loaded_at = time.time()
        self._source = source
        log.info("registry loaded: %d prefixes from %s", len(self._networks), source)

    async def _save_cache(self, networks: list[ipaddress.IPv4Network], source: str) -> None:
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            lines = [f"# source: {source}", f"# loaded_at: {time.time():.0f}"]
            lines.extend(n.with_prefixlen for n in sorted(networks, key=lambda n: int(n.network_address)))
            await asyncio.to_thread(
                self._cache_path.write_text, "\n".join(lines) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            log.warning("registry cache write failed: %s", exc)

    async def load_cache(self) -> bool:
        """Поднимает последний удачный список с диска (рестарт без сети)."""
        if self._cache_path is None or not self._cache_path.exists():
            return False
        try:
            text = await asyncio.to_thread(self._cache_path.read_text, encoding="utf-8")
        except OSError as exc:
            log.warning("registry cache read failed: %s", exc)
            return False
        networks: list[ipaddress.IPv4Network] = []
        source = ""
        loaded_at: float | None = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("# source:"):
                source = line.removeprefix("# source:").strip()
            elif line.startswith("# loaded_at:"):
                try:
                    loaded_at = float(line.removeprefix("# loaded_at:").strip())
                except ValueError:
                    pass
            elif line:
                try:
                    networks.append(ipaddress.IPv4Network(line, strict=False))
                except ValueError:
                    continue
        if not networks:
            return False
        await self._install(networks, source=source or "cache")
        self._loaded_at = loaded_at if loaded_at is not None else time.time()
        return True

    # --- проверка ------------------------------------------------------------

    @property
    def known(self) -> bool:
        return bool(self._networks)

    def list_age_s(self) -> int | None:
        if self._loaded_at is None:
            return None
        return int(time.time() - self._loaded_at)

    def lookup_ip(self, ip: str) -> RegistryHit:
        """Проверяет один IPv4-адрес. Синхронный и быстрый: вызывать до прогона."""
        now = datetime.now(timezone.utc)
        if not self._networks:
            return RegistryHit(listed=False, known=False, checked_at=now, list_age_s=self.list_age_s())
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return RegistryHit(listed=False, known=False, checked_at=now, list_age_s=self.list_age_s())
        for network in self._networks:
            if addr in network:
                return RegistryHit(
                    listed=True,
                    source=self._source,
                    prefix=str(network),
                    known=True,
                    checked_at=now,
                    list_age_s=self.list_age_s(),
                )
        return RegistryHit(listed=False, known=True, checked_at=now, list_age_s=self.list_age_s())

    def lookup(self, target: str) -> RegistryHit:
        """Проверка цели. Домены и IPv6 — known=False (вне рамок плана)."""
        value = target.strip()
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return RegistryHit(listed=False, known=False, checked_at=datetime.now(timezone.utc))
        return self.lookup_ip(value)

    # --- фоновое обновление --------------------------------------------------

    def start(self) -> None:
        """Запускает фоновую задачу обновления. Не блокирует старт бота."""
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _loop(self) -> None:
        # Первая загрузка при старте: сначала кэш (мгновенно), затем сеть.
        if not self.known:
            await self.load_cache()
            await self.refresh()
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._refresh_s)
                return
            except asyncio.TimeoutError:
                pass
            try:
                await self.refresh()
            except Exception:  # noqa: BLE001 — фоновая задача не должна падать
                log.exception("registry refresh failed")


def _parse_list(text: str) -> list[ipaddress.IPv4Network]:
    """Парсит список префиксов. Мусор игнорируется, не падаем."""
    networks: list[ipaddress.IPv4Network] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.IPv4Network(line, strict=False))
        except ValueError:
            # Формат списка простой, но бывают служебные строки — пропускаем.
            continue
    return networks


def registry_note_for(hit: RegistryHit | None, klass_value: str | None = None) -> str:
    """Формулирует пометку реестра для отчёта. Пустая строка — пометки нет."""
    if hit is None:
        return ""
    age = ""
    if hit.list_age_s is not None:
        hours = hit.list_age_s // 3600
        age = f"список от {hours} ч назад" if hours else "список свежий (<1 ч)"
        if hit.list_age_s > 24 * 3600:
            age += ", список устарел"
    if not hit.known:
        return "Реестр блокировок недоступен — пометка о реестре отсутствует"
    caveat = (
        "membership в реестре — не факт блокировки: списки запаздывают относительно "
        "DPI-листов и содержат shared IP/CDN"
    )
    if hit.listed:
        detail = f"источник {hit.source}, префикс {hit.prefix}" if hit.source else ""
        base = (
            "Адрес в реестре блокировок "
            f"({detail}): с высокой вероятностью под блокировкой; проверка зондами "
            "подтверждает или опровергает фактом сети"
        )
        return f"{base}. {age}. {caveat}"
    if klass_value and klass_value.startswith("block_"):
        return (
            f"В публичном реестре РКН адреса нет ({age}), но зонды показали блокировку: "
            "свежая блокировка до обновления списка, иной механизм, либо не ТСПУ"
        )
    return ""
