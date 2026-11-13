"""RuProbe — Telegram-бот проверки доступности IP, доменов и диапазонов."""

# Версию дублирует pyproject.toml; здесь она нужна только для логов.
__version__ = "0.1.0"

from .classifier import Classification, Signal, classify
from .models import CheckStatus, TargetKind, VerdictClass
from .service import CheckReport, TargetReport, run_check
from .settings import Settings, get_settings

__all__ = [
    "CheckReport",
    "CheckStatus",
    "Classification",
    "Settings",
    "Signal",
    "TargetKind",
    "TargetReport",
    "VerdictClass",
    "__version__",
    "classify",
    "get_settings",
    "run_check",
]
