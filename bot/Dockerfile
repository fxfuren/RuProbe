# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Зависимости отдельным слоем: правка кода не переустанавливает пакеты.
COPY pyproject.toml ./
RUN pip install --upgrade pip \
    && pip install .

COPY src/ ./src/
COPY alembic.ini ./
COPY alembic/ ./alembic/

# Непривилегированный пользователь с постоянным uid: том должен быть доступен
# и после пересоздания контейнера.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin ruprobe \
    && mkdir -p /data \
    && chown -R ruprobe:ruprobe /data /app
USER ruprobe

ENV PYTHONPATH=/app/src \
    DB_PATH=/data/ruprobe.sqlite3

# Миграции применяются на старте: отдельного шага деплоя нет, а схема должна
# быть актуальной до первого запроса пользователя.
CMD ["sh", "-c", "python -m alembic upgrade head && python -m ruprobe_bot.main"]
