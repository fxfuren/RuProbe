"""Клавиатуры бота."""

from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup

MAIN_MENU = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="Проверить"), KeyboardButton(text="Помощь")],
    ],
    resize_keyboard=True,
)


def quick_targets() -> InlineKeyboardMarkup:
    """Быстрые примеры целей: разные виды, которые понимает агент."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="example.com", callback_data="quick:example.com"),
                InlineKeyboardButton(text="1.1.1.1", callback_data="quick:1.1.1.1"),
            ],
            [
                InlineKeyboardButton(
                    text="Диапазон /29", callback_data="quick:192.0.2.0/29"
                ),
            ],
        ]
    )
