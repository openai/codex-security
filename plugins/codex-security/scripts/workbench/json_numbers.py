"""JSON number semantics shared by contract checks and report projections."""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any


def _number_key(source: str) -> tuple[int, str, int]:
    mantissa, _, exponent = source.lower().partition("e")
    whole, _, fraction = mantissa.lstrip("-").partition(".")
    digits = (whole + fraction).lstrip("0")
    coefficient = digits.rstrip("0")
    if not coefficient:
        return 0, "", 0
    # Parse only the integer exponent with Decimal: its coefficient has no
    # context rounding or JSON exponent range, and int() avoids string digit caps.
    power = int(Decimal(exponent or "0")) - len(fraction) + len(digits) - len(coefficient)
    return (-1 if mantissa.startswith("-") else 1), coefficient, power


class JsonFloat(float):
    """Keep the source decimal for checks without changing JSON serialization."""

    def __new__(cls, source: str | float) -> JsonFloat:
        value = super().__new__(cls, source)
        value.exact = _number_key(str(source))
        return value


def json_number_key(value: int | float) -> tuple[int, str, int]:
    return value.exact if isinstance(value, JsonFloat) else _number_key(str(value))


def is_json_integer(value: object) -> bool:
    if isinstance(value, JsonFloat):
        return math.isfinite(value) and value.exact[2] >= 0
    if isinstance(value, float):
        return value.is_integer()
    return isinstance(value, int) and not isinstance(value, bool)


def normalize_json_integer(value: Any) -> Any:
    return int(value) if is_json_integer(value) else value
