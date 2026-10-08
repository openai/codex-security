"""JSON number semantics shared by contract checks and report projections."""

from __future__ import annotations

import json
import math
import re
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
    """Retain source decimal metadata while behaving as a float."""

    def __new__(cls, source: str | float) -> JsonFloat:
        value = super().__new__(cls, source)
        value.source = str(source)
        value.exact = _number_key(value.source)
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


_JSON_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)')


def dumps_json(value: Any, **options: Any) -> str:
    """Keep exact decoded numbers while using the standard JSON writer's behavior."""
    encoded = json.dumps(value, **options)

    def numbers():
        pending = [value]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                keys = sorted(item) if options.get("sort_keys") else item
                pending.extend(reversed([item[key] for key in keys]))
            elif isinstance(item, (list, tuple)):
                pending.extend(reversed(item))
            elif isinstance(item, (int, float)) and not isinstance(item, bool):
                if not isinstance(item, float) or math.isfinite(item):
                    yield item

    numeric_values = numbers()

    def replace(match: re.Match[str]) -> str:
        if match.group(1) is None:
            return match.group()
        number = next(numeric_values)
        if isinstance(number, JsonFloat) and number.exact != json_number_key(float(number)):
            return number.source
        return match.group()

    return _JSON_TOKEN.sub(replace, encoded)
