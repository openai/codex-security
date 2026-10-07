"""Shared source examples for inventory and ranking integration tests.

Keep these examples representative: selection and previews do not depend on
language-specific support. Every inventory and ranking mode uses the same cases.
"""

from __future__ import annotations

from typing import NamedTuple


class SourceCase(NamedTuple):
    path: str
    before: str
    after: str


SOURCE_CASES = (
    SourceCase("scripts/entrypoint", "exec service --before", "exec service --after"),
    SourceCase("src/handler.unlisted", "render(before)", "render(after)"),
    SourceCase(
        "src/service.py",
        "def handle():\n    return before",
        "def handle():\n    return after",
    ),
    SourceCase(
        "infra/policy.yaml",
        "access:\n  enabled: false",
        "access:\n  enabled: true",
    ),
    SourceCase(
        "src/view.ejs",
        "<% const count = 0; %>\n<p><%= count %></p>",
        "<% const count = 1; %>\n<p><%= count %></p>",
    ),
)
