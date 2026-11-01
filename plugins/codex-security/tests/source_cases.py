"""Shared source examples for inventory and ranking integration tests.

Keep these examples representative: security-relevant behavior can live in
build files, dependencies, tests, CI, documentation, and generated code. Selection
and previews do not depend on language-specific support or directory names.
"""

from __future__ import annotations

from typing import NamedTuple


class SourceCase(NamedTuple):
    path: str
    before: str
    after: str


SOURCE_CASES = (
    SourceCase(
        "Dockerfile",
        "FROM python:3.13-slim\nCOPY service.py /app/service.py\nRUN chmod 644 /app/service.py",
        "FROM python:3.13-slim\nCOPY service.py /app/service.py\nRUN chmod 666 /app/service.py",
    ),
    SourceCase(
        "vendor/handler.unlisted",
        'db.execute("SELECT name FROM records WHERE id = ?", [record_id])',
        'db.execute("SELECT name FROM records WHERE id = " + record_id)',
    ),
    SourceCase(
        "tests/service.py",
        "def request(endpoint):\n    return requests.get(endpoint, verify=True)",
        "def request(endpoint):\n    return requests.get(endpoint, verify=False)",
    ),
    SourceCase(
        ".circleci/config.yaml",
        "jobs:\n  build:\n    steps:\n      - run: printf '%s' \"$BUILD_LABEL\"",
        'jobs:\n  build:\n    steps:\n      - run: sh -c "$BUILD_LABEL"',
    ),
    SourceCase(
        "docs/view.ejs",
        "<p><%= request.query.title %></p>",
        "<p><%- request.query.title %></p>",
    ),
    SourceCase(
        "generated/client.min.js",
        "document.body.textContent=location.hash.slice(1);",
        "document.body.innerHTML=location.hash.slice(1);",
    ),
)
