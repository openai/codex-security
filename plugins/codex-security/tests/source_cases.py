"""Shared source examples for inventory and ranking integration tests.

Add source-selection regressions here so every inventory and ranking mode uses
the same examples. Expectations are independent of the production allowlist.
"""

from __future__ import annotations

from typing import NamedTuple


class SourceCase(NamedTuple):
    path: str
    before: str
    after: str
    # Sampled previews preserve the changed text; structural previews override it.
    preview: str | None = None


SOURCE_CASES = (
    SourceCase(
        "infra/main.tf",
        'variable "enabled" { default = false }',
        'variable "enabled" { default = true }',
    ),
    SourceCase(
        "ios/ViewController.m",
        'NSString *greeting = @"hello";',
        'NSString *greeting = @"goodbye";',
    ),
    SourceCase(
        "ios/Bridge.mm",
        "@implementation Bridge\n@end",
        "@implementation Bridge\n@end\n// Changed.",
    ),
    SourceCase(
        "ios/ViewController.h",
        "@interface ViewController : NSObject\n@end",
        "@interface ViewController : NSObject\n@end\n// Changed.",
    ),
    *(
        SourceCase(
            f"include/{name}",
            "inline int before() { return 1; }",
            "inline int after() { return 2; }",
            "function after",
        )
        for name in ("base.h", "base.hpp", "lower.hh", "lower.hxx", "upper.HH", "upper.HXX")
    ),
    SourceCase("contracts/Vault.sol", "uint256 public limit = 1;", "uint256 public limit = 2;"),
    SourceCase(
        "contracts/Vault.vy",
        "stored: public(uint256)",
        "stored: public(uint256)\nowner: public(address)",
    ),
    SourceCase("src/routes/+page.svelte", "<p>before</p>", "<p>after</p>"),
    *(
        SourceCase(f"src/{filename}", content, content.replace("count = 0", "count = 1"))
        for filename, content in (
            (
                "Counter.svelte",
                '<script lang="ts">\nlet count = 0;\n</script>\n<button>{count}</button>',
            ),
            ("routes/profile.ejs", "<% const count = 0; %>\n<p><%= count %></p>"),
            ("profile.EJS", "<% const count = 0; %>\n<p><%= count %></p>"),
            ("show.html.erb", "<% count = 0 %>\n<p><%= count %></p>"),
            ("card.phtml", "<?php $count = 0; ?>\n<p><?= $count ?></p>"),
            ("index.jsp", "<% int count = 0; %>\n<p><%= count %></p>"),
            ("list.jspx", "<jsp:scriptlet>int count = 0;</jsp:scriptlet>\n<p>${count}</p>"),
            ("Index.cshtml", "@{ var count = 0; }\n<p>@count</p>"),
            ("Counter.razor", "<p>@count</p>\n@code { int count = 0; }"),
            ("Default.ASPX", "<% var count = 0; %>\n<p><%= count %></p>"),
            ("Header.ascx", "<% var count = 0; %>\n<p><%= count %></p>"),
        )
    ),
)
