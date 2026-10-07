"""Shared source examples for inventory and ranking integration tests.

Add source-selection and preview regressions here so every inventory and ranking
mode uses the same examples, including source with unfamiliar or no extensions.
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
    SourceCase("scripts/entrypoint", "exec service --before", "exec service --after"),
    SourceCase("src/handler.unlisted", "render(before)", "render(after)"),
    SourceCase(
        "src/raw.cpp",
        "void before() {}",
        'void before() {}\nconst char* text = R"tag("{)tag";\nvoid after() {}',
        "function before\nfunction after",
    ),
    SourceCase(
        "src/raw.go",
        "package sample\n\nfunc Before() {}",
        "package sample\n\nfunc Before() {}\n\nconst Root = `C:\\`\n\nfunc After() {}",
        "function Before\nfunction After",
    ),
    *(
        SourceCase(
            f"src/{name}.cs",
            "class Before {}",
            f"class Before {{}}\nclass Service {{\n  string Text = {literal};\n"
            "  void Visible() {}\n}\nclass After {}",
            "class Before\nclass Service\nmethod Service.Visible\nclass After",
        )
        for name, literal in (
            ("three_quotes", '"""\n    { "a": "b" }\n    """'),
            ("four_quotes", '""""\n    { "a": """ }\n    """"'),
            ("five_quotes", '""""" contains """" and { """""'),
        )
    ),
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
