"""Build deterministic structural or sampled source previews for rank inputs."""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path

DEFAULT_PREVIEW_BYTES = 1024
PREVIEW_HEAD_LINES = 12
PREVIEW_SAMPLE_LINES = 10

TEXT_CODE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".clj",
    ".cpp",
    ".cs",
    ".css",
    ".cue",
    ".cxx",
    ".dart",
    ".ex",
    ".exs",
    ".go",
    ".graphql",
    ".h",
    ".hpp",
    ".hs",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".lua",
    ".mjs",
    ".mm",
    ".php",
    ".proto",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}

JAVASCRIPT_EXTENSIONS = {".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue"}
JAVA_LIKE_EXTENSIONS = {".c", ".cc", ".cpp", ".cs", ".cxx", ".h", ".hpp", ".java", ".mm"}
BRACE_LANGUAGE_EXTENSIONS = {
    *JAVASCRIPT_EXTENSIONS,
    *JAVA_LIKE_EXTENSIONS,
    ".dart",
    ".go",
    ".kt",
    ".kts",
    ".php",
    ".rs",
    ".scala",
    ".swift",
}
NESTED_BLOCK_COMMENT_EXTENSIONS = {".kt", ".kts", ".rs", ".scala", ".swift"}
RUST_RAW_STRING_RE = re.compile(r'(?:br|r)(#{0,16})"')
RUST_LIFETIME_RE = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*")
PHP_HEREDOC_RE = re.compile(r"<<<\s*['\"]?([A-Za-z_]\w*)['\"]?")


def is_binary_sample(data: bytes) -> bool:
    return b"\0" in data


def compact_preview_line(line: str) -> str:
    return " ".join(line.split())


def truncate_utf8(text: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def select_preview_lines(lines: list[str]) -> list[str]:
    compact = [value for line in lines if (value := compact_preview_line(line))]
    head = compact[:PREVIEW_HEAD_LINES]
    remainder = compact[PREVIEW_HEAD_LINES:]
    if len(remainder) <= PREVIEW_SAMPLE_LINES:
        return [*head, *remainder]

    last_index = len(remainder) - 1
    sampled = [
        remainder[index * last_index // (PREVIEW_SAMPLE_LINES - 1)]
        for index in range(PREVIEW_SAMPLE_LINES)
    ]
    return [*head, "...", *sampled]


def fit_preview_lines(lines: list[str], max_bytes: int) -> str:
    if not lines or max_bytes <= 0:
        return ""

    full_preview = "\n".join(lines)
    if len(full_preview.encode("utf-8")) <= max_bytes:
        return full_preview

    def render(line_bytes: int) -> str:
        return "\n".join(
            line if line == "..." else truncate_utf8(line, line_bytes).rstrip() for line in lines
        )

    content_lines = [line for line in lines if line != "..."]
    if not content_lines:
        return truncate_utf8(full_preview, max_bytes)
    low = 0
    high = max(len(line.encode("utf-8")) for line in content_lines)
    best = ""
    while low <= high:
        middle = (low + high) // 2
        candidate = render(middle)
        if len(candidate.encode("utf-8")) <= max_bytes:
            best = candidate
            low = middle + 1
        else:
            high = middle - 1
    if best:
        return best
    return truncate_utf8(full_preview, max_bytes)


def python_decorators(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> str:
    values: list[str] = []
    for decorator in node.decorator_list:
        try:
            rendered = compact_preview_line(ast.unparse(decorator))
        except (AttributeError, RecursionError, ValueError):
            continue
        if rendered:
            values.append(f"@{rendered}")
    return " ".join(values)


def python_arguments(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    arguments = [argument.arg for argument in (*node.args.posonlyargs, *node.args.args)]
    if node.args.vararg is not None:
        arguments.append(f"*{node.args.vararg.arg}")
    arguments.extend(argument.arg for argument in node.args.kwonlyargs)
    if node.args.kwarg is not None:
        arguments.append(f"**{node.args.kwarg.arg}")
    return ", ".join(arguments)


def python_outline(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError, MemoryError):
        return []

    outline: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            prefix = python_decorators(node)
            kind = "async function" if isinstance(node, ast.AsyncFunctionDef) else "function"
            declaration = f"{kind} {node.name}({python_arguments(node)})"
            outline.append(f"{prefix} {declaration}".strip())
        elif isinstance(node, ast.ClassDef):
            prefix = python_decorators(node)
            bases: list[str] = []
            for base in node.bases:
                try:
                    bases.append(compact_preview_line(ast.unparse(base)))
                except (AttributeError, RecursionError, ValueError):
                    continue
            suffix = f"({', '.join(bases)})" if bases else ""
            outline.append(f"{prefix} class {node.name}{suffix}".strip())
            for member in node.body:
                if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                member_prefix = python_decorators(member)
                kind = "async method" if isinstance(member, ast.AsyncFunctionDef) else "method"
                declaration = f"{kind} {node.name}.{member.name}"
                outline.append(f"{member_prefix} {declaration}".strip())
    return outline


def javascript_regex_end(text: str, start: int) -> int | None:
    if start + 1 >= len(text) or text[start + 1] in {"/", "*"}:
        return None
    previous = start - 1
    while previous >= 0 and text[previous] in " \t\r":
        previous -= 1
    if previous >= 0 and text[previous] not in "=(:,[!&|?{};\n":
        prefix = text[max(0, previous - 8) : previous + 1]
        if not re.search(r"\b(?:case|return|throw)$", prefix):
            return None

    index = start + 1
    in_character_class = False
    while index < len(text):
        char = text[index]
        if char == "\n":
            return None
        if char == "\\" and index + 1 < len(text):
            index += 2
            continue
        if char == "[":
            in_character_class = True
        elif char == "]":
            in_character_class = False
        elif char == "/" and not in_character_class:
            index += 1
            while index < len(text) and text[index].isalpha():
                index += 1
            return index
        index += 1
    return None


def mask_c_style_source(text: str, suffix: str) -> str:
    masked: list[str] = []
    index = 0
    block_comment_depth = 0
    in_line_comment = False
    quote = ""
    raw_terminator = ""
    heredoc_terminator = ""
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if char == "\n":
            masked.append(char)
            in_line_comment = False
            if quote and quote not in {"`", '"""', "'''", '@"'}:
                quote = ""
            index += 1
            continue
        if in_line_comment:
            masked.append(" ")
            index += 1
            continue
        if block_comment_depth:
            if char == "/" and next_char == "*" and suffix in NESTED_BLOCK_COMMENT_EXTENSIONS:
                masked.extend((" ", " "))
                block_comment_depth += 1
                index += 2
            elif char == "*" and next_char == "/":
                masked.extend((" ", " "))
                block_comment_depth -= 1
                index += 2
            else:
                masked.append(" ")
                index += 1
            continue
        if heredoc_terminator:
            if index == 0 or text[index - 1] == "\n":
                line_end = text.find("\n", index)
                if line_end < 0:
                    line_end = len(text)
                candidate = text[index:line_end].strip().removesuffix(";")
                if candidate == heredoc_terminator:
                    masked.extend(" " * (line_end - index))
                    index = line_end
                    heredoc_terminator = ""
                    continue
            masked.append(" ")
            index += 1
            continue
        if raw_terminator:
            if text.startswith(raw_terminator, index):
                masked.extend(" " * len(raw_terminator))
                index += len(raw_terminator)
                raw_terminator = ""
            else:
                masked.append(" ")
                index += 1
            continue
        if quote in {'"""', "'''"}:
            if text.startswith(quote, index):
                masked.extend(" " * len(quote))
                index += len(quote)
                quote = ""
            else:
                masked.append(" ")
                index += 1
            continue
        if quote == '@"':
            masked.append(" ")
            if char == '"' and next_char == '"':
                masked.append(" ")
                index += 2
            else:
                if char == '"':
                    quote = ""
                index += 1
            continue
        if quote:
            if char == "\\" and next_char:
                masked.append(" ")
                if next_char == "\n":
                    index += 1
                else:
                    masked.append(" ")
                    index += 2
            else:
                masked.append(" ")
                if char == quote:
                    quote = ""
                index += 1
            continue
        if suffix == ".rs":
            raw_match = RUST_RAW_STRING_RE.match(text, index)
            if raw_match:
                token = raw_match.group(0)
                masked.extend(" " * len(token))
                raw_terminator = f'"{raw_match.group(1)}'
                index += len(token)
                continue
            if char == "'":
                lifetime_match = RUST_LIFETIME_RE.match(text, index)
                if lifetime_match:
                    token = lifetime_match.group(0)
                    following = text[index + len(token) : index + len(token) + 1]
                    if following != "'":
                        masked.extend(token)
                        index += len(token)
                        continue
        if suffix == ".cs" and char == "@" and next_char == '"':
            masked.extend((" ", " "))
            quote = '@"'
            index += 2
            continue
        triple_quote = text[index : index + 3]
        if triple_quote in {'"""', "'''"}:
            masked.extend((" ", " ", " "))
            quote = triple_quote
            index += 3
            continue
        if suffix == ".php" and text.startswith("<<<", index):
            heredoc_match = PHP_HEREDOC_RE.match(text, index)
            if heredoc_match:
                token = heredoc_match.group(0)
                masked.extend(" " * len(token))
                heredoc_terminator = heredoc_match.group(1)
                index += len(token)
                continue
        if suffix in JAVASCRIPT_EXTENSIONS and char == "/":
            regex_end = javascript_regex_end(text, index)
            if regex_end is not None:
                masked.extend(" " * (regex_end - index))
                index = regex_end
                continue
        if char == "/" and next_char == "/":
            masked.extend((" ", " "))
            in_line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            masked.extend((" ", " "))
            block_comment_depth = 1
            index += 2
            continue
        if char == "#" and suffix == ".php" and next_char != "[":
            masked.append(" ")
            in_line_comment = True
            index += 1
            continue
        if char in {'"', "'", "`"}:
            quote = char
            masked.append(" ")
            index += 1
            continue
        masked.append(char)
        index += 1
    return "".join(masked)


def match_type_declaration(line: str, suffix: str) -> tuple[str, str] | None:
    match: re.Match[str] | None = None
    if suffix in JAVASCRIPT_EXTENSIONS:
        match = re.match(
            r"^(?:(?:export|default|declare|abstract)\s+)*(class|interface|enum|namespace)\s+"
            r"([A-Za-z_$][\w$]*)",
            line,
        )
    elif suffix == ".java":
        match = re.search(r"\b(class|interface|enum|record|@interface)\s+([A-Za-z_$][\w$]*)", line)
    elif suffix == ".cs":
        match = re.search(
            r"\b(class|interface|struct|enum|record(?:\s+(?:class|struct))?)\s+"
            r"(@?[A-Za-z_]\w*)",
            line,
        )
    elif suffix == ".php":
        match = re.match(
            r"^(?:(?:abstract|final|readonly)\s+)*(class|interface|trait|enum)\s+"
            r"([A-Za-z_]\w*)",
            line,
        )
    elif suffix == ".go":
        match = re.match(r"^type\s+([A-Za-z_]\w*)\s+(struct|interface)\b", line)
        if match:
            return match.group(2), match.group(1)
    elif suffix in {".kt", ".kts"}:
        companion_match = re.search(r"\bcompanion\s+object(?:\s+([A-Za-z_]\w*))?", line)
        if companion_match:
            return "object", companion_match.group(1) or "Companion"
        match = re.search(
            r"\b((?:(?:data|enum|sealed|annotation|value)\s+)?(?:class|interface|object))\s+"
            r"([A-Za-z_]\w*)",
            line,
        )
    elif suffix == ".scala":
        match = re.match(
            r"^(?:(?:case|sealed|abstract)\s+)*(class|trait|object|enum)\s+([A-Za-z_]\w*)", line
        )
    elif suffix == ".rs":
        match = re.search(r"\b(struct|enum|trait|union)\s+([A-Za-z_]\w*)", line)
        if not match:
            impl_match = re.search(
                r"\bimpl(?:\s*<[^>{}]*>)?\s+(?:[\w:<>]+\s+for\s+)?([A-Za-z_]\w*)",
                line,
            )
            if impl_match:
                return "impl", impl_match.group(1)
    elif suffix == ".swift":
        match = re.search(r"\b(class|struct|enum|protocol|actor|extension)\s+([A-Za-z_]\w*)", line)
    elif suffix == ".dart":
        match = re.search(r"\b(class|mixin|enum|extension)\s+([A-Za-z_]\w*)", line)
    elif suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".mm"}:
        match = re.search(
            r"\b(class|struct|union|enum(?:\s+class)?)\s+([A-Za-z_]\w*)",
            line,
        )
    if not match:
        return None
    return match.group(1), match.group(2)


CONTROL_NAMES = {
    "assert",
    "catch",
    "for",
    "foreach",
    "if",
    "lock",
    "new",
    "return",
    "sizeof",
    "static_assert",
    "switch",
    "synchronized",
    "throw",
    "typeof",
    "while",
}


def match_java_like_function(
    line: str, suffix: str, type_name: str | None
) -> tuple[str, str] | None:
    paren = line.find("(")
    if paren < 0:
        return None
    before = line[:paren].rstrip()
    if not before or "=" in before or before.startswith("#"):
        return None
    before = re.sub(r"<[^<>]*>$", "", before).rstrip()
    name_match = re.search(
        r"(~?[A-Za-z_$@][\w$@]*(?:(?:::|\.)~?[A-Za-z_$@][\w$@]*)?)$",
        before,
    )
    if not name_match:
        return None
    qualified_name = name_match.group(1)
    name = re.split(r"::|\.", qualified_name)[-1].lstrip("~")
    if name in CONTROL_NAMES:
        return None
    prefix = before[: name_match.start()].strip()
    if not prefix and name != (type_name or ""):
        return None
    if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".mm"} and prefix.startswith(
        ("typedef", "using")
    ):
        return None
    if (
        suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".mm"}
        and type_name is None
        and line.endswith(";")
        and not re.search(
            r"(?:\b(?:auto|bool|char|consteval|constexpr|double|extern|float|inline|int|long|"
            r"short|signed|static|unsigned|void)\b|[*&:]|<)",
            prefix,
        )
    ):
        return None
    return ("method" if type_name else "function"), qualified_name


def match_function_declaration(
    line: str, suffix: str, type_name: str | None
) -> tuple[str, str] | None:
    if suffix in JAVASCRIPT_EXTENSIONS:
        function_match = re.match(
            r"^(?:(?:export|default|declare)\s+)*(async\s+)?function\s*\*?\s*"
            r"([A-Za-z_$][\w$]*)\s*(?:<[^>{}]*>)?\s*\(",
            line,
        )
        if function_match:
            kind = "async function" if function_match.group(1) else "function"
            return kind, function_match.group(2)
        arrow_match = re.match(
            r"^(?:(?:export|declare)\s+)*(?:const|let|var)\s+([A-Za-z_$][\w$]*)"
            r"\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|"
            r"[A-Za-z_$][\w$]*\s*=>)",
            line,
        )
        if arrow_match:
            return "function", arrow_match.group(1)
        if type_name:
            field_arrow_match = re.match(
                r"^(?:(?:public|private|protected|static|abstract|override|readonly|declare|"
                r"accessor)\s+)*(#?[A-Za-z_$][\w$]*)(?:[?!])?\s*(?::[^=]+)?=\s*"
                r"(?:async\s+)?(?:\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)",
                line,
            )
            if field_arrow_match:
                return "method", field_arrow_match.group(1)
            method_match = re.match(
                r"^(?:(?:public|private|protected|static|abstract|async|override|readonly|"
                r"declare|get|set)\s+)*(#?[A-Za-z_$][\w$]*|constructor)\s*"
                r"(?:<[^>{}]*>)?\s*\(",
                line,
            )
            if method_match and method_match.group(1) not in CONTROL_NAMES:
                return "method", method_match.group(1)
        return None
    if suffix == ".php":
        match = re.match(
            r"^(?:(?:public|protected|private|static|final|abstract|readonly)\s+)*"
            r"function\s*&?\s*([A-Za-z_]\w*)\s*\(",
            line,
        )
        if match:
            return ("method" if type_name else "function"), match.group(1)
        return None
    if suffix == ".go":
        match = re.match(
            r"^func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^]]+\]\s*)?\(",
            line,
        )
        if match:
            receiver = match.group(1)
            name = match.group(2)
            if receiver:
                receiver_match = re.search(r"\*?([A-Za-z_]\w*)(?:\[[^]]*])?\s*$", receiver)
                if receiver_match:
                    return "method", f"{receiver_match.group(1)}.{name}"
                return "method", name
            return ("method" if type_name else "function"), name
        return None
    if suffix in {".kt", ".kts"}:
        match = re.search(r"\bfun\s+(?:<[^>{}]*>\s*)?(?:[\w.<>?]+\.)?([A-Za-z_]\w*)\s*\(", line)
        if match:
            return ("method" if type_name else "function"), match.group(1)
        return None
    if suffix == ".scala":
        match = re.search(r"\bdef\s+([A-Za-z_]\w*)\b", line)
        if match:
            return ("method" if type_name else "function"), match.group(1)
        return None
    if suffix == ".rs":
        match = re.search(
            r"\b(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]+\"\s+)?(?:const\s+)?"
            r"fn\s+([A-Za-z_]\w*)",
            line,
        )
        if match:
            return ("method" if type_name else "function"), match.group(1)
        return None
    if suffix == ".swift":
        match = re.search(r"\bfunc\s+([A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\(", line)
        if match:
            return ("method" if type_name else "function"), match.group(1)
        if type_name and re.search(r"\binit\s*\(", line):
            return "method", "init"
        return None
    if suffix == ".dart":
        return match_java_like_function(line, suffix, type_name)
    if suffix in JAVA_LIKE_EXTENSIONS:
        return match_java_like_function(line, suffix, type_name)
    return None


def is_annotation_line(line: str) -> bool:
    return bool(
        re.match(r"^@[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\(.*\))?$", line)
        or re.match(r"^\[[A-Za-z_][^]]*]$", line)
        or re.match(r"^#\[[A-Za-z_][^]]*]$", line)
    )


LEADING_ANNOTATION_RE = re.compile(
    r"^(?:@[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\([^)]*\))?|"
    r"\[[A-Za-z_][^]]*]|#\[[A-Za-z_][^]]*])\s*"
)


def strip_leading_annotations(original: str, masked: str) -> tuple[str, str, list[str]]:
    annotations: list[str] = []
    if masked.startswith("@interface "):
        return original, masked, annotations
    while masked_match := LEADING_ANNOTATION_RE.match(masked):
        original_match = LEADING_ANNOTATION_RE.match(original)
        if original_match:
            annotations.append(compact_preview_line(original_match.group(0)))
            original = original[original_match.end() :].lstrip()
        masked = masked[masked_match.end() :].lstrip()
    return original, masked, annotations


def brace_language_outline(text: str, suffix: str) -> list[str]:
    original_lines = text.splitlines()
    masked_lines = mask_c_style_source(text, suffix).splitlines()
    outline: list[str] = []
    seen: set[str] = set()
    type_stack: list[tuple[str, int]] = []
    function_depths: list[int] = []
    blocked_depths: list[int] = []
    pending_type: str | None = None
    pending_function = False
    pending_annotations: list[str] = []
    depth = 0

    def add(value: str) -> None:
        decorated = f"{' '.join(pending_annotations[-2:])} {value}".strip()
        if decorated not in seen:
            seen.add(decorated)
            outline.append(decorated)

    def next_lines_open_body(line_index: int) -> bool:
        inspected = 0
        for future_index in range(line_index + 1, len(masked_lines)):
            future = masked_lines[future_index]
            future_line = compact_preview_line(future)
            if not future_line:
                continue
            inspected += 1
            if "{" in future_line:
                return True
            if "}" in future_line or future_line.endswith(";") or inspected >= 6:
                return False
        return False

    for line_index, (original, masked) in enumerate(
        zip(original_lines, masked_lines, strict=False)
    ):
        while function_depths and depth < function_depths[-1]:
            function_depths.pop()
        while type_stack and depth < type_stack[-1][1]:
            type_stack.pop()
        while blocked_depths and depth < blocked_depths[-1]:
            blocked_depths.pop()

        masked_line = compact_preview_line(masked)
        original_line = compact_preview_line(original)
        opens = masked.count("{")
        closes = masked.count("}")

        opened_pending_scope = False
        if pending_type and "{" in masked:
            type_stack.append((pending_type, depth + 1))
            pending_type = None
            opened_pending_scope = True
        if pending_function and "{" in masked:
            function_depths.append(depth + 1)
            pending_function = False
            opened_pending_scope = True

        if (
            masked_line
            and original_line
            and is_annotation_line(original_line)
            and not function_depths
            and not blocked_depths
        ):
            pending_annotations.append(original_line)
        elif masked_line and not function_depths and not blocked_depths:
            _, masked_line, inline_annotations = strip_leading_annotations(
                original_line, masked_line
            )
            pending_annotations.extend(inline_annotations)
            current_type = type_stack[-1][0] if type_stack else None
            direct_type_body = not type_stack or depth == type_stack[-1][1]
            type_match = match_type_declaration(masked_line, suffix) if direct_type_body else None
            if type_match:
                kind, name = type_match
                if (
                    current_type
                    and suffix in {".kt", ".kts"}
                    and kind == "object"
                    and name == "Companion"
                ):
                    name = f"{current_type}.{name}"
                add(f"{kind} {name}")
                pending_annotations.clear()
                if "{" in masked:
                    type_stack.append((name, depth + 1))
                elif not masked_line.endswith(";") and next_lines_open_body(line_index):
                    pending_type = name
            elif direct_type_body:
                function_match = match_function_declaration(masked_line, suffix, current_type)
                if function_match:
                    kind, name = function_match
                    qualified_name = (
                        f"{current_type}.{name}"
                        if current_type and "." not in name and "::" not in name
                        else name
                    )
                    add(f"{kind} {qualified_name}")
                    pending_annotations.clear()
                    if "{" in masked:
                        function_depths.append(depth + 1)
                    elif (
                        not masked_line.endswith(";")
                        and "=>" not in masked_line
                        and "=" not in masked_line
                        and next_lines_open_body(line_index)
                    ):
                        pending_function = True
                else:
                    pending_annotations.clear()
                    is_transparent_container = bool(
                        re.match(
                            r"^(?:(?:export|inline)\s+)?namespace\b|"
                            r"^(?:pub\s+)?mod\b|^(?:declare\s+)?module\b|"
                            r"^(?:unsafe\s+)?extern\b",
                            masked_line,
                        )
                    )
                    if opens and not opened_pending_scope and not is_transparent_container:
                        blocked_depths.append(depth + 1)

        depth = max(0, depth + opens - closes)
        while function_depths and depth < function_depths[-1]:
            function_depths.pop()
        while type_stack and depth < type_stack[-1][1]:
            type_stack.pop()
        while blocked_depths and depth < blocked_depths[-1]:
            blocked_depths.pop()
    return outline


def ruby_outline(text: str) -> list[str]:
    outline: list[str] = []
    seen: set[str] = set()
    type_stack: list[tuple[int, str]] = []
    function_indents: list[int] = []

    def add(value: str) -> None:
        if value not in seen:
            seen.add(value)
            outline.append(value)

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line.expandtabs(4)) - len(raw_line.lstrip().expandtabs(4))
        while function_indents and indent <= function_indents[-1]:
            function_indents.pop()
        while type_stack and indent <= type_stack[-1][0]:
            type_stack.pop()

        type_match = re.match(r"^(class|module)\s+([A-Z]\w*(?:::[A-Z]\w*)*)", stripped)
        if type_match and not function_indents:
            kind, name = type_match.groups()
            add(f"{kind} {name}")
            type_stack.append((indent, name))
            continue

        function_match = re.match(r"^def\s+(?:self\.)?([^\s(]+)", stripped)
        if function_match and not function_indents:
            name = function_match.group(1)
            if type_stack:
                add(f"method {type_stack[-1][1]}.{name}")
            else:
                add(f"function {name}")
            function_indents.append(indent)
    return outline


def simple_language_outline(text: str, suffix: str) -> list[str]:
    outline: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value not in seen:
            seen.add(value)
            outline.append(value)

    for raw_line in text.splitlines():
        line = compact_preview_line(raw_line)
        if not line:
            continue
        match: re.Match[str] | None = None
        if suffix == ".py":
            match = re.match(r"^(async\s+)?def\s+([A-Za-z_]\w*)\s*\(", line)
            if match:
                add(f"{'async function' if match.group(1) else 'function'} {match.group(2)}")
                continue
            match = re.match(r"^class\s+([A-Za-z_]\w*)", line)
            if match:
                add(f"class {match.group(1)}")
        elif suffix == ".rb":
            match = re.match(r"^(class|module)\s+([A-Z]\w*(?:::[A-Z]\w*)*)", line)
            if match:
                add(f"{match.group(1)} {match.group(2)}")
                continue
            match = re.match(r"^def\s+(?:self\.)?([^\s(]+)", line)
            if match:
                add(f"function {match.group(1)}")
        elif suffix in {".ex", ".exs"}:
            match = re.match(r"^defmodule\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)", line)
            if match:
                add(f"module {match.group(1)}")
                continue
            match = re.match(r"^(?:def|defp|defmacro)\s+([A-Za-z_]\w*[!?]?)", line)
            if match:
                add(f"function {match.group(1)}")
        elif suffix == ".clj":
            match = re.match(
                r"^\((defn|defmacro|defprotocol|defrecord|deftype|defmulti|defmethod)\s+([^\s)]+)",
                line,
            )
            if match:
                add(f"{match.group(1)} {match.group(2)}")
        elif suffix == ".lua":
            match = re.match(r"^(?:local\s+)?function\s+([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)", line)
            if match:
                add(f"function {match.group(1)}")
        elif suffix == ".sh":
            match = re.match(r"^(?:function\s+)?([A-Za-z_]\w*)\s*\(\s*\)\s*\{?", line)
            if match:
                add(f"function {match.group(1)}")
        elif suffix == ".hs":
            match = re.match(r"^(data|newtype|type|class)\s+([A-Z]\w*)", line)
            if match:
                add(f"{match.group(1)} {match.group(2)}")
                continue
            match = re.match(r"^([a-z_]\w*)\s*::", line)
            if match:
                add(f"function {match.group(1)}")
        elif suffix == ".proto":
            match = re.match(r"^(message|service|enum)\s+([A-Za-z_]\w*)", line)
            if match:
                add(f"{match.group(1)} {match.group(2)}")
                continue
            match = re.match(r"^rpc\s+([A-Za-z_]\w*)\s*\(", line)
            if match:
                add(f"rpc {match.group(1)}")
        elif suffix == ".graphql":
            match = re.match(
                r"^(type|interface|input|enum|union|scalar|directive)\s+([A-Za-z_]\w*)",
                line,
            )
            if match:
                add(f"{match.group(1)} {match.group(2)}")
                continue
            match = re.match(r"^(query|mutation|subscription)\s+([A-Za-z_]\w*)", line)
            if match:
                add(f"{match.group(1)} {match.group(2)}")
        elif suffix == ".sql":
            match = re.match(
                r"^CREATE\s+(?:OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE|TABLE|VIEW|TRIGGER)\s+"
                r"([^\s(;]+)",
                line,
                flags=re.IGNORECASE,
            )
            if match:
                add(f"{match.group(1).lower()} {match.group(2)}")
        elif suffix in {".yaml", ".yml"}:
            match = re.match(r"^([A-Za-z0-9_.-]+):(?:\s|$)", raw_line)
            if match:
                add(f"key {match.group(1)}")
        elif suffix in {".toml", ".cfg"}:
            match = re.match(r"^\[([^]]+)]$", line)
            if match:
                add(f"section {match.group(1)}")
    return outline


def json_outline(text: str) -> list[str]:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, RecursionError, MemoryError):
        return []
    if not isinstance(parsed, dict):
        return []
    outline: list[str] = []
    for key, value in parsed.items():
        if isinstance(value, dict) and value:
            children = ", ".join(str(child) for child in value)
            outline.append(f"key {key} [{children}]")
        else:
            outline.append(f"key {key}")
    return outline


def structural_outline(path: Path, text: str) -> list[str]:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return python_outline(text) or simple_language_outline(text, suffix)
    if suffix == ".rb":
        return ruby_outline(text)
    if suffix in BRACE_LANGUAGE_EXTENSIONS:
        return brace_language_outline(text, suffix)
    if suffix == ".json":
        return json_outline(text)
    return simple_language_outline(text, suffix)


def preview_for(path: Path, preview_bytes: int) -> tuple[str, bool]:
    try:
        data = path.read_bytes()
    except OSError:
        return "", True
    sample = data[:4096]
    if is_binary_sample(sample):
        return "", True
    text = data.decode("utf-8", errors="ignore")
    outline = structural_outline(path, text)
    preview_lines = select_preview_lines(outline or text.splitlines())
    return fit_preview_lines(preview_lines, preview_bytes), False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build structural or sampled previews for Codex Security rank inputs."
    )
    parser.parse_args()


if __name__ == "__main__":
    main()
