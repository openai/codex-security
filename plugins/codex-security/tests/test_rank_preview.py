from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
from rank_preview import DEFAULT_PREVIEW_BYTES, preview_for


def test_preview_for_does_not_fully_read_a_large_binary(tmp_path: Path) -> None:
    source = tmp_path / "payload.bin"
    with source.open("wb") as output:
        output.write(b"header\0payload")
        output.truncate(256 * 1024 * 1024)

    with patch.object(Path, "read_bytes", side_effect=MemoryError("full binary read")):
        assert preview_for(source, DEFAULT_PREVIEW_BYTES) == ("", True)


def test_preview_for_bounds_a_source_like_binary_after_the_initial_sample(tmp_path: Path) -> None:
    source = tmp_path / "payload.py"
    with source.open("wb") as output:
        output.write(b"header-without-a-nul" * 256)
        output.write(b"\0binary")
        output.truncate(256 * 1024 * 1024)

    assert preview_for(source, DEFAULT_PREVIEW_BYTES, max_read_bytes=64 * 1024) == ("", True)


def generate_preview(
    tmp_path: Path, filename: str, source: str, *, preview_bytes: int | None = None
) -> str:
    source_path = tmp_path / filename
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source, encoding="utf-8")
    preview, is_binary = preview_for(
        source_path,
        DEFAULT_PREVIEW_BYTES if preview_bytes is None else preview_bytes,
    )
    assert not is_binary
    return preview


def test_python_preview_lists_top_level_symbols_and_direct_methods(tmp_path: Path) -> None:
    imports = "\n".join(f"import package_{index}" for index in range(30))
    source = f"""{imports}

@router.post("/login")
async def login(request, token=None):
    def nested_helper():
        return None
    return nested_helper()

class UserService(BaseService):
    @classmethod
    def create(cls, config):
        return cls(config)

    async def refresh(self):
        return None
"""

    preview = generate_preview(tmp_path, "service.py", source)

    assert "@router.post('/login') async function login(request, token)" in preview
    assert "class UserService(BaseService)" in preview
    assert "@classmethod method UserService.create" in preview
    assert "async method UserService.refresh" in preview
    assert "package_" not in preview
    assert "nested_helper" not in preview


@pytest.mark.parametrize(
    ("filename", "source", "expected"),
    [
        (
            "controller.js",
            """if (enabled) {
  function conditionalOnly() {}
}
export class UserController {
  async login(request) {
    function nestedHelper() {}
    return request;
  }
}
export const verifyToken = (token) => token;
""",
            ("class UserController", "method UserController.login", "function verifyToken"),
        ),
        (
            "store.ts",
            """export interface TokenStore {
  get(id: string): Token;
}
export function loadStore(): TokenStore { throw new Error(); }
""",
            ("interface TokenStore", "method TokenStore.get", "function loadStore"),
        ),
        (
            "UserService.java",
            """public class UserService {
  @PostMapping("/login") public User login(String name) { return null; }
}
""",
            ("class UserService", "method UserService.login"),
        ),
        (
            "UserController.cs",
            """public class UserController {
  [HttpPost("login")] public T Login<T>(User user) { return default(T); }
}
""",
            ("class UserController", "method UserController.Login"),
        ),
        (
            "user_service.rb",
            """class FirstService
  def call(user)
    true
  end
end
class SecondService
  def call(user)
    true
  end
end
""",
            (
                "class FirstService",
                "method FirstService.call",
                "class SecondService",
                "method SecondService.call",
            ),
        ),
        (
            "UserService.php",
            """<?php
final class UserService {
  # A comment brace must not change declaration depth: {
  public function authenticate($user) { return true; }
}
""",
            ("class UserService", "method UserService.authenticate"),
        ),
        (
            "user_service.go",
            """package service
type UserService struct {}
func (service *UserService) Authenticate(user User) bool { return true }
""",
            ("struct UserService", "method UserService.Authenticate"),
        ),
        (
            "user_service.cpp",
            """Widget widget(options);
class UserService {
public:
  bool authenticate(const User& user) { return true; }
};
bool verify_token(const Token& token) { return true; }
""",
            ("class UserService", "method UserService.authenticate", "function verify_token"),
        ),
        (
            "UserService.kt",
            """class UserService {
  fun authenticate(user: User): Boolean { return true }
}
""",
            ("class UserService", "method UserService.authenticate"),
        ),
        (
            "UserService.scala",
            """class UserService {
  def authenticate(user: User): Boolean = { true }
}
""",
            ("class UserService", "method UserService.authenticate"),
        ),
        (
            "user_service.rs",
            """pub fn borrow<'a>() {}
struct UserService {}
impl UserService {
  pub fn authenticate(&self, user: User) -> bool { true }
}
""",
            (
                "function borrow",
                "struct UserService",
                "impl UserService",
                "method UserService.authenticate",
            ),
        ),
        (
            "UserService.swift",
            """final class UserService {
  func authenticate(user: User) -> Bool { return true }
}
""",
            ("class UserService", "method UserService.authenticate"),
        ),
        (
            "user_service.ex",
            """defmodule UserService do
  def authenticate(user), do: true
end
""",
            ("module UserService", "function authenticate"),
        ),
        (
            "service.clj",
            """(defprotocol UserService
  (authenticate [service user]))
(defn verify-token [token] true)
""",
            ("defprotocol UserService", "defn verify-token"),
        ),
        (
            "service.proto",
            """service UserService {
  rpc Authenticate (User) returns (Result);
}
message User {}
""",
            ("service UserService", "rpc Authenticate", "message User"),
        ),
        (
            "schema.graphql",
            """type User { id: ID! }
type Query { user(id: ID!): User }
query CurrentUser { user(id: "me") { id } }
""",
            ("type User", "type Query", "query CurrentUser"),
        ),
        (
            "schema.sql",
            """CREATE TABLE users (id BIGINT PRIMARY KEY);
CREATE PROCEDURE rotate_tokens() BEGIN SELECT 1; END;
""",
            ("table users", "procedure rotate_tokens"),
        ),
        (
            "service.json",
            '{"service":{"host":"localhost","port":443},"enabled":true}',
            ("key service [host, port]", "key enabled"),
        ),
    ],
)
def test_enterprise_language_previews_list_declarations(
    tmp_path: Path, filename: str, source: str, expected: tuple[str, ...]
) -> None:
    preview = generate_preview(tmp_path, filename, source, preview_bytes=4096)

    for declaration in expected:
        assert declaration in preview
    assert "nestedHelper" not in preview
    assert "conditionalOnly" not in preview
    assert "function widget" not in preview


def test_expression_bodied_function_does_not_consume_next_type_body(tmp_path: Path) -> None:
    source = """fun answer(): Int = 42
class Service {
  fun run() {}
}
"""

    preview = generate_preview(tmp_path, "Service.kt", source)

    assert "function answer" in preview
    assert "class Service" in preview
    assert "method Service.run" in preview


def test_protocol_requirement_does_not_consume_following_function(tmp_path: Path) -> None:
    source = """protocol Required {
  func run()
}
func visible() {}
"""

    preview = generate_preview(tmp_path, "Required.swift", source)

    assert "method Required.run" in preview
    assert "function visible" in preview


def test_multiline_string_and_commented_annotation_do_not_change_depth(tmp_path: Path) -> None:
    source = '''public class Visible {
  String template = """
    { notABlock }
  """;
  /*
   * @Route("/not-a-route")
   */
  public void run() {}
}
'''

    preview = generate_preview(tmp_path, "Visible.java", source)

    assert "class Visible" in preview
    assert "method Visible.run" in preview
    assert "Route" not in preview


@pytest.mark.parametrize(
    ("filename", "source", "expected"),
    [
        (
            "api.rs",
            """mod api {
  pub fn handle() {}
}
""",
            "function handle",
        ),
        (
            "api.ts",
            """declare module "api" {
  export function handle(): void;
}
""",
            "function handle",
        ),
        (
            "api.cpp",
            """extern "C" {
  void handle() {}
}
""",
            "function handle",
        ),
    ],
)
def test_namespace_like_containers_expose_declarations(
    tmp_path: Path, filename: str, source: str, expected: str
) -> None:
    preview = generate_preview(tmp_path, filename, source)

    assert expected in preview


def test_kotlin_companion_object_lists_factory_method(tmp_path: Path) -> None:
    source = """class Service {
  companion object {
    fun create() {}
  }
  fun visible() {}
}
"""

    preview = generate_preview(tmp_path, "Service.kt", source)

    assert "object Service.Companion" in preview
    assert "method Service.Companion.create" in preview
    assert "method Service.visible" in preview


def test_javascript_regex_literal_does_not_change_declaration_depth(tmp_path: Path) -> None:
    source = r"""class Service {
  pattern = /\{/;
  visible() {}
}
"""

    preview = generate_preview(tmp_path, "service.ts", source)

    assert "method Service.visible" in preview


def test_javascript_preview_lists_class_field_arrow_handlers(tmp_path: Path) -> None:
    source = """export class Controller {
  login = async (request: Request) => request;
  public refresh: Handler = (request) => request;
  protected validate = value => Boolean(value);
}
"""

    preview = generate_preview(tmp_path, "controller.ts", source)

    assert "method Controller.login" in preview
    assert "method Controller.refresh" in preview
    assert "method Controller.validate" in preview


def test_php_heredoc_does_not_hide_following_method(tmp_path: Path) -> None:
    source = """<?php
class Service {
  public function template() {
    $value = <<<TXT
{
TXT;
  }
  public function visible() {}
}
"""

    preview = generate_preview(tmp_path, "Service.php", source)

    assert "method Service.template" in preview
    assert "method Service.visible" in preview


def test_malformed_python_uses_sampled_source_fallback(tmp_path: Path) -> None:
    source = """import package
broken = (
first_runtime_line()
second_runtime_line()
"""

    preview = generate_preview(tmp_path, "broken.py", source)

    assert preview.splitlines() == [
        "import package",
        "broken = (",
        "first_runtime_line()",
        "second_runtime_line()",
    ]


def test_fallback_preview_uses_head_and_evenly_sampled_nonblank_lines(tmp_path: Path) -> None:
    source = "\n\n".join(f"line_{index:02d} {{ color: red; }}" for index in range(40))

    preview = generate_preview(tmp_path, "styles.css", source)

    assert preview.splitlines() == [
        *(f"line_{index:02d} {{ color: red; }}" for index in range(12)),
        "...",
        *(
            f"line_{index:02d} {{ color: red; }}"
            for index in (12, 15, 18, 21, 24, 27, 30, 33, 36, 39)
        ),
    ]


def test_fallback_preview_omits_marker_when_no_lines_are_skipped(tmp_path: Path) -> None:
    source = "\n".join(f"line_{index:02d}" for index in range(22))

    preview = generate_preview(tmp_path, "styles.css", source, preview_bytes=4096)

    assert preview.splitlines() == [f"line_{index:02d}" for index in range(22)]
    assert "..." not in preview


def test_preview_byte_budget_preserves_sampled_tail_and_valid_unicode(tmp_path: Path) -> None:
    source = "\n".join(f"line_{index:02d} {'😀' * 20}" for index in range(40))

    preview = generate_preview(tmp_path, "styles.css", source, preview_bytes=220)

    assert len(preview.encode("utf-8")) <= 220
    assert "..." in preview
    assert "line_39" in preview


def test_literal_elision_line_respects_tiny_byte_budget(tmp_path: Path) -> None:
    preview = generate_preview(tmp_path, "styles.css", "...", preview_bytes=2)

    assert preview == ".."
