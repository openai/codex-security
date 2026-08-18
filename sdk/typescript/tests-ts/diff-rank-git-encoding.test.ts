import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("diff ranking decodes Git path lists explicitly as UTF-8", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  const helper = join(PLUGIN_ROOT, "scripts", "generate_rank_input.py");
  const script = `
import importlib.util
import json
import subprocess
from pathlib import Path

helper = ${JSON.stringify(helper)}
spec = importlib.util.spec_from_file_location("codex_security_generate_rank_input", helper)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

calls = []
def fake_run(command, **kwargs):
    assert kwargs.get("text") is True
    assert kwargs.get("encoding") == "utf-8"
    calls.append(command)
    if "ls-files" in command:
        return subprocess.CompletedProcess(command, 0, stdout="src/新規.py\\0", stderr="")
    return subprocess.CompletedProcess(command, 0, stdout="M\\0src/測試.py\\0", stderr="")

module.subprocess.run = fake_run
repository = Path("/synthetic-repository")
committed = module.run_git_changed_paths(repository, ["base..head"])
working = module.git_changed_paths(repository, "base", "HEAD", "local-patch")
print(json.dumps({
    "calls": len(calls),
    "committed": [[str(path), status] for path, status in committed],
    "working": [[str(path), status] for path, status in working],
}, ensure_ascii=False))
`;

  const result = spawnSync(python!, ["-B", "-c", script], {
    encoding: "utf8",
  });
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    calls: 4,
    committed: [["/synthetic-repository/src/測試.py", "M"]],
    working: [
      ["/synthetic-repository/src/新規.py", "A"],
      ["/synthetic-repository/src/測試.py", "M"],
    ],
  });
});
