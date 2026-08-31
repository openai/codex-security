import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

export const gitExecutable = execFileSync(
  process.env.PYTHON?.trim() || "python3",
  ["-c", "import shutil; print(shutil.which('git') or '')"],
  { encoding: "utf8" }
).trim();

assert.ok(gitExecutable, "Git is required for repository fixtures.");
