// Exercise the installed CLI over real pipes with a fake host, without inference.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  exerciseRemediationProtocol,
  remediationInput,
} from "../tests-ts/support/hosted-remediation.mjs";

const packageRoot = resolve(process.argv[2] ?? join(import.meta.dirname, ".."));
const node = process.argv[3] ?? process.execPath;
const entrypoint = join(packageRoot, "bin", "codex-security.mjs");
const repository = await mkdtemp(join(tmpdir(), "hosted-remediation-smoke-"));
const git = (...args) =>
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { cwd: repository, encoding: "utf8" },
  ).trim();
const source = join(repository, "guard.ts");
const candidate = "export const allowed = true;\n";

try {
  await writeFile(source, "export const allowed = false;\n");
  git("init", "-q");
  git("add", ".");
  git("commit", "-qm", "fixture");
  const revision = git("rev-parse", "HEAD");
  for (const operation of ["patch", "verify"]) {
    const input = remediationInput({ repository, revision }, operation);
    await exerciseRemediationProtocol(node, entrypoint, input, {
      async onExecution(request) {
        assert.ok(request.prompt.includes(input.validationInstructions));
        const skill = operation === "patch" ? "fix-finding" : "verify-fix";
        assert.ok(
          await readFile(
            join(request.runtime.pluginRoot, "skills", skill, "SKILL.md"),
            "utf8",
          ),
        );
        if (operation === "patch") await writeFile(source, candidate);
        else assert.equal(await readFile(source, "utf8"), candidate);
      },
    });
    assert.equal(await readFile(source, "utf8"), candidate);
  }
  console.log(
    JSON.stringify({
      status: "passed",
      operations: ["patch", "verify"],
      executor: "fake",
    }),
  );
} finally {
  await rm(repository, { recursive: true, force: true });
}
