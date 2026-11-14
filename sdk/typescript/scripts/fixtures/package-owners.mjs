import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [installedRoot, consumer] = process.argv.slice(2);
const repository = join(consumer, "owner-repository");
const plugin = join(installedRoot, "_bundled_plugin");
const input = join(
  plugin,
  "examples",
  "legacy-completed-scan",
  "findings.json",
);
const { findings } = JSON.parse(await readFile(input, "utf8"));
await mkdir(join(repository, "src"), { recursive: true });
await writeFile(join(repository, "CODEOWNERS"), "* @reviewer @backup\n");
await writeFile(join(repository, "src", "extract.py"), "pass\n".repeat(48));
const git = (...args) =>
  execFileSync("git", args, { cwd: repository, encoding: "utf8" }).trim();
git("init", "-q");
git("add", ".");
git(
  "-c",
  "user.name=Author",
  "-c",
  "user.email=author@example.test",
  "-c",
  "commit.gpgsign=false",
  "commit",
  "-qm",
  "Add fixture",
);

const scan = JSON.parse(
  execFileSync(
    process.execPath,
    [
      join(plugin, "mcp", "scan-owners.mjs"),
      repository,
      git("rev-parse", "HEAD"),
    ],
    { input: JSON.stringify([findings[0]]), encoding: "utf8" },
  ),
);
const cli = JSON.parse(
  execFileSync(
    process.execPath,
    [
      join(installedRoot, "bin", "codex-security.mjs"),
      "suggest-owners",
      input,
      "--source-root",
      repository,
      "--json",
    ],
    {
      cwd: consumer,
      encoding: "utf8",
      env: { ...process.env, CODEX_HOME: join(consumer, "owner-home") },
    },
  ),
);
assert.deepEqual(
  cli.results[0].suggestions.map(({ owner }) => owner.handle),
  ["reviewer", "backup"],
);
assert.deepEqual(scan.suggestions.slice(0, 2), cli.results[0].suggestions);
assert.equal(scan.suggestions[2].owner.email, "author@example.test");
