import { afterEach, expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runCodexSkillCommand } from "../src/cli.js";
import { capture } from "./cli-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test("patch transports a large administration profile through the child protocol", async () => {
  const directory = await fixtures.create("patch-large-profile-");
  const readOnlyPaths = Array.from({ length: 1024 }, (_, index) =>
    join(
      directory,
      "repositories",
      `synthetic-${index}-${"a".repeat(100)}`,
      ".git",
    ),
  );
  const filesystem = Object.fromEntries(
    readOnlyPaths.map((path) => [path, { ".": "read" }]),
  );
  expect(Buffer.byteLength(JSON.stringify(filesystem))).toBeGreaterThan(
    128 * 1024,
  );
  await writeFile(
    join(directory, "expected-paths.json"),
    JSON.stringify(readOnlyPaths),
  );
  const child = join(directory, "app-server.cjs");
  await writeFile(
    child,
    `
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const paths = JSON.parse(fs.readFileSync(path.join(__dirname, "expected-paths.json"), "utf8"));
assert.equal(process.argv.some((arg) => arg.includes("permissions.codex_security_patch")), false);
assert.equal(process.argv.some((arg) => Buffer.byteLength(arg) >= 128 * 1024), false);
const lines = require("node:readline").createInterface({ input: process.stdin });
const send = (message) => process.stdout.write(JSON.stringify(message) + "\\n");
let configured = false;
let preflight = false;
let permissionProfile;
lines.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.method === "initialize") {
    send({ id: request.id, result: {} });
  } else if (request.method === "config/read") {
    configured = true;
    send({ id: request.id, result: { config: {} } });
  } else if (request.method === "thread/start") {
    assert.equal(configured, true);
    const profiles = Object.keys(request.params.config.permissions);
    assert.equal(profiles.length, 1);
    permissionProfile = profiles[0];
    assert.match(permissionProfile, /^codex_security_patch_[a-f0-9-]+$/);
    assert.deepEqual(request.params.config, { default_permissions: permissionProfile, permissions: { [permissionProfile]: {
      extends: ":workspace", network: { enabled: false }, workspace_roots: {},
      filesystem: Object.fromEntries(paths.map((value) => [value, { ".": "read" }]))
    } } });
    send({ id: request.id, result: { thread: { id: "large-profile-thread" }, sandbox: {
      type: "workspaceWrite", writableRoots: [], networkAccess: false,
      excludeTmpdirEnvVar: false, excludeSlashTmp: false
    } } });
  } else if (request.method === "command/exec") {
    assert.equal(request.params.sandboxPolicy.type, "workspaceWrite");
    assert.equal(Object.hasOwn(request.params, "permissionProfile"), false);
    preflight = true;
    send({ id: request.id, result: { exitCode: 0, stdout: "", stderr: "" } });
  } else if (request.method === "experimentalFeature/list") {
    send({ id: request.id, result: { data: [{ name: "cli_daybreak", enabled: false }], nextCursor: null } });
  } else if (request.method === "turn/start") {
    assert.equal(preflight, true);
    assert.equal(request.params.permissions, permissionProfile);
    assert.equal(request.params.threadId, "large-profile-thread");
    send({ id: request.id, result: { turn: { id: "large-profile-turn" } } });
    send({ method: "item/completed", params: { threadId: "large-profile-thread", turnId: "large-profile-turn", item: { type: "agentMessage", text: "All synthetic paths received." } } });
    send({ method: "turn/completed", params: { threadId: "large-profile-thread", turn: { id: "large-profile-turn", status: "completed" } } });
  }
});
`,
  );
  const stdout = capture();
  const stderr = capture();
  expect(
    await runCodexSkillCommand(
      [child],
      {
        command: "patch",
        stdout: stdout.stream,
        stderr: stderr.stream,
        appServer: {
          directory,
          prompt: "Fix the synthetic issue.",
          threadSource: "security_remediation",
          permissions: { name: "codex_security_patch", readOnlyPaths },
        },
      },
      { command: process.execPath },
      { PATH: process.env["PATH"] },
    ),
  ).toBe(0);
  expect(stdout.text()).toBe("All synthetic paths received.\n");
  expect(stderr.text()).toBe("");
});
