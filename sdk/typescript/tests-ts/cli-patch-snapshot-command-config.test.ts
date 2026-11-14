import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { runRepositoryCommand } from "../src/cli.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test("snapshot filters receive safe command config from both Git encodings", async () => {
  const cwd = await fixtures.create("snapshot-command-config-");
  const credentials = "synthetic-config-marker";
  const run = (command: string, args: string[], options = {}) =>
    execFileSync(command, args, { cwd, encoding: "utf8", ...options });
  run("git", ["init", "--quiet"]);
  await writeFile(join(cwd, ".gitattributes"), "*.txt filter=check\n");
  await writeFile(join(cwd, "note.txt"), "input\n");
  await writeFile(
    join(cwd, "check.cjs"),
    [
      'const raw = Object.values(process.env).join("\\n");',
      "process.stdout.write(JSON.stringify({",
      '  secret: raw.includes("synthetic-config-marker"),',
      '  input: require("node:fs").readFileSync(0, "utf8"),',
      "}));",
    ].join("\n"),
  );

  const env = {
    ...process.env,
    CODEX_HOME: await fixtures.create("snapshot-config-home-"),
    GIT_CONFIG_COUNT: "3",
    GIT_CONFIG_KEY_0: "demo.value",
    GIT_CONFIG_VALUE_0: "first",
    GIT_CONFIG_KEY_1: "http.extraHeader",
    GIT_CONFIG_VALUE_1: "Authorization: " + credentials,
    GIT_CONFIG_KEY_2: "http.proxy",
    GIT_CONFIG_VALUE_2: "https://proxy.example.test/?route=a@b",
    GIT_CONFIG_VALUE_9: credentials,
  };
  const parameters = [
    "'demo.value'='second with spaces'",
    "'demo.a=b.flag'=",
    "'demo.empty'=''",
    "'demo.value'='third'\\''s'",
    "'remote.origin.proxy'='https:/user:" +
      credentials +
      "@proxy.example.test'",
    "'url.https://user:" + credentials + "@example.test/.insteadOf'='example:'",
  ].join(" ");
  await writeFile(
    join(env.CODEX_HOME, "config.toml"),
    patchSnapshotWindowsConfig() +
      `[shell_environment_policy.set]
GIT_CONFIG_PARAMETERS="'http.extraHeader'='Authorization: synthetic-config-marker'"
`,
  );
  const objects = await fixtures.create("snapshot-config-objects-");
  const filtered = await runRepositoryCommand(
    "git",
    [
      "-c",
      "filter.check.clean=git config --get-all demo.value && git config --type=bool demo.a=b.flag && git config demo.empty && git config http.proxy && node check.cjs",
      "hash-object",
      "-w",
      "--path=note.txt",
      "note.txt",
    ],
    cwd,
    {
      sandbox: {
        directory: cwd,
        environment: patchSnapshotEnvironment(
          await fixtures.create("snapshot-config-temp-"),
          env,
        ),
        gitEnvironment: {
          GIT_CONFIG_PARAMETERS: parameters,
          GIT_OBJECT_DIRECTORY: objects,
        },
        profile: {
          extends: ":workspace",
          network: { enabled: false },
          filesystem: { [objects]: { ".": "write" } },
        },
      },
    },
  );
  const blob = run("git", ["cat-file", "blob", filtered], {
    env: { ...process.env, GIT_OBJECT_DIRECTORY: objects },
  });
  const lines = blob.split("\n");
  expect(lines.slice(0, 6)).toEqual([
    "first",
    "second with spaces",
    "third's",
    "true",
    "",
    env.GIT_CONFIG_VALUE_2,
  ]);
  expect(JSON.parse(lines.slice(6).join("\n"))).toEqual({
    secret: false,
    input: "input\n",
  });
});
