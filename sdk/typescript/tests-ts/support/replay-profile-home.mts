import assert from "node:assert/strict";
import { snapshotNativeEnvironment } from "../../../../plugins/codex-security/mcp-app/src/native-executable.js";
import { mkdir, readFile, realpath, symlink } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { main } from "../../src/cli.js";
import {
  createProviderProfile,
  restoreProviderProfile,
} from "../../src/provider-profile.js";
import type { JsonObject } from "../../src/config.js";
import { capture, dependencies, savedRecipe } from "../cli-fixtures.js";

const root = await realpath(process.argv[2]!);
const alias = join(root, "alias");
const physical = join(root, "physical");
const aliasHome = join(alias, "home");
const physicalHome = join(physical, "home");
await Promise.all([
  mkdir(aliasHome, { recursive: true }),
  mkdir(physicalHome, { recursive: true }),
  mkdir(join(physical, "nested"), { recursive: true }),
]);
await symlink(
  join(physical, "nested"),
  join(alias, "link"),
  process.platform === "win32" ? "junction" : "dir",
);
const rawHome = `${alias}${sep}link${sep}..${sep}home`;
const traversedHome = process.platform === "win32" ? aliasHome : physicalHome;
const privateConfig = {
  model_providers: {
    synthetic: {
      name: "Synthetic",
      wire_api: "responses",
      http_headers: { Authorization: "synthetic-provider-token" },
    },
  },
};
let canonicalControl: JsonObject | undefined;
const results = [];
for (const [spelling, requestedHome, expectedHome] of [
  ["absolute", rawHome, traversedHome],
  [
    "relative",
    `${relative(process.cwd(), alias)}${sep}link${sep}..${sep}home`,
    traversedHome,
  ],
  ["home-relative", `~${sep}alias${sep}link${sep}..${sep}home`, aliasHome],
  [
    "missing-parent",
    `${root}${sep}missing${sep}..${sep}physical${sep}home`,
    physicalHome,
  ],
] as const) {
  const environment = {
    HOME: root,
    USERPROFILE: root,
    CODEX_HOME: requestedHome,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const previous = Object.fromEntries(
    Object.keys(environment).map((key) => [key, process.env[key]]),
  );
  let producer: Record<string, string>;
  try {
    Object.assign(process.env, environment);
    producer = await snapshotNativeEnvironment();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
  const selectedHome = producer.CODEX_HOME!;
  assert.equal(selectedHome, expectedHome);
  const profile = await createProviderProfile(selectedHome, privateConfig);
  const reference = { name: profile.name, home: "ambient" };
  canonicalControl = await restoreProviderProfile({}, reference, {
    CODEX_HOME: selectedHome,
  });
  const original = await readFile(profile.path);
  for (const command of ["resume", "rerun"] as const) {
    const saved = savedRecipe({
      model: "gpt-5.6-sol",
      model_provider: "synthetic",
    });
    Object.assign(saved.recipe, { mode: "deep", providerProfile: reference });
    let observed: JsonObject | undefined;
    let launches = 0;
    const stderr = capture();
    const code = await main(
      ["scans", command, saved.scanId, "--json"],
      capture().stream,
      stderr.stream,
      dependencies({
        environment,
        onWorkbench: () => ({ ...saved, scanDir: join(root, "scan") }),
        onConfig: (config) => {
          observed = config.codexOverrides as JsonObject;
        },
        onRun: () => {
          launches++;
        },
      }),
    );
    results.push({
      command,
      spelling,
      code,
      launches,
      observed,
      error: stderr.text(),
      profileUnchanged: (await readFile(profile.path)).equals(original),
      environmentUnchanged: environment.CODEX_HOME === requestedHome,
    });
  }
}
console.log(JSON.stringify({ canonicalControl, privateConfig, results }));
