import { mkdir, readFile, realpath, symlink } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { main } from "../../src/cli.js";
import {
  createReplayProfile,
  restoreReplayProfile,
} from "../../src/provider-profile.js";
import type { JsonObject } from "../../src/config.js";
import { capture, dependencies, savedRecipe } from "../cli-fixtures.js";

const root = await realpath(process.argv[2]!);
const alias = join(root, "alias");
const physical = join(root, "physical");
await Promise.all([
  mkdir(join(alias, "home"), { recursive: true }),
  mkdir(join(physical, "nested"), { recursive: true }),
  mkdir(join(physical, "home"), { recursive: true }),
]);
await symlink(
  join(physical, "nested"),
  join(alias, "link"),
  process.platform === "win32" ? "junction" : "dir",
);
// Keep the junction outside either directory selected as the credential home.
const rawHome = `${alias}${sep}link${sep}..${sep}home`;
// Native startup uses Node's realpath before writing its private replay file.
const selectedHome = await realpath(rawHome);
const privateConfig = {
  model_providers: {
    synthetic: {
      name: "Synthetic",
      wire_api: "responses",
      http_headers: { Authorization: "synthetic-provider-token" },
    },
  },
  mcp_servers: {
    synthetic: {
      url: "https://mcp.example.test",
      http_headers: { Authorization: "synthetic-mcp-token" },
    },
  },
};
const profile = await createReplayProfile(selectedHome, privateConfig);
const reference = { name: profile.name, home: "ambient" };
const canonicalControl = await restoreReplayProfile({}, reference, {
  CODEX_HOME: selectedHome,
});
const original = await readFile(profile.path);
const results = [];
for (const [spelling, requestedHome] of [
  ["absolute", rawHome],
  ["relative", `${relative(process.cwd(), alias)}${sep}link${sep}..${sep}home`],
  ["home-relative", `~${sep}alias${sep}link${sep}..${sep}home`],
] as const) {
  for (const command of ["resume", "rerun"] as const) {
    const environment = {
      HOME: root,
      USERPROFILE: root,
      CODEX_HOME: requestedHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    const saved = savedRecipe({
      model: "gpt-5.6-sol",
      model_provider: "synthetic",
    });
    Object.assign(saved.recipe, { mode: "deep", replayProfile: reference });
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
