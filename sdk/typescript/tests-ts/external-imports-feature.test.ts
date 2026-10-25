import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";

test.each(["win32", "linux", "darwin"])(
  "external import opt-in follows %s environment key semantics",
  (platform) => {
    const result = spawnSync(
      process.execPath,
      [
        "-e",
        `
const { strict: assert } = await import("node:assert");
const { importGitHubAdvisories } = await import(process.argv[2]);
Object.defineProperty(process, "platform", { value: process.argv[1] });
const flag = "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS";
const environments = [
  { Codex_Security_Enable_External_Imports: "1" },
  { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
  { Codex_Security_Enable_External_Imports: "0" },
  { Codex_Security_Enable_External_Imports: "true" },
  { Codex_Security_Enable_External_Imports: "1", CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: undefined },
  { codex_security_enable_external_imports: "1", Codex_Security_Enable_External_Imports: "0" },
  { codex_security_enable_external_imports: "0", Codex_Security_Enable_External_Imports: "1" },
  Object.create({ CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" }),
  Object.assign(Object.create({ CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "0" }), {
    Codex_Security_Enable_External_Imports: "1",
  }),
  Object.defineProperty({}, flag, { value: "1" }),
  Object.defineProperty({ [flag.toLowerCase()]: "1" }, flag, { value: "0" }),
  Object.defineProperty({ [flag.toLowerCase()]: "1" }, flag, { value: undefined }),
  {},
];
async function importAdvisories(environment) {
  let requests = 0;
  try {
    const advisories = await importGitHubAdvisories(
      { repository: "example/project" },
      { environment, createGitHub: async () => ({ request: async () => {
        requests++;
        return { data: [], headers: {} };
      } }) },
    );
    return { enabled: true, advisories, requests };
  } catch (error) {
    return { enabled: false, message: error.message, requests };
  }
}
const results = await Promise.all(environments.map(importAdvisories));
if (process.platform === "win32") {
  const mixed = "Codex_Security_Enable_External_Imports";
  for (const name of Object.keys(process.env)) if (name.toUpperCase() === flag) delete process.env[name];
  for (const hostKey of [flag, mixed, flag.toLowerCase()]) {
    for (const own of ["0", "1"]) {
      process.env[hostKey] = own === "0" ? "1" : "0";
      const overlay = Object.create(process.env, { [mixed]: { value: own, enumerable: true } });
      assert.equal((await importAdvisories(overlay)).requests, Number(own), hostKey);
    }
    delete process.env[hostKey];
  }
}
console.log(JSON.stringify(results));
`,
        platform,
        fileURLToPath(new URL("../src/github-advisories.ts", import.meta.url)),
      ],
      { encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    const enabled = { enabled: true, advisories: [], requests: 1 };
    const disabled = {
      enabled: false,
      message: expect.stringContaining(
        "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
      ),
      requests: 0,
    };
    expect(JSON.parse(result.stdout)).toEqual([
      platform === "win32" ? enabled : disabled,
      enabled,
      disabled,
      disabled,
      disabled,
      disabled,
      platform === "win32" ? enabled : disabled,
      enabled,
      disabled,
      enabled,
      disabled,
      platform === "win32" ? enabled : disabled,
      disabled,
    ]);
  },
);
