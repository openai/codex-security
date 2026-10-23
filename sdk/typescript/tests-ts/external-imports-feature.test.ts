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
const { importGitHubAdvisories } = await import(process.argv[2]);
Object.defineProperty(process, "platform", { value: process.argv[1] });
const environments = [
  { Codex_Security_Enable_External_Imports: "1" },
  { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
  { Codex_Security_Enable_External_Imports: "0" },
  { Codex_Security_Enable_External_Imports: "true" },
  {},
];
const results = await Promise.all(environments.map(async (environment) => {
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
}));
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
    ]);
  },
);
