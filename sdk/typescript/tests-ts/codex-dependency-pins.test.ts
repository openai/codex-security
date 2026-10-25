import { readFile } from "node:fs/promises";
import { expect, test } from "bun:test";

test("pins one Codex version across the CLI, MCP app, and evals", async () => {
  const directories = [
    "sdk/typescript",
    "plugins/codex-security/mcp-app",
    "evals/triage-finding",
  ];
  const manifests = await Promise.all(
    directories.map(async (directory) =>
      JSON.parse(
        await readFile(
          new URL(`../../../${directory}/package.json`, import.meta.url),
          "utf8",
        ),
      ),
    ),
  );
  const version = manifests[0].dependencies["@openai/codex"];
  expect(version).toBeTruthy();
  for (const [index, directory] of directories.entries()) {
    expect(manifests[index].dependencies["@openai/codex-sdk"]).toBe(version);
    const lockfile = Bun.YAML.parse(
      await readFile(
        new URL(`../../../${directory}/pnpm-lock.yaml`, import.meta.url),
        "utf8",
      ),
    ) as {
      packages: Record<string, { os?: string[]; cpu?: string[] }>;
    };
    expect(
      Object.keys(lockfile.packages).filter((name) =>
        name.startsWith("@openai/codex-sdk@"),
      ),
    ).toEqual([`@openai/codex-sdk@${version}`]);
    for (const [name, metadata] of Object.entries(lockfile.packages)) {
      if (name.startsWith("@openai/codex@")) {
        const platform =
          metadata.os && metadata.cpu
            ? `-${metadata.os[0]}-${metadata.cpu[0]}`
            : "";
        expect(name).toBe(`@openai/codex@${version}${platform}`);
      }
    }
  }
});
