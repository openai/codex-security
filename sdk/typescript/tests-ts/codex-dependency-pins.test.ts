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

test("the Wolfi recipe records sources for its pinned Linux amd64 binaries", async () => {
  const repo = new URL("../../../", import.meta.url);
  const [sources, sdk, wolfi, action] = await Promise.all(
    [
      "docker/wolfi/payload/native-sources.json",
      "sdk/typescript/package.json",
      "docker/wolfi/payload/package-lock.json",
      "github-action/runtime/package-lock.json",
    ].map((path) => Bun.file(new URL(path, repo)).json()),
  );
  const codex = wolfi.packages["node_modules/@openai/codex-linux-x64"];
  const canvas = "@napi-rs/canvas-linux-x64-gnu";
  // Action release preparation replaces the scanner and its exact Codex dependency.
  // It can retain the transitive Canvas resolution from its existing npm lock.
  for (const name of [
    `@openai/codex@${sdk.dependencies["@openai/codex"]}-linux-x64`,
    `${codex.name}@${codex.version}`,
    ...[wolfi, action].map(
      (lock) => `${canvas}@${lock.packages[`node_modules/${canvas}`].version}`,
    ),
  ]) {
    expect(
      sources[name] ?? "",
      `Review Wolfi source and notices for ${name}`,
    ).toMatch(/\/tree\/[a-f0-9]{40}$/);
  }
});
