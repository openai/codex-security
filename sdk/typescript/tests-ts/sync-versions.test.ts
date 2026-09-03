import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";

const { syncVersions } = (await import(
  new URL("../scripts/sync-versions.mjs", import.meta.url).href
)) as {
  syncVersions: (options: {
    root: string;
    check?: boolean;
  }) => Promise<{ version: string; changed: string[] }>;
};

const roots: string[] = [];
const manifests = [
  "plugins/codex-security/.codex-plugin/plugin.json",
  "plugins/codex-security/mcp-app/package.json",
  "plugins/codex-security/pyproject.toml",
];

afterEach(async () => {
  for (const root of roots.splice(0)) {
    await rm(root, { recursive: true, force: true });
  }
});

async function fixture(): Promise<string> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "release-versions-")),
  );
  roots.push(root);
  const files: Record<string, string> = {
    "sdk/typescript/package.json": JSON.stringify({
      name: "@openai/codex-security",
      version: "0.2.0",
    }),
    "plugins/codex-security/.codex-plugin/plugin.json":
      '{\n  "name": "codex-security",\n  "version": "0.1.79"\n}\n',
    "plugins/codex-security/mcp-app/package.json": JSON.stringify(
      {
        name: "codex-security-mcp-app",
        version: "0.1.158",
        private: true,
        dependencies: { "@openai/codex-sdk": "0.149.1" },
      },
      null,
      2,
    ),
    "plugins/codex-security/pyproject.toml":
      '[project]\nname = "codex-security"\nversion = "0.1.0"\n\n[tool.ruff]\nrequired-version = "==0.16.1"\n',
  };
  for (const [path, contents] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), contents);
  }
  return root;
}

test("reports component version drift without rewriting manifests", async () => {
  const root = await fixture();
  const before = await Promise.all(
    manifests.map((path) => readFile(join(root, path), "utf8")),
  );

  await expect(syncVersions({ root, check: true })).rejects.toThrow(
    manifests.join("\n"),
  );
  expect(
    await Promise.all(
      manifests.map((path) => readFile(join(root, path), "utf8")),
    ),
  ).toEqual(before);
});

test("synchronizes component metadata while preserving dependency versions", async () => {
  const root = await fixture();
  expect(await syncVersions({ root })).toEqual({
    version: "0.2.0",
    changed: manifests,
  });
  const plugin = JSON.parse(
    await readFile(join(root, manifests[0]!), "utf8"),
  ) as { version: string };
  const mcp = JSON.parse(await readFile(join(root, manifests[1]!), "utf8")) as {
    version: string;
    dependencies: Record<string, string>;
    private: boolean;
  };
  expect(plugin.version).toBe("0.2.0");
  expect(mcp.version).toBe("0.2.0");
  expect(mcp.private).toBe(true);
  expect(mcp.dependencies["@openai/codex-sdk"]).toBe("0.149.1");
  expect(await readFile(join(root, manifests[2]!), "utf8")).toBe(
    '[project]\nname = "codex-security"\nversion = "0.2.0"\n\n[tool.ruff]\nrequired-version = "==0.16.1"\n',
  );
  expect(await syncVersions({ root, check: true })).toEqual({
    version: "0.2.0",
    changed: [],
  });
  expect((await syncVersions({ root })).changed).toEqual([]);
});
