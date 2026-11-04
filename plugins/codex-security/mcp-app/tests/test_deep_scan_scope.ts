import assert from "node:assert/strict";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { finding } from "./scan-draft-fixture.ts";
import { fixture } from "./scan-draft-recovery-fixture.ts";
import { readJson } from "./support/json.ts";

const findings = [
  finding("api", "api/source.py"),
  finding("jobs", "background jobs/source.py"),
  finding("unrelated", "unrelated/source.py"),
  finding("prefix", "api-other/source.py"),
];

for (const resumed of [false, true]) {
  for (const [label, binding, expected] of [
    [
      "multi-path",
      { scope: ".", includePaths: ["api", "background jobs"] },
      ["api", "jobs", "file-descendant"],
    ],
    ["single-path", { scope: "api" }, ["api", "file-descendant"]],
    [
      "normalized-paths",
      { includePaths: ["./api/", "background jobs/."] },
      ["api", "jobs", "file-descendant"],
    ],
    [
      "file-path",
      { includePaths: ["./api/source.py"], filePaths: ["api/source.py/"] },
      ["api"],
    ],
    [
      "repository",
      { scope: "." },
      ["api", "jobs", "unrelated", "prefix", "file-descendant"],
    ],
  ] as const) {
    test(`${label} worker filters reconciled findings with resumed=${resumed}`, async (t) => {
      const f = await fixture(t, "worker");
      await mkdir(join(f.root, "api"));
      await writeFile(join(f.root, "api/source.py"), "# scoped file\n");
      const input = {
        ...f.draft({}, true),
        findings: [
          ...findings,
          finding("file-descendant", "api/source.py/generated"),
        ],
      };
      let checkpoints: [string, Buffer][] = [];
      if (resumed) {
        await f.write(input);
        checkpoints = await Promise.all(
          (await readdir(join(f.root, "checkpoints"))).map(
            async (name) =>
              [name, await readFile(join(f.root, "checkpoints", name))] as [
                string,
                Buffer,
              ],
          ),
        );
      }
      Object.assign(f.context, binding);
      await f.write({ ...input, findings: resumed ? [] : input.findings });
      const result = await readJson(f.root, "result.json");
      assert.deepEqual(
        result.findings.map(
          (row: { identity: { anchor: string } }) => row.identity.anchor,
        ),
        expected,
      );
      for (const [name, bytes] of checkpoints)
        assert.deepEqual(
          await readFile(join(f.root, "checkpoints", name)),
          bytes,
        );
    });
  }
}

for (const mode of ["deep", "standard"] as const) {
  test(`${mode} parent publication keeps its scope behavior`, async (t) => {
    const f = await fixture(t, mode);
    f.context.targetContract = {
      ...f.context.targetContract,
      scope: {
        requiredIncludePaths: ["api", "background jobs"],
        requiredExcludePaths: [],
      },
    };
    const input = { ...f.draft({}, true), findings };
    await f.write(input);
    const result = await readJson(f.root, "findings.json");
    assert.deepEqual(
      result.findings.map(
        (row: { identity: { anchor: string } }) => row.identity.anchor,
      ),
      mode === "deep"
        ? ["api", "jobs"]
        : ["api", "jobs", "unrelated", "prefix"],
    );
    assert.equal(input.findings.length, 4);
  });
}

for (const legacy of [false, true]) {
  test(`artifact MCP uses the coordinator's multi-path binding with legacy=${legacy}`, async (t) => {
    const { importSource } = await import("./import-module.ts");
    const { Client } =
      await import("@modelcontextprotocol/sdk/client/index.js");
    const { InMemoryTransport } =
      await import("@modelcontextprotocol/sdk/inMemory.js");
    const { createCodexSecurityArtifactWriterServer } = await importSource(
      "../artifact-writer-main.ts",
      { absWorkingDir: import.meta.dirname },
    );
    const f = await fixture(t, "worker");
    const scopeFile = join(f.root, "../scope café.json");
    const paths = [
      "api/source.py",
      "background jobs",
      ...Array.from({ length: 1024 }, (_, index) => `source ${index}/café`),
    ];
    await writeFile(
      scopeFile,
      JSON.stringify(
        legacy ? paths : { paths, filePaths: ["./api/source.py"] },
      ),
    );
    const server = await createCodexSecurityArtifactWriterServer({
      CODEX_SECURITY_ARTIFACT_ROOT: f.root,
      CODEX_SECURITY_REPO_ROOT: f.root,
      CODEX_SECURITY_SCAN_ID: f.context.scanId,
      CODEX_SECURITY_SCOPE: ".",
      CODEX_SECURITY_INCLUDE_PATHS_FILE: scopeFile,
    });
    const client = new Client({ name: "scope-fixture", version: "1.0.0" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      assert.equal(
        client.getServerVersion()?.version,
        (await readJson(import.meta.dirname, "../package.json")).version,
      );
      const response = await client.callTool({
        name: "record_codex_security_scan_draft",
        arguments: {
          ...f.draft({}, true),
          findings: [
            ...findings,
            finding("descendant", "api/source.py/generated"),
          ],
        },
      });
      assert.equal(response.isError, undefined);
      const result = await readJson(f.root, "result.json");
      assert.deepEqual(
        result.findings.map(
          (row: { identity: { anchor: string } }) => row.identity.anchor,
        ),
        legacy ? ["api", "jobs", "descendant"] : ["api", "jobs"],
      );
    } finally {
      await client.close();
      await server.close();
    }
  });
}

test("worker scope keeps a finding with any matching location and supports exact files", async (t) => {
  const f = await fixture(t, "worker");
  Object.assign(f.context, {
    includePaths: ["api/source.py", "background jobs"],
  });
  const mixed = finding("mixed", "unrelated/source.py");
  mixed.locations.push({ path: "api/source.py", startLine: 1, endLine: 2 });
  await f.write({
    ...f.draft({}, true),
    findings: [...findings, mixed, finding("other-api", "api/other.py")],
  });
  const result = await readJson(f.root, "result.json");
  assert.deepEqual(
    result.findings.map(
      (row: { identity: { anchor: string } }) => row.identity.anchor,
    ),
    ["api", "jobs", "mixed"],
  );
  assert.deepEqual(result.findings.at(-1).locations, mixed.locations);
});

for (const scope of ["./api/", "api/source.py"]) {
  test(`Deep parent publication respects ${scope}`, async (t) => {
    const f = await fixture(t, "deep");
    await mkdir(join(f.root, "api"));
    await writeFile(join(f.root, "api/source.py"), "# scoped file\n");
    f.context.targetContract = {
      ...f.context.targetContract,
      scope: {
        requiredIncludePaths: [scope],
        requiredExcludePaths: [],
        filePaths: scope === "api/source.py" ? [scope] : [],
      },
    };
    await f.write({
      ...f.draft({}, true),
      findings: [findings[0], finding("descendant", "api/source.py/generated")],
    });
    const result = await readJson(f.root, "findings.json");
    assert.deepEqual(
      result.findings.map(
        (row: { identity: { anchor: string } }) => row.identity.anchor,
      ),
      scope === "./api/" ? ["api", "descendant"] : ["api"],
    );
  });
}

for (const layout of ["worker", "deep"] as const) {
  for (const scope of ["./api/", "./api/source.py"]) {
    test(`${layout} preserves original ${scope} scope after checkout changes`, async (t) => {
      const f = await fixture(t, layout);
      await mkdir(join(f.root, "api"));
      await writeFile(join(f.root, "api/source.py"), "# original target\n");
      const filePaths = scope.endsWith(".py") ? ["api/source.py"] : [];
      Object.assign(f.context, { includePaths: [scope], filePaths });
      f.context.targetContract = {
        ...f.context.targetContract,
        scope: {
          requiredIncludePaths: [scope],
          requiredExcludePaths: [],
          filePaths,
        },
      };
      const input = {
        ...f.draft({}, true),
        findings: [
          findings[0],
          finding("descendant", "api/source.py/generated"),
        ],
      };
      await f.write(input);
      const checkpoints = await Promise.all(
        (await readdir(join(f.root, "checkpoints"))).map(
          async (name) =>
            [name, await readFile(join(f.root, "checkpoints", name))] as const,
        ),
      );
      if (filePaths.length) {
        await rm(join(f.root, "api/source.py"));
        await mkdir(join(f.root, "api/source.py"));
      } else {
        await rm(join(f.root, "api"), { recursive: true });
        await writeFile(join(f.root, "api"), "new checkout file\n");
      }
      await f.write(layout === "worker" ? { ...input, findings: [] } : input);
      const result = await readJson(
        f.root,
        layout === "worker" ? "result.json" : "findings.json",
      );
      assert.deepEqual(
        result.findings.map(
          (row: { identity: { anchor: string } }) => row.identity.anchor,
        ),
        filePaths.length ? ["api"] : ["api", "descendant"],
      );
      for (const [name, bytes] of checkpoints)
        assert.deepEqual(
          await readFile(join(f.root, "checkpoints", name)),
          bytes,
        );
    });
  }
}
