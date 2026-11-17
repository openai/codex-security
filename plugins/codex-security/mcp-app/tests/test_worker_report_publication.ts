import assert from "node:assert/strict";
import { mkdir, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { fixture } from "./scan-draft-recovery-fixture.ts";
import { finding } from "./scan-draft-fixture.ts";

const { validateDiscoveryArtifacts } = await importSource(
  "src/deep-scan/artifact-validation.ts",
);

for (const [field, extra, error] of [
  [
    "findings",
    {
      findings: [
        { ...finding("api", "api/source.py"), title: "invalid \ud800 text" },
      ],
    },
    /well-formed Unicode/,
  ],
  [
    "scope",
    { scope: { metrics: { count: Number.MAX_SAFE_INTEGER + 1 } } },
    /unsafe integer/,
  ],
  [
    "threatModel",
    { threatModel: { summary: "Model", metadata: { "\udc00": true } } },
    /well-formed Unicode/,
  ],
] as const) {
  test(`worker tool and direct result both reject unpublishable ${field} metadata`, async (t) => {
    const f = await fixture(t, "worker");
    const draft = { ...f.draft({}, true), ...extra };
    await assert.rejects(f.write(draft), error);
    assert.deepEqual(await readdir(f.root), []);
    const output = join(f.root, "first", "output");
    await mkdir(output, { recursive: true });
    const path = join(output, "result.json");
    await writeFile(path, JSON.stringify(draft));
    await assert.rejects(
      validateDiscoveryArtifacts({ workersRoot: f.root }, path, draft.scanId),
      error,
    );
  });
}
