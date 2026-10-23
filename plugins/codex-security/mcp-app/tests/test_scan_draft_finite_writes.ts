import assert from "node:assert/strict";
import { readdir, rm } from "node:fs/promises";
import { test, type TestContext } from "node:test";
import { deserializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { finding } from "./scan-draft-fixture.ts";
import type { PreparedScanDraft } from "../../../../sdk/typescript/src/scan-semantics.js";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import { importSource } from "./import-module.ts";
import { privateDirectory } from "./helpers/source.mjs";

const { recordCodexSecurityScanDraft, scanDraftInputSchema } =
  await importSource("../src/artifact-scan-draft.ts", {
    absWorkingDir: import.meta.dirname,
  });
const marker = "overflow-number";
const finiteError = {
  name: "TypeError",
  message: "Stored finding JSON cannot contain non-finite numbers.",
};
const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";

function requestInput(input: unknown, token = "1e400") {
  const line = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "record_codex_security_scan_draft", arguments: input },
  }).replaceAll(JSON.stringify(marker), token);
  const request = CallToolRequestSchema.parse(deserializeMessage(line));
  return scanDraftInputSchema.parse(request.params.arguments);
}

function draft(overrides: Record<string, unknown> = {}) {
  return {
    scanId,
    findings: [],
    coverage: { surfaces: [], explicitExclusions: [], deferred: [] },
    ...overrides,
  };
}
function markedFinding(path = "api/source.py") {
  return {
    ...finding("overflow", path),
    extensions: { audit: { measurement: marker } },
  };
}
async function fixture(t: TestContext, mode: "standard" | "diff" | "deep") {
  const root = await privateDirectory("codex-security-finite-");
  t.after(() => rm(root, { recursive: true, force: true }));
  return {
    root,
    repoRoot: root,
    scanId,
    mode,
    status: "running",
    targetContract: {
      target: {
        allowedKinds: ["directory_snapshot"],
        targetId: "synthetic-target",
        displayName: "Synthetic repository",
      },
      scope: { requiredIncludePaths: ["api"], requiredExcludePaths: [] },
      ...(mode === "diff"
        ? {
            diffTarget: {
              kind: "range",
              baseRevision: "a".repeat(40),
              headRevision: "b".repeat(40),
            },
          }
        : {}),
    },
  };
}

for (const mode of ["standard", "diff", "deep"] as const) {
  for (const complete of [false, true]) {
    test(`${mode} ${complete ? "terminal" : "progress"} rejects retained overflow before publication`, async (t) => {
      const context = await fixture(t, mode);
      const input = requestInput(
        draft({ complete, findings: [markedFinding()] }),
      );
      assert.equal(input.findings[0].extensions.audit.measurement, Infinity);
      const before = structuredClone(input);
      let published = false;
      await assert.rejects(
        recordCodexSecurityScanDraft(context, input, async () => {
          published = true;
        }),
        finiteError,
      );
      assert.equal(published, false);
      assert.deepEqual(await readdir(context.root), []);
      assert.deepEqual(input, before);
    });
  }
}

for (const mode of ["standard", "deep"] as const) {
  test(`${mode} progress preserves outside findings in its authored checkpoint`, async (t) => {
    const context = await fixture(t, mode);
    const input = requestInput(
      draft({
        complete: false,
        findings: [markedFinding("outside/source.py")],
      }),
      "-1e400",
    );
    await assert.rejects(
      recordCodexSecurityScanDraft(context, input, async () =>
        assert.fail("published invalid draft"),
      ),
      finiteError,
    );
    assert.deepEqual(await readdir(context.root), []);
  });
}

test("terminal Deep publication drops outside overflow before writing", async (t) => {
  const context = await fixture(t, "deep");
  const kept = finding("kept", "api/source.py");
  const input = requestInput(
    draft({ findings: [kept, markedFinding("outside/source.py")] }),
  );
  const before = structuredClone(input);
  let published = false;
  await recordCodexSecurityScanDraft(
    context,
    input,
    async (
      documents: PreparedScanDraft,
      _digest: string | undefined,
      checkpoint: ScanDraftInput,
    ) => {
      published = true;
      assert.deepEqual(documents.findings.findings, [kept]);
      assert.deepEqual(checkpoint.findings, [kept]);
      assert.equal(Object.hasOwn(documents.coverage, "completeness"), false);
    },
  );
  assert.equal(published, true);
  assert.deepEqual(input, before);
});

test("terminal Deep publication retains overflow when a later location matches scope", async (t) => {
  const context = await fixture(t, "deep");
  const mixed = markedFinding("outside/source.py");
  mixed.locations.push({ path: "api/source.py", startLine: 3, endLine: 4 });
  await assert.rejects(
    recordCodexSecurityScanDraft(
      context,
      requestInput(draft({ findings: [mixed] })),
      async () => assert.fail("published invalid draft"),
    ),
    finiteError,
  );
});

for (const field of ["deferred", "surfaces", "threatModel"] as const) {
  test(`terminal Deep publication rejects overflow in retained ${field} metadata`, async (t) => {
    const context = await fixture(t, "deep");
    const metadata = { audit: { measurement: marker } };
    const input = draft();
    if (field === "threatModel")
      Object.assign(input, {
        threatModel: { summary: "API model", ...metadata },
      });
    else
      Object.assign(input.coverage, {
        [field]: [
          field === "deferred"
            ? { reason: "Review API", ...metadata }
            : { label: "API", disposition: "needs_follow_up", ...metadata },
        ],
      });
    await assert.rejects(
      recordCodexSecurityScanDraft(context, requestInput(input), async () =>
        assert.fail("published invalid draft"),
      ),
      finiteError,
    );
    assert.deepEqual(await readdir(context.root), []);
  });
}

test("publication preserves finite nested values", async (t) => {
  const context = await fixture(t, "standard");
  let nested: unknown = 1.25e300;
  for (let depth = 0; depth < 300; depth++) nested = [nested];
  const kept = {
    ...finding("finite", "api/source.py"),
    extensions: {
      values: [null, true, false, 0, -1.25e300, "Infinity", "λ 🧪"],
      nested,
    },
  };
  await recordCodexSecurityScanDraft(
    context,
    requestInput(draft({ findings: [kept] })),
    async (
      documents: PreparedScanDraft,
      _digest: string | undefined,
      checkpoint: ScanDraftInput,
    ) => {
      assert.deepEqual(documents.findings.findings, [kept]);
      assert.deepEqual(checkpoint.findings, [kept]);
    },
  );
});
