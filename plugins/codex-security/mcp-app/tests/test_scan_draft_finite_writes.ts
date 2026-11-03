import assert from "node:assert/strict";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { deserializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { finding } from "./scan-draft-fixture.ts";
import {
  draftApi,
  fixture,
  interruptDraftWrite,
} from "./scan-draft-recovery-fixture.ts";
import { readJson } from "./support/json.ts";

const marker = "overflow-number";
const finiteError = {
  name: "TypeError",
  message: "Stored finding JSON cannot contain non-finite numbers.",
};

// JSON exponent overflow survives the MCP decoder and registered tool schema.
function requestInput(draft: unknown, token = "1e400") {
  const line = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "record_codex_security_scan_draft", arguments: draft },
  }).replaceAll(JSON.stringify(marker), token);
  const request = CallToolRequestSchema.parse(deserializeMessage(line));
  return draftApi.scanDraftInputSchema.parse(request.params.arguments);
}

function markedFinding(repositoryPath = "api/source.py") {
  return {
    ...finding("overflow", repositoryPath),
    extensions: { audit: { measurement: marker } },
  };
}

async function checkpoints(root: string) {
  const names = await readdir(join(root, "checkpoints"));
  assert.ok(names.length > 0);
  return Promise.all(names.map((name) => readJson(root, "checkpoints", name)));
}

for (const layout of ["standard", "diff", "deep", "worker"] as const) {
  for (const complete of layout === "deep" ? [false, true] : [true]) {
    test(`${layout} ${complete ? "terminal" : "progress"} rejects retained overflow before writing`, async (t) => {
      const f = await fixture(t, layout);
      const input = requestInput({
        ...f.draft({}, complete),
        findings: [markedFinding()],
      });
      assert.equal(input.findings[0].extensions.audit.measurement, Infinity);
      const before = structuredClone(input);
      await assert.rejects(f.write(input), finiteError);
      assert.deepEqual(await readdir(f.root), []);
      assert.deepEqual(input, before);
    });
  }
}

for (const layout of ["standard", "deep"] as const) {
  test(`${layout} progress retains outside findings in its authored checkpoint`, async (t) => {
    const f = await fixture(t, layout);
    Object.assign(f.context.targetContract!.scope as object, {
      requiredIncludePaths: ["api"],
    });
    const input = requestInput(
      { ...f.draft(), findings: [markedFinding("outside/source.py")] },
      "-1e400",
    );
    await assert.rejects(f.write(input), finiteError);
    assert.deepEqual(await readdir(f.root), []);
  });
}

for (const layout of ["worker", "deep"] as const) {
  test(`${layout} drops outside overflow before saving a terminal draft`, async (t) => {
    const f = await fixture(t, layout);
    f.context.scope = "api";
    Object.assign(f.context.targetContract!.scope as object, {
      requiredIncludePaths: ["api"],
    });
    const kept = finding("kept", "api/source.py");
    const input = requestInput({
      ...f.draft({ completeness: marker }, true),
      findings: [kept, markedFinding("outside/source.py")],
    });
    const before = structuredClone(input);
    assert.equal((await f.write(input)).findingCount, 1);
    const saved =
      layout === "worker"
        ? await readJson(f.root, "result.json")
        : {
            ...(await readJson(f.root, "findings.json")),
            reviewState: await readJson(f.root, "coverage.json"),
          };
    for (const document of [saved, ...(await checkpoints(f.root))]) {
      assert.deepEqual(document.findings, [kept]);
      assert.equal(Object.hasOwn(document.reviewState, "completeness"), false);
    }
    assert.deepEqual(input, before);
    if (layout === "deep")
      assert.deepEqual(await readdir(join(f.root, "drafts")), []);
  });

  test(`${layout} retains overflow when a later finding location matches scope`, async (t) => {
    const f = await fixture(t, layout);
    f.context.scope = "api";
    Object.assign(f.context.targetContract!.scope as object, {
      requiredIncludePaths: ["api"],
    });
    const mixed = markedFinding("outside/source.py");
    mixed.locations.push({ path: "api/source.py", startLine: 3, endLine: 4 });
    const input = requestInput(
      { ...f.draft({}, true), findings: [mixed] },
      "-1e400",
    );
    await assert.rejects(f.write(input), finiteError);
    assert.deepEqual(await readdir(f.root), []);
  });

  for (const field of ["deferred", "surfaces", "threatModel"] as const) {
    test(`${layout} rejects overflow in retained ${field} metadata`, async (t) => {
      const f = await fixture(t, layout);
      const metadata = { audit: { measurement: marker } };
      const input = requestInput({
        ...f.draft(
          field === "deferred"
            ? { deferred: [{ reason: "Review API", ...metadata }] }
            : field === "surfaces"
              ? {
                  surfaces: [
                    {
                      label: "API",
                      disposition: "needs_follow_up",
                      ...metadata,
                    },
                  ],
                }
              : {},
          true,
        ),
        ...(field === "threatModel"
          ? { threatModel: { summary: "API model", ...metadata } }
          : {}),
      });
      const before = structuredClone(input);
      await assert.rejects(
        f.write(input),
        layout === "worker" && field !== "threatModel"
          ? {
              name: "Error",
              message: `coverage.${field}[0].<property>.<property>: non-finite JSON numbers are not supported`,
            }
          : finiteError,
      );
      assert.deepEqual(await readdir(f.root), []);
      assert.deepEqual(input, before);
    });
  }
}

test("Deep retains historical threat-model reader behavior", async (t) => {
  const f = await fixture(t, "deep");
  const manifest =
    '{"scan":{"threatModel":{"summary":"Earlier model","audit":{"measurement":1e400}}}}\n';
  await writeFile(join(f.root, "scan-manifest.json"), manifest, "utf8");
  const input = requestInput(f.draft({}, true));
  let calls = 0;
  await draftApi.recordCodexSecurityScanDraftViaWorkbench(
    f.context,
    input,
    async (args: string[]) => {
      calls++;
      const draft = await readJson(args[args.indexOf("--draft-path") + 1]);
      const checkpoint = await readJson(
        args[args.indexOf("--checkpoint-path") + 1],
      );
      assert.equal(draft.manifest.scan.threatModel.audit.measurement, null);
      assert.equal(checkpoint.threatModel.audit.measurement, null);
      return {};
    },
  );
  assert.equal(calls, 1);
  assert.equal(
    await readFile(join(f.root, "scan-manifest.json"), "utf8"),
    manifest,
  );
  assert.deepEqual(await readdir(join(f.root, "drafts")), []);
  assert.equal(Object.hasOwn(input, "threatModel"), false);
});

test("worker recovers finite nested values after an interrupted result write", async (t) => {
  const f = await fixture(t, "worker");
  let nested: unknown = 1.25e300;
  for (let depth = 0; depth < 300; depth++) nested = [nested];
  const kept = {
    ...finding("finite", "api/source.py"),
    extensions: {
      values: [null, true, false, 0, -1.25e300, "Infinity", "λ 🧪"],
      nested,
    },
  };
  const input = requestInput({ ...f.draft(), findings: [kept] });
  await interruptDraftWrite(join(f.root, "result.json"), () => f.write(input));
  assert.deepEqual((await checkpoints(f.root))[0].findings, [kept]);
  await f.write(f.draft());
  assert.deepEqual((await readJson(f.root, "result.json")).findings, [kept]);
});
