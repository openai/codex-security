import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

import { packageSmokeTimeouts } from "./package-smoke-timeouts.mjs";

const { commandTimeoutMs } = packageSmokeTimeouts();
const packageRoot = resolve(process.argv[2] ?? ".");
const publicSdk = await import(
  pathToFileURL(join(packageRoot, "dist/index.js")).href
);
assert.equal(typeof publicSdk.runHostedScan, "function");
const fixture = JSON.parse(
  await readFile(
    createRequire(join(packageRoot, "package.json")).resolve(
      "@openai/codex-security/schemas/hosted-scan-v2.fixture.json",
    ),
    "utf8",
  ),
);
const input = publicSdk.HostedScanInputSchema.parse(fixture.run.params);
assert.equal(input.version, 2);
await assert.rejects(
  publicSdk.runHostedScan(
    { ...input, scope: { paths: [] } },
    { executor: { run: () => assert.fail("Invalid input must not execute") } },
  ),
  { name: "ZodError" },
);

// Check the packaged entrypoint and protocol without repository preparation.
// Real scans and executor receipts are covered by hosted-scan.test.ts.
const result = spawnSync(
  process.execPath,
  [join(packageRoot, "bin/codex-security.mjs"), "scan", "--host"],
  { input: "invalid JSON\n", encoding: "utf8", windowsHide: true },
);
assert.equal(result.error, undefined);
assert.equal(result.status, 2, result.stderr);
const response = JSON.parse(result.stdout);
assert.equal(response.jsonrpc, "2.0");
assert.equal(response.id, null);
assert.equal(response.error.code, -32700);
// A late failed review exercises the installed classifier's observer and frame writer.
const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const records = Array.from({ length: 9 }, (_, index) => {
  const id = `fixture-${index}`;
  const findingJson = JSON.stringify({
    findingId: id,
    title: "Synthetic finding",
    summary: "Synthetic evidence",
    severity: { level: "low" },
  });
  return { id, revision: 1, inputSha256: sha256(findingJson), findingJson };
});
const rubric = "High";
const request = {
  jsonrpc: "2.0",
  id: "run",
  method: "run",
  params: {
    version: 1,
    model: "fixture",
    effort: "high",
    records,
    rubric: { revision: 1, markdown: rubric, sha256: sha256(rubric) },
  },
};
for (const enabled of [false, true]) {
  const args = enabled ? ["--conditions=codex-security-records-logs-v1"] : [];
  const child = spawn(
    process.execPath,
    [
      ...args,
      join(packageRoot, "bin/codex-security.mjs"),
      "classify-severity",
      "--records",
    ],
    {
      stdio: ["pipe", "pipe", "inherit"],
      windowsHide: true,
      timeout: commandTimeoutMs,
      killSignal: "SIGKILL",
      env: { ...process.env, NODE_OPTIONS: "" },
    },
  );
  const closed = once(child, "close");
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const send = (frame) => child.stdin.write(JSON.stringify(frame) + "\n");
  let reviews = 0;
  const codes = [];
  let terminal;
  try {
    send(request);
    for await (const line of lines) {
      const frame = JSON.parse(line);
      if (enabled) {
        assert.equal(frame.cliDiagnostics.dropped, 0);
        codes.push(
          ...frame.cliDiagnostics.records.map((record) => JSON.parse(record)),
        );
      } else {
        assert.equal(Object.hasOwn(frame, "cliDiagnostics"), false);
      }
      if (frame.method === "review.run") {
        reviews++;
        if (reviews === 27)
          send({
            jsonrpc: "2.0",
            id: frame.id,
            error: { code: -32001, message: "Synthetic review failure" },
          });
        else
          send({
            jsonrpc: "2.0",
            id: frame.id,
            result: {
              findingId: records[Math.floor((reviews - 1) / 3)].id,
              decision: "assessed",
              level: "high",
              rubricLabel: "High",
              rationale: "Synthetic rationale",
              confidence: "high",
              reviewTrigger: null,
            },
          });
      } else {
        assert.equal(frame.id, request.id);
        terminal = frame.result;
      }
    }
    assert.deepEqual(await closed, [1, null]);
    assert.equal(reviews, 27);
    assert.equal(terminal?.error?.code, "review_failed");
    if (enabled) {
      assert.deepEqual(
        codes.slice(0, 3).map((record) => record.code),
        ["invocation_started", "input_validated", "review_requested"],
      );
      assert.deepEqual(
        codes.slice(-2).map(({ code, ordinal }) => [code, ordinal]),
        [
          ["review_failed", 3],
          ["exit_unresolved", undefined],
        ],
      );
      assert.equal(
        codes.filter((record) => record.code === "review_requested").length,
        27,
      );
    }
  } finally {
    lines.close();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  }
}
console.log(
  "Validated hosted SDK exports, scans and classifier diagnostics through the installed CLI.",
);
