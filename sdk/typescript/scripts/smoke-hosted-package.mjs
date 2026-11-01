import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

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
console.log(
  "Validated hosted SDK exports, input validation, and CLI protocol.",
);
