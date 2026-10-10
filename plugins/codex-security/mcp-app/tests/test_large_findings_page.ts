import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { rm } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { applicationRoot, buildServer } from "./build-server.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const exec = promisify(execFile);
const pluginRoot = path.dirname(applicationRoot);
const python = process.env.PYTHON || "python3";

await test("returns an accepted 50-finding Unicode page through the MCP subprocess", async () => {
  const root = await temporaryDirectory("codex-security-large-findings-");
  const client = new Client({
    name: "large-findings-fixture",
    version: "1.0.0",
  });
  try {
    const fixture = await exec(
      python,
      [
        "-c",
        `import copy, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workbench_test_support import empty_target_scan, run_workbench, write_completed_contract
state, target, scan_id, scan_dir = empty_target_scan(Path(sys.argv[2]))
write_completed_contract(scan_dir, scan_id, target)
file = scan_dir / "findings.json"
document = json.loads(file.read_text())
template = document["findings"][0]
document["findings"] = []
for index in range(50):
    finding = copy.deepcopy(template)
    finding["identity"]["anchor"] = f"synthetic-large-page-{index}"
    finding["locations"] = [{"path": "/".join(["é" * 64] * 15 + [f"fixture-{index}-{location}.py"]), "startLine": 1, "endLine": 1, "role": "sink"} for location in range(8)]
    document["findings"].append(finding)
file.write_text(json.dumps(document))
run_workbench(state, "complete-scan", "--scan-id", scan_id)
print(json.dumps({"scanId": scan_id, "target": str(target), "state": str(state)}))`,
        path.join(pluginRoot, "tests"),
        root,
      ],
      { maxBuffer: Infinity },
    );
    const { scanId, target, state } = JSON.parse(fixture.stdout);
    const environment = {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: state,
      CODEX_HOME: path.join(root, "home"),
    };
    for (const limit of [20, 50]) {
      const { stdout } = await exec(
        python,
        [
          path.join(pluginRoot, "scripts/workbench_db.py"),
          "list-findings",
          "--scan-id",
          scanId,
          "--limit",
          String(limit),
        ],
        { env: environment, maxBuffer: Infinity },
      );
      assert.equal(JSON.parse(stdout).findingsPage.findings.length, limit);
      assert.equal(Buffer.byteLength(stdout) > 4 * 1024 * 1024, limit === 50);
    }

    const bundle = path.join(root, "server.cjs");
    await buildServer(bundle, {
      define: {
        __dirname: JSON.stringify(applicationRoot),
        "import.meta.url": "__filename",
      },
    });
    const env = Object.fromEntries(
      Object.entries(environment).filter(
        (entry): entry is [string, string] => entry[1] !== undefined,
      ),
    );
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [bundle, "--stdio"],
        cwd: target,
        env,
      }),
    );
    for (const limit of [20, 50]) {
      const result = await client.callTool({
        name: "list_codex_security_findings",
        arguments: { scanId, limit },
      });
      assert.notEqual(result.isError, true, JSON.stringify(result));
      const { findingsPage: page } = result.structuredContent as {
        findingsPage: { findings: unknown[]; limit: number };
      };
      assert.equal(page.findings.length, limit);
      assert.equal(page.limit, limit);
    }
  } finally {
    await client.close();
    await rm(root, { recursive: true, force: true });
  }
});
