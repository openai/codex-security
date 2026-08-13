import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { brotliDecompressSync } from "node:zlib";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

type JsonObject = Record<string, unknown>;

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function createRepository(): { root: string; repository: string } {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  mkdirSync(repository);
  git(repository, "init", "-q");
  return { root, repository };
}

function git(repository: string, ...args: string[]): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { cwd: repository, encoding: "utf8" },
  ).trim();
}

function writeSource(
  repository: string,
  path: string,
  content: string | Buffer,
): void {
  const destination = join(repository, path);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, content);
}

function python(script: string, ...args: string[]) {
  const command =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(command).not.toBeNull();
  return spawnSync(
    command!,
    ["-B", join(PLUGIN_ROOT, "scripts", script), ...args],
    { encoding: "utf8" },
  );
}

function pythonWithState(stateDir: string, script: string, ...args: string[]) {
  const command =
    Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(command).not.toBeNull();
  return spawnSync(
    command!,
    ["-B", join(PLUGIN_ROOT, "scripts", script), ...args],
    {
      encoding: "utf8",
      env: { ...process.env, CODEX_SECURITY_STATE_DIR: stateDir },
    },
  );
}

function immutableDiffDigest(
  kind: "commit" | "range",
  baseRevision: string,
  headRevision: string,
): string {
  const digest = createHash("sha256")
    .update("codex-security-diff/v1\0")
    .update(kind)
    .update("\0")
    .update(baseRevision)
    .update("\0")
    .update(headRevision)
    .digest("hex");
  return `codex-security-snapshot/v1:sha256:${digest}`;
}

function candidate(path: string): JsonObject {
  return {
    cwe_ids: [],
    locations: [{ path, start_line: 1, role: "root_control" }],
    summary: "The handler may rely on a removed guard.",
    evidence: "The selected change removes the neighboring guard.",
  };
}

async function startMcp(root: string) {
  const child = spawn(
    process.execPath,
    [join(PLUGIN_ROOT, "mcp", "server.mjs"), "--stdio"],
    {
      env: {
        ...process.env,
        CODEX_SECURITY_SCAN_ROOT: join(root, "scans"),
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        PYTHONDONTWRITEBYTECODE: "1",
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const messages = createInterface({ input: child.stdout })[
    Symbol.asyncIterator
  ]();
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  let nextId = 0;

  async function request(
    method: string,
    params: JsonObject,
  ): Promise<JsonObject> {
    const id = ++nextId;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    child.stdin.write("\n");

    while (true) {
      const message = await messages.next();
      if (message.done) {
        throw new Error(`MCP server exited before replying: ${stderr}`);
      }
      const response = JSON.parse(message.value) as JsonObject;
      if (response["id"] !== id) continue;
      if (response["error"] !== undefined) {
        throw new Error(JSON.stringify(response["error"]));
      }
      return response["result"] as JsonObject;
    }
  }

  await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "compact-diff-test", version: "1.0.0" },
  });
  child.stdin.write(
    `${JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    })}\n`,
  );

  return {
    request,
    async call(
      name: string,
      args: JsonObject,
      owner: string,
    ): Promise<JsonObject> {
      const result = await request("tools/call", {
        name,
        arguments: args,
        _meta: { "openai/threadId": owner },
      });
      expect(result["isError"], JSON.stringify(result)).not.toBe(true);
      return result["structuredContent"] as JsonObject;
    },
    async close(): Promise<void> {
      child.stdin.end();
      await new Promise<void>((resolve) => {
        child.once("close", () => resolve());
      });
    },
  };
}

describe("compact diff scan", () => {
  test("uses the selected Git revisions and keeps deleted source files", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/guard.py", "allowed = True\n");
    writeSource(repository, "src/handler.py", "value = 1\n");
    writeSource(repository, "src/untouched.py", "unchanged = True\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    const base = git(repository, "rev-parse", "HEAD");

    rmSync(join(repository, "src", "guard.py"));
    writeSource(repository, "src/handler.py", "value = 2\n");
    writeSource(repository, "src/new handler.py", "created = True\n");
    writeSource(repository, "src/binary.py", Buffer.from([0, 255, 1]));
    writeSource(repository, "tests/ignored.py", "ignored = True\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "selected changes");
    const head = git(repository, "rev-parse", "HEAD");
    writeSource(repository, "src/handler.py", Buffer.from([0, 255, 1]));
    const output = join(root, "in-scope.txt");

    const result = python(
      "generate_in_scope_files.py",
      "--repo",
      repository,
      "--scope",
      ".",
      "--diff-base",
      base,
      "--diff-head",
      head,
      "--out",
      output,
    );

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(output, "utf8").split("\n").filter(Boolean)).toEqual([
      "src/guard.py",
      "src/handler.py",
      "src/new handler.py",
    ]);
  });

  test("includes staged, unstaged, and untracked working-tree changes", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/handler.py", "value = 1\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    writeSource(repository, "src/handler.py", "value = 2\n");
    writeSource(repository, "src/staged.py", "staged = True\n");
    git(repository, "add", "src/staged.py");
    writeSource(repository, "src/untracked.py", "untracked = True\n");
    writeSource(repository, "src/binary.py", Buffer.from([0, 255, 1]));
    const output = join(root, "in-scope.txt");

    const result = python(
      "generate_in_scope_files.py",
      "--repo",
      repository,
      "--scope",
      ".",
      "--diff-base",
      "HEAD",
      "--diff-mode",
      "local-patch",
      "--out",
      output,
    );

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(output, "utf8").split("\n").filter(Boolean)).toEqual([
      "src/handler.py",
      "src/staged.py",
      "src/untracked.py",
    ]);
  });

  test("keeps deleted inventory paths without accepting unsafe candidates", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/handler.py", "value = 1\n");
    const inventory = join(root, "in-scope.txt");
    const input = join(root, "candidates.jsonl");
    const output = join(root, "normalized.jsonl");
    writeFileSync(inventory, "src/deleted.py\nsrc/handler.py\n");
    writeFileSync(input, `${JSON.stringify(candidate("src/handler.py"))}\n`);
    const args = [
      "--input",
      input,
      "--out",
      output,
      "--repo-root",
      repository,
      "--in-scope-files",
      inventory,
    ];

    expect(python("normalize_candidates.py", ...args).status).toBe(2);
    const accepted = python(
      "normalize_candidates.py",
      ...args,
      "--allow-missing-in-scope",
    );
    expect(accepted.status, accepted.stderr).toBe(0);
    const normalized = JSON.parse(readFileSync(output, "utf8")) as {
      locations: { path: string }[];
    };
    expect(normalized.locations[0]?.path).toBe("src/handler.py");

    writeFileSync(inventory, "../escaped.py\nsrc/handler.py\n");
    const escaped = python(
      "normalize_candidates.py",
      ...args,
      "--allow-missing-in-scope",
    );
    expect(escaped.status).toBe(2);
    expect(escaped.stderr).toContain("in-scope file row 1");
  });

  test("derives canonical digests for immutable and working-tree diffs", () => {
    const { repository } = createRepository();
    writeSource(repository, "app.ts", "export const value = 1;\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "first");
    const first = git(repository, "rev-parse", "HEAD");
    writeSource(repository, "app.ts", "export const value = 2;\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "second");
    const second = git(repository, "rev-parse", "HEAD");
    writeSource(repository, "app.ts", "export const value = 3;\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "third");
    const third = git(repository, "rev-parse", "HEAD");

    const inspect = (
      kind: "commit" | "range" | "working_tree",
      baseRevision?: string,
      headRevision?: string,
    ): JsonObject => {
      const args = [
        "inspect-setup",
        "--target-path",
        repository,
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        kind,
      ];
      if (baseRevision !== undefined)
        args.push("--diff-base-revision", baseRevision);
      if (headRevision !== undefined)
        args.push("--diff-head-revision", headRevision);
      const result = python("workbench_db.py", ...args);
      expect(result.status, result.stderr).toBe(0);
      return (JSON.parse(result.stdout) as { diffTarget: JsonObject }).diffTarget;
    };

    const commit = inspect("commit", second, third);
    const range = inspect("range", second, third);
    const repeatedRange = inspect("range", second, third);
    const widerRange = inspect("range", first, third);
    expect(commit["contentDigest"]).toBe(
      immutableDiffDigest("commit", second, third),
    );
    expect(range["contentDigest"]).toBe(
      immutableDiffDigest("range", second, third),
    );
    expect(repeatedRange["contentDigest"]).toBe(range["contentDigest"]);
    expect(commit["contentDigest"]).not.toBe(range["contentDigest"]);
    expect(widerRange["contentDigest"]).not.toBe(range["contentDigest"]);

    writeSource(repository, "app.ts", "export const value = 4;\n");
    const workingTree = inspect("working_tree");
    const repeatedWorkingTree = inspect("working_tree");
    expect(workingTree["contentDigest"]).toMatch(
      /^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/u,
    );
    expect(repeatedWorkingTree["contentDigest"]).toBe(
      workingTree["contentDigest"],
    );
    writeSource(repository, "app.ts", "export const value = 5;\n");
    expect(inspect("working_tree")["contentDigest"]).not.toBe(
      workingTree["contentDigest"],
    );
  });

  test("prepares CLI range completion with the canonical snapshot digest", () => {
    const { root, repository } = createRepository();
    writeSource(repository, "app.ts", "export const value = 1;\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    const baseRevision = git(repository, "rev-parse", "HEAD");
    writeSource(repository, "app.ts", "export const value = 2;\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "head");
    const headRevision = git(repository, "rev-parse", "HEAD");
    const stateDir = join(root, "state");
    const scanDir = join(root, "scan");
    mkdirSync(stateDir);
    mkdirSync(scanDir);

    const registration = pythonWithState(
      stateDir,
      "workbench_db.py",
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "standard",
        repository,
        target: {
          kind: "refs",
          paths: [],
          base: baseRevision,
          head: headRevision,
        },
      }),
    );
    expect(registration.status, registration.stderr).toBe(0);
    const scanId = (JSON.parse(registration.stdout) as { scanId: string })
      .scanId;

    cpSync(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
      recursive: true,
    });
    const manifestPath = join(scanDir, "scan-manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      scan: {
        id: string;
        sealedAt?: string;
        artifacts?: unknown;
        target: JsonObject;
      };
    };
    manifest.scan.id = scanId;
    manifest.scan.target["kind"] = "git_diff";
    delete manifest.scan.target["snapshotDigest"];
    delete manifest.scan.sealedAt;
    delete manifest.scan.artifacts;
    writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);

    for (const name of ["findings.json", "coverage.json"]) {
      const path = join(scanDir, name);
      const artifact = JSON.parse(readFileSync(path, "utf8")) as JsonObject;
      artifact["scanId"] = scanId;
      writeFileSync(path, `${JSON.stringify(artifact)}\n`);
    }
    writeFileSync(join(scanDir, "report.md"), "# Draft report\n");

    const prepared = pythonWithState(
      stateDir,
      "workbench_db.py",
      "prepare-scan-completion",
      "--scan-id",
      scanId,
    );
    expect(prepared.status, prepared.stderr).toBe(0);
    const target = (
      (
        JSON.parse(readFileSync(manifestPath, "utf8")) as {
          scan: { target: JsonObject };
        }
      ).scan
    ).target;
    expect(target["snapshotDigest"]).toBe(
      immutableDiffDigest("range", baseRevision, headRevision),
    );
  });

  test("runs the compact MCP diff lifecycle through a completed scan", async () => {
    const { root, repository } = createRepository();
    writeSource(repository, "src/guard.py", "allowed = True\n");
    writeSource(repository, "src/handler.py", "value = 1\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    const baseRevision = git(repository, "rev-parse", "HEAD");
    rmSync(join(repository, "src", "guard.py"));
    writeSource(repository, "src/handler.py", "value = 2\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "changed");
    const headRevision = git(repository, "rev-parse", "HEAD");
    mkdirSync(join(root, "scans"));
    mkdirSync(join(root, "state"));
    const client = await startMcp(root);
    const owner = "compact-diff-owner";
    const call = (name: string, args: JsonObject) =>
      client.call(name, args, owner);

    try {
      const tools = (await client.request("tools/list", {}))["tools"] as {
        name: string;
        inputSchema: { properties: Record<string, { maxLength?: number }> };
      }[];
      expect(tools.map((tool) => tool.name)).toContain(
        "prepare_codex_security_review_items",
      );
      expect(tools.map((tool) => tool.name)).toContain(
        "record_codex_security_discovery_candidates",
      );
      expect(
        tools.find((tool) => tool.name === "start_codex_security_standard_scan")
          ?.inputSchema.properties["userContext"]?.maxLength,
      ).toBe(2400);

      const selection = {
        targetPath: repository,
        scope: ".",
        mode: "diff",
        diffTarget: { kind: "range", baseRevision, headRevision },
      };
      const opened = await call("open_codex_security_workspace", selection);
      const sessionId = (opened["workspace"] as JsonObject)["id"] as string;
      await call("submit_codex_security_setup", { ...selection, sessionId });
      const started = await call("start_codex_security_scan", { sessionId });
      const results = (started["workspace"] as JsonObject)[
        "results"
      ] as JsonObject;
      const scanId = results["scanId"] as string;
      const handoffClaimToken = randomUUID();
      await call("claim_codex_security_scan_handoff_delivery", {
        scanId,
        claimToken: handoffClaimToken,
      });
      await call("attach_codex_security_scan_continuation_thread", {
        scanId,
        claimToken: handoffClaimToken,
        threadId: owner,
      });
      await call("get_codex_security_scan_context", {
        scanId,
        handoffClaimToken,
      });

      const inventory = await call("prepare_codex_security_review_items", {
        scanId,
        handoffClaimToken,
      });
      expect(inventory["reviewItemsTotal"]).toBe(2);
      const items = await call("list_codex_security_review_items", {
        scanId,
        handoffClaimToken,
      });
      expect(items["items"]).toEqual([
        { path: "src/guard.py" },
        { path: "src/handler.py" },
      ]);

      await call("record_codex_security_discovery_candidates", {
        scanId,
        candidates: [candidate("src/handler.py")],
      });
      const listed = await call("list_codex_security_candidates", { scanId });
      const rows = listed["rows"] as JsonObject[];
      expect(rows).toHaveLength(1);
      await call("record_codex_security_candidate_validations", {
        scanId,
        validations: [
          {
            candidateId: rows[0]?.["candidate_id"],
            validation: {
              disposition: "suppressed",
              method: "Static review of the changed handler.",
              confidence: "high",
              confidence_rationale: "The assignment is directly visible.",
              rubric: ["The assignment does not cross a trust boundary."],
              evidence: ["value = 2"],
              counterevidence_or_proof_gap: "No sensitive operation exists.",
              remaining_uncertainty: "",
            },
          },
        ],
      });
      await call("record_candidate_attack_paths", { scanId, attackPaths: [] });
      await call("record_codex_security_scan_draft", {
        scanId,
        handoffClaimToken,
        findings: [],
        coverage: {
          completeness: "complete",
          surfaces: [{ label: "Changed files", disposition: "rejected" }],
          explicitExclusions: [],
          deferred: [],
        },
      });
      await call("complete_codex_security_scan", {
        scanId,
        handoffClaimToken,
      });
      const completed = await call("get_codex_security_completed_scan", {
        scanId,
        handoffClaimToken,
      });
      const target = (
        (completed["manifest"] as JsonObject)["scan"] as JsonObject
      )["target"] as JsonObject;
      expect(target["snapshotDigest"]).toBe(
        immutableDiffDigest("range", baseRevision, headRevision),
      );
      expect((completed["coverage"] as JsonObject)["inventoryStrategy"]).toBe(
        "diff",
      );
    } finally {
      await client.close();
    }
  });

  test("preserves stable finding identities from existing public scans", () => {
    const runtime = brotliDecompressSync(
      Buffer.concat(
        ["000", "001"].map((part) =>
          readFileSync(join(PLUGIN_ROOT, "mcp", `server.mjs.br.part-${part}`)),
        ),
      ),
    ).toString("utf8");
    const source = /function buildFindings\(findings\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
    expect(source).toBeDefined();
    const buildFindings = new Function(
      "semanticIdentifier",
      `${source}\nreturn buildFindings;`,
    )((value: string) => value) as (findings: JsonObject[]) => JsonObject[];

    const [finding] = buildFindings([
      {
        title: "Changed title",
        extensions: { candidateId: "candidate-stable" },
      },
    ]);
    expect((finding?.["identity"] as JsonObject)["anchor"]).toBe(
      "candidate-stable",
    );
  });
});
