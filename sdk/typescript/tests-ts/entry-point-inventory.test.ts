import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

type EntryPoint = {
  path: string;
  line: number;
  kind: string;
  framework: string;
  evidence: string;
  symbol?: string;
};

type Summary = {
  documentType: string;
  schemaVersion: string;
  filesScanned: number;
  entryPointCount: number;
  truncated: boolean;
  byKind: Record<string, number>;
  byFramework: Record<string, number>;
  files: Array<{ path: string; entryPointCount: number }>;
};

const SCRIPT = join(PLUGIN_ROOT, "scripts", "inventory_entry_points.py");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  while (temporaryDirectories.length > 0) {
    const directory = temporaryDirectories.pop();
    if (directory) {
      await rm(directory, { recursive: true, force: true });
    }
  }
});

async function repositoryWith(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-entry-points-"));
  temporaryDirectories.push(root);
  for (const [relative, contents] of Object.entries(files)) {
    const absolute = join(root, relative);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, contents);
  }
  return root;
}

function inventory(root: string): { rows: EntryPoint[]; raw: string } {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const result = spawnSync(
    python!,
    ["-I", "-B", SCRIPT, "--repo", root, "--out", "-"],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  const raw = result.stdout;
  const rows = raw
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as EntryPoint);
  return { rows, raw };
}

function summaryOf(root: string): Summary {
  const python = Bun.which("python3") ?? Bun.which("python");
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      SCRIPT,
      "--repo",
      root,
      "--out",
      "/dev/null",
      "--summary",
      "-",
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as Summary;
}

describe("entry point inventory", () => {
  test("reports framework routes with their handler symbols", async () => {
    const root = await repositoryWith({
      "server/api.py": [
        "from flask import Blueprint",
        "",
        "bp = Blueprint('api', __name__)",
        "",
        '@bp.post("/withdraw")',
        "def withdraw():",
        "    return {}",
        "",
        "@bp.after_request",
        "def add_headers(response):",
        "    return response",
      ].join("\n"),
    });

    const { rows } = inventory(root);

    expect(rows).toEqual([
      {
        path: "server/api.py",
        line: 5,
        kind: "http_route",
        framework: "flask",
        symbol: "withdraw",
        evidence: '@bp.post("/withdraw")',
      },
    ]);
  });

  test("covers express, apollo, and go across languages", async () => {
    const root = await repositoryWith({
      "web/server.js": 'app.get("/health", (req, res) => res.send("ok"));',
      "web/graph.js": "export const server = new ApolloServer({ typeDefs });",
      "svc/main.go": 'http.HandleFunc("/status", statusHandler)',
    });

    const { rows } = inventory(root);
    const seen = rows.map((row) => `${row.kind}:${row.framework}`).sort();

    expect(seen).toEqual([
      "graphql:apollo",
      "http_route:express",
      "http_route:net_http",
    ]);
  });

  test("finds workflow triggers, which the shared worklist constants exclude", async () => {
    const root = await repositoryWith({
      ".github/workflows/ci.yml": [
        "name: CI",
        "on:",
        "  pull_request_target:",
        "    types: [opened]",
        "  workflow_dispatch:",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
      ].join("\n"),
    });

    const { rows } = inventory(root);

    // generate_rank_input.EXCLUDED_DIRS contains ".github", so worklist-driven
    // scans never see this file. The inventory deliberately does not inherit
    // that exclusion.
    expect(rows.map((row) => row.symbol)).toEqual([
      "pull_request_target",
      "workflow_dispatch",
    ]);
    expect(rows.every((row) => row.kind === "ci_trigger")).toBe(true);
    // "types:" is nested under a trigger and is not itself a trigger.
    expect(rows.some((row) => row.symbol === "types")).toBe(false);
  });

  test("does not treat trigger names outside the on block as triggers", async () => {
    const root = await repositoryWith({
      ".github/workflows/ci.yml": [
        "name: CI",
        "on:",
        "  push:",
        "jobs:",
        "  build:",
        "    steps:",
        "      - run: echo pull_request_target:",
        "    issues:",
      ].join("\n"),
    });

    const { rows } = inventory(root);

    expect(rows.map((row) => row.symbol)).toEqual(["push"]);
  });

  test("requires the lambda signature before claiming a serverless handler", async () => {
    const root = await repositoryWith({
      "app/callbacks.py": [
        "def handler(agent_id, message):",
        "    return True",
        "",
        "def lambda_handler(event, context):",
        "    return {}",
        "",
        "def process(event, context):",
        "    return {}",
      ].join("\n"),
    });

    const { rows } = inventory(root);

    // A bare `handler` taking arbitrary arguments is an ordinary callback.
    expect(rows.map((row) => row.symbol).sort()).toEqual([
      "lambda_handler",
      "process",
    ]);
    expect(rows.every((row) => row.kind === "serverless_handler")).toBe(true);
  });

  test("separates stdlib http.server from tornado", async () => {
    const root = await repositoryWith({
      "a/stdlib.py": "class Probe(BaseHTTPRequestHandler):\n    pass",
      "a/tornado_app.py": "class Main(RequestHandler):\n    pass",
    });

    const { rows } = inventory(root);
    const byPath = Object.fromEntries(
      rows.map((row) => [row.path, row.framework]),
    );

    expect(byPath["a/stdlib.py"]).toBe("http_server");
    expect(byPath["a/tornado_app.py"]).toBe("tornado");
  });

  test("reports nothing for code with no remote entry point", async () => {
    const root = await repositoryWith({
      "web/merge.js": "export function merge(a, b) { return { ...a, ...b }; }",
      "lib/util.py": "def add(left, right):\n    return left + right",
      "README.md": "# Docs\n\napp.get is mentioned in prose only.",
    });

    const { rows } = inventory(root);

    expect(rows).toEqual([]);
  });

  test("skips commented-out routes", async () => {
    const root = await repositoryWith({
      "server/api.py": [
        '# @bp.post("/legacy")',
        '@bp.post("/live")',
        "def live():",
        "    return {}",
      ].join("\n"),
    });

    const { rows } = inventory(root);

    expect(rows).toHaveLength(1);
    expect(rows[0]!.line).toBe(2);
  });

  test("ignores dependency and build directories", async () => {
    const root = await repositoryWith({
      "node_modules/pkg/index.js": 'app.get("/vendored", handler);',
      "dist/bundle.js": 'app.get("/built", handler);',
      "src/app.js": 'app.get("/real", handler);',
    });

    const { rows } = inventory(root);

    expect(rows.map((row) => row.path)).toEqual(["src/app.js"]);
  });

  test("produces byte-identical output across runs", async () => {
    const root = await repositoryWith({
      "a/one.py": '@app.route("/a")\ndef a():\n    return {}',
      "b/two.js": 'router.post("/b", handler);',
      ".github/workflows/w.yml": "on:\n  push:\n",
    });

    const first = inventory(root).raw;
    const second = inventory(root).raw;

    expect(first).toBe(second);
    expect(first.length).toBeGreaterThan(0);
  });

  test("summarizes counts and ranks files by entry point density", async () => {
    const root = await repositoryWith({
      "server/many.py": [
        '@bp.get("/one")',
        "def one():",
        "    return {}",
        '@bp.get("/two")',
        "def two():",
        "    return {}",
      ].join("\n"),
      "server/few.py": '@bp.get("/three")\ndef three():\n    return {}',
    });

    const summary = summaryOf(root);

    expect(summary.documentType).toBe("codex-security.entry-point-inventory");
    expect(summary.schemaVersion).toBe("1.0");
    expect(summary.entryPointCount).toBe(3);
    expect(summary.truncated).toBe(false);
    expect(summary.byKind).toEqual({ http_route: 3 });
    expect(summary.byFramework).toEqual({ flask: 3 });
    expect(summary.files[0]).toEqual({
      path: "server/many.py",
      entryPointCount: 2,
    });
  });

  test("rejects a scope outside the repository", async () => {
    const root = await repositoryWith({ "a.py": "x = 1" });
    const python = Bun.which("python3") ?? Bun.which("python");
    const result = spawnSync(
      python!,
      ["-I", "-B", SCRIPT, "--repo", root, "--scope", "../..", "--out", "-"],
      { encoding: "utf8" },
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "Scope must be an existing path inside repo",
    );
  });
});
