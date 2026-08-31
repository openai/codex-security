import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { afterEach, expect, test } from "bun:test";
import type { ScanOptions } from "../src/api.js";
import { main } from "../src/cli.js";
import {
  normalizeComponentPlan,
  planComponents,
  type ComponentPlan,
  type ComponentPlanningOptions,
} from "../src/component-plan.js";
import {
  runComponentScans,
  type ComponentScanEvent,
  type ComponentScanOptions,
} from "../src/component-scan.js";
import type { Finding, SeverityLevel } from "../src/models.js";
import { ScanResult } from "../src/result.js";
import { normalizeTarget } from "../src/targets.js";
import {
  matchScanFindings,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";
import {
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
  FakeSignals,
} from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporary: string[] = [];
const components: ComponentPlan["components"] = [
  { name: "API", paths: ["apps/api"] },
  { name: "Web", paths: ["apps/web"] },
  { name: "Shared", paths: ["shared"] },
];
const noMatches: ScanComparisonResult = { matches: [], uncertain: [] };
type Fixture = Awaited<ReturnType<typeof fixture>>;

afterEach(async () => {
  await Promise.all(
    temporary
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "component-scan-")));
  temporary.push(root);
  const repository = join(root, "repo");
  for (const file of [
    "package.json",
    "apps/api/app.ts",
    "apps/web/app.ts",
    "shared/util.ts",
  ]) {
    await mkdir(dirname(join(repository, file)), { recursive: true });
    await writeFile(join(repository, file), "{}\n");
  }
  return { root, repository, outputDir: join(root, "results") };
}

async function json(path: string) {
  return JSON.parse(await readFile(path, "utf8"));
}

function finding(
  id: string,
  level: SeverityLevel = "high",
  fingerprint = id,
): Finding {
  return {
    findingId: fingerprint,
    occurrenceId: id,
    fingerprints: { algorithm: "codex-security/v1", primary: fingerprint },
    title: id,
    severity: { level },
  } as Finding;
}

async function completed(
  options: ScanOptions,
  findings = [finding(String(options.target))],
  coverage: "complete" | "partial" = "complete",
) {
  const original = fakeResult([], coverage);
  const scanId = String(options.target);
  original.manifest.scan.id = scanId;
  original.findings.scanId = scanId;
  original.findings.findings = findings;
  original.coverage.scanId = scanId;
  const result = new ScanResult({
    ...original,
    scanDir: options.outputDir!,
    threadId: scanId,
    sarifPath: null,
  });
  await mkdir(result.scanDir, { recursive: true });
  for (const [name, value] of Object.entries({
    "scan-manifest.json": result.manifest,
    "findings.json": result.findings,
    "coverage.json": result.coverage,
    "report.md": "Original report",
  })) {
    await writeFile(
      join(result.scanDir, name),
      typeof value === "string" ? value : JSON.stringify(value),
    );
  }
  return result;
}

function client(
  run: (
    repository: string,
    options: ScanOptions,
  ) => Promise<ScanResult> = async (_repository, options) => completed(options),
  close = async () => {},
) {
  return () => ({
    run: async (repository: string, options: ScanOptions = {}) =>
      run(repository, options),
    preflight: async (repository: string) => fakePreflight(repository),
    close,
  });
}

function scan(paths: Fixture, options: Partial<ComponentScanOptions> = {}) {
  return runComponentScans({
    ...paths,
    components,
    workers: 1,
    createSecurity: client(),
    matchFindings: async () => noMatches,
    ...options,
  });
}

async function cli(
  paths: Fixture,
  args: string[],
  overrides: Partial<ReturnType<typeof dependencies>> = {},
) {
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    [
      "scan-components",
      paths.repository,
      "--output-dir",
      paths.outputDir,
      ...args,
      "--json",
    ],
    stdout.stream,
    stderr.stream,
    { ...dependencies({ currentDirectory: paths.root }), ...overrides },
  );
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}

function fakeCodex(
  response: () => unknown,
): NonNullable<ComponentPlanningOptions["codex"]> {
  return {
    startThread: () => ({
      run: async () => ({ finalResponse: JSON.stringify(await response()) }),
    }),
  };
}

async function scopedInventory(paths: Fixture, scope: string) {
  const python =
    process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const scopesFile = join(paths.root, "scopes.json");
  const output = join(paths.root, "scoped-source-input.jsonl");
  await writeFile(scopesFile, JSON.stringify([scope]));
  const stdout = execFileSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      [
        "import json, sys",
        "from argparse import Namespace",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_target as target",
        "from generate_rank_input import make_repo_scope_input",
        "queries = []",
        "git_bytes = target.git_bytes",
        "def record_query(repository, *args, **kwargs):",
        "    data = git_bytes(repository, *args, **kwargs)",
        "    if 'ls-files' in args:",
        "        queries.append({'pathspec': args[-1], 'count': len([path for path in (data or b'').split(b'\\0') if path])})",
        "    return data",
        "target.git_bytes = record_query",
        "repo, scope, scopes, output = sys.argv[2:]",
        "make_repo_scope_input(Namespace(repo=repo, scopes_file=scopes, out=output))",
        "rows = [json.loads(line)['path'] for line in Path(output).read_text().splitlines()]",
        "count = target.directory_snapshot_regular_file_count((Path(repo) / scope).resolve())",
        "print(json.dumps({'paths': rows, 'count': count, 'queries': queries}))",
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      paths.repository,
      scope,
      scopesFile,
      output,
    ],
    { encoding: "utf8", stdio: "pipe" },
  );
  return JSON.parse(stdout.trim().split("\n").at(-1)!) as {
    paths: string[];
    count: number;
    queries: Array<{ pathspec: string; count: number }>;
  };
}

function matcher(
  response: (
    input: ScanComparisonInput,
    options: ScanComparisonOptions,
  ) => unknown,
): typeof matchScanFindings {
  return async (input, options = {}) =>
    matchScanFindings(input, {
      ...options,
      codex: fakeCodex(() => response(input, options)),
    });
}

function match(
  beforeOccurrenceIds: string[],
  afterOccurrenceIds: string[],
): ScanComparisonResult["matches"][number] {
  return {
    beforeOccurrenceIds,
    afterOccurrenceIds,
    confidence: "high",
    reason: "Same root cause and remediation.",
  };
}

function uncertain(
  beforeOccurrenceId: string,
  afterOccurrenceId: string,
): ScanComparisonResult["uncertain"][number] {
  return {
    beforeOccurrenceId,
    afterOccurrenceId,
    reason: "Possibly independent controls.",
  };
}

test("bounds standard scans, continues after failure, and preserves partial results", async () => {
  const paths = await fixture();
  let active = 0,
    peak = 0,
    closed = 0;
  let unblock!: () => void;
  const bothStarted = new Promise<void>((resolve) => {
    unblock = resolve;
  });
  const seen: ScanOptions[] = [];
  const summary = await scan(paths, {
    workers: 2,
    scanOptions: {
      auth: "chatgpt",
      scanPrompt: "Check access controls",
      maxCostUsd: 3,
    },
    onProgress() {
      throw new Error("optional observer");
    },
    createSecurity: client(
      async (repository, options) => {
        expect(repository).toBe(paths.repository);
        seen.push(options);
        peak = Math.max(peak, ++active);
        if (active === 2) unblock();
        await bothStarted;
        try {
          expect(options).toMatchObject({
            mode: "standard",
            auth: "chatgpt",
            scanPrompt: "Check access controls",
            maxCostUsd: 3,
          });
          if (String(options.target) === "apps/api")
            throw new Error("Authorization: Bearer SYNTHETIC_SECRET_123");
          return await completed(
            options,
            undefined,
            String(options.target) === "apps/web" ? "partial" : "complete",
          );
        } finally {
          active--;
        }
      },
      async () => {
        closed++;
      },
    ),
  });
  expect([peak, closed]).toEqual([2, 2]);
  expect(seen.map(({ target }) => target)).toEqual(
    components.map(({ paths }) => paths),
  );
  expect(summary).toMatchObject({
    total: 3,
    completed: 1,
    incomplete: 1,
    failed: 1,
  });
  const saved = await json(summary.findingsPath!);
  expect(saved.documentType).toBe("codex-security.component-findings");
  expect(saved.findings).toHaveLength(2);
  expect(
    saved.findings.flatMap(({ sources }: { sources: { scanId: string }[] }) =>
      sources.map(({ scanId }) => scanId),
    ),
  ).toEqual(["apps/web", "shared"]);
  expect(await json(summary.summaryPath!)).toMatchObject({
    completeness: "partial",
    findingCount: 2,
  });
  expect(await json(summary.retryPlanPath!)).toEqual({
    components: components.slice(0, 2),
  });
  expect(await readFile(summary.summaryPath!, "utf8")).not.toContain(
    "SYNTHETIC_SECRET_123",
  );
  expect(
    await readFile(join(paths.outputDir, "component-2", "report.md"), "utf8"),
  ).toBe("Original report");
  expect(await readFile(summary.reportPath!, "utf8")).toContain(
    "./component-2/report.md",
  );
});

test("forwards scan events with their component identity without letting observers stop scans", async () => {
  const paths = await fixture();
  const events: ComponentScanEvent[] = [];
  let planned = false;
  const summary = await scan(paths, {
    workers: 2,
    onPlan(receipts) {
      expect(receipts.map(({ status }) => status)).toEqual([
        "pending",
        "pending",
        "pending",
      ]);
      for (const receipt of receipts) receipt.paths.splice(0);
      planned = true;
      throw new Error("optional plan observer");
    },
    onScanEvent(event) {
      events.push(event);
      throw new Error("optional event observer");
    },
    onProgress(receipt) {
      receipt.paths[0] = "changed-by-observer";
    },
    createSecurity: client(async (_repository, options) => {
      expect(planned).toBe(true);
      const target = String(options.target);
      options.onProgress?.({
        phase: "discovery",
        filesCompleted: 1,
        filesTotal: 2,
      });
      options.onActivity?.({
        id: "same-id",
        kind: "message",
        status: "completed",
        description: target,
        paths: [],
      });
      options.onSessionEvent?.({
        threadId: target,
        parentThreadId: null,
        event: {},
      });
      options.onCost?.(fakeResult([], "complete", { input_tokens: 100 }).cost!);
      options.onWorkerStatus?.({
        kind: "dispatch",
        phase: "validation",
        planned: 1,
        started: 1,
      });
      options.onWarning?.("synthetic warning");
      return completed(options);
    }),
  });
  expect(summary).toMatchObject({
    completed: 3,
    findingCount: 3,
    sourceFindingCount: 3,
  });
  for (const [index, component] of components.entries()) {
    const received = events.filter(
      ({ componentId }) => componentId === `component-${index + 1}`,
    );
    expect(received.map(({ type }) => type)).toEqual([
      "progress",
      "activity",
      "session",
      "cost",
      "workers",
      "warning",
    ]);
    expect(received[1]).toMatchObject({
      value: { description: component.paths.join(",") },
    });
  }
});

test.each(["dashboard", "headless", "ci"])(
  "CLI component presentation: %s",
  async (presentation) => {
    const paths = await fixture();
    const stdout = capture();
    const stderr = capture(true);
    const signals = new FakeSignals();
    const code = await main(
      [
        "scan-components",
        paths.repository,
        "--component",
        "apps/api",
        "--output-dir",
        paths.outputDir,
        ...(presentation === "headless" ? ["--headless"] : []),
        "--json",
      ],
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({
          currentDirectory: paths.root,
          signals,
          environment:
            presentation === "ci" ? { CI: "true" } : { NO_COLOR: "1" },
        }),
        createSecurity: client(async (_repository, options) => {
          expect(typeof options.onProgress).toBe(
            presentation === "dashboard" ? "function" : "undefined",
          );
          options.onProgress?.({
            phase: "validation",
            filesCompleted: 2,
            filesTotal: 2,
          });
          return completed(options);
        }),
      },
    );
    expect(code).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      completed: 1,
      findingCount: 1,
    });
    expect(stderr.text().includes("\u001B[?1049h")).toBe(
      presentation === "dashboard",
    );
    expect(stderr.text()).toContain("Report:");
    if (presentation === "dashboard") {
      expect(stderr.text()).toContain("validating findings");
      expect(stderr.text().indexOf("\u001B[?1049l")).toBeLessThan(
        stderr.text().indexOf("Component scans:"),
      );
    } else expect(stderr.text()).toContain("apps/api completed");
    expect(
      [...signals.listeners.values()].every(
        (listeners) => listeners.size === 0,
      ),
    ).toBe(true);
  },
);

test("CLI restores the dashboard and reports saved partial results on cancellation", async () => {
  const paths = await fixture();
  const stdout = capture();
  const stderr = capture(true);
  const signals = new FakeSignals();
  const code = await main(
    [
      "scan-components",
      paths.repository,
      "--component",
      "apps/api",
      "--component",
      "apps/web",
      "--workers",
      "1",
      "--output-dir",
      paths.outputDir,
      "--json",
    ],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ currentDirectory: paths.root, signals }),
      createSecurity: client(async (_repository, options) => {
        const result = await completed(options);
        signals.emit("SIGINT");
        return result;
      }),
    },
  );
  expect(code).toBe(130);
  expect(await json(join(paths.outputDir, "retry-components.json"))).toEqual({
    components: [{ name: "apps/web", paths: ["apps/web"] }],
  });
  expect(stderr.text()).toContain("1 complete, 0 incomplete, 1 failed");
  expect(stderr.text()).toContain("Retry with --components-file");
  expect(stderr.text().indexOf("\u001B[?1049l")).toBeLessThan(
    stderr.text().indexOf("Component scans:"),
  );
  expect(
    [...signals.listeners.values()].every((listeners) => listeners.size === 0),
  ).toBe(true);
});

test("merges confirmed root causes with complete evidence and the highest severity", async () => {
  const paths = await fixture();
  const config = {
    codexOverrides: {
      model: "synthetic-model",
      model_provider: "synthetic-provider",
      model_reasoning_effort: "high",
    },
  };
  const inputs: ScanComparisonInput[] = [];
  const batches = [
    [finding("a1"), finding("a2"), finding("u1")],
    [finding("b1"), finding("b2", "critical"), finding("u2")],
    [finding("c1"), finding("c2")],
  ];
  let batch = 0,
    started = 0;
  const summary = await scan(paths, {
    config,
    onDeduplicationStarted() {
      started++;
      throw new Error("optional observer");
    },
    createSecurity: client(async (_repository, options) =>
      completed(options, batches[batch++]),
    ),
    matchFindings: matcher((input, options) => {
      inputs.push(input);
      expect(options).toMatchObject({
        config,
        allowHistoricalUncertainty: true,
      });
      return inputs.length === 1
        ? {
            matches: [match(["a1", "a2"], ["b1", "b2"])],
            uncertain: [uncertain("u1", "u2")],
          }
        : {
            matches: [match(["a1", "b1"], ["c1"]), match(["u1", "u2"], ["c2"])],
            uncertain: [],
          };
    }),
  });
  expect(started).toBe(1);
  expect(
    inputs.map(({ before, after }) => [before.length, after.length]),
  ).toEqual([
    [3, 3],
    [6, 2],
  ]);
  expect(summary.deduplication).toEqual({
    status: "completed",
    confirmedGroups: 3,
    uncertainPairs: 0,
  });
  const saved = await json(summary.findingsPath!);
  expect(
    saved.findings.map(({ sources }: { sources: unknown[] }) => sources.length),
  ).toEqual([5, 3]);
  expect(saved.findings[0].finding).toMatchObject({
    occurrenceId: "b2",
    severity: { level: "critical" },
  });
  expect(saved.deduplication.matches).toHaveLength(3);
  expect(saved.deduplication.uncertain).toEqual([]);
  expect(
    (await json(join(paths.outputDir, "component-1", "findings.json")))
      .findings,
  ).toHaveLength(3);
});

test("keeps uncertain findings separate even when their fingerprints match", async () => {
  const paths = await fixture();
  const summary = await scan(paths, {
    components: components.slice(0, 2),
    createSecurity: client(async (_repository, options) =>
      completed(options, [finding(String(options.target), "high", "same")]),
    ),
    matchFindings: matcher(({ before, after }) => ({
      matches: [],
      uncertain: [uncertain(before[0]!.occurrenceId, after[0]!.occurrenceId)],
    })),
  });
  const saved = await json(summary.findingsPath!);
  expect(saved.findings).toHaveLength(2);
  expect(saved.deduplication.uncertain).toHaveLength(1);
});

test("retains earlier confirmed matches if later matching fails", async () => {
  const paths = await fixture();
  let calls = 0;
  const summary = await scan(paths, {
    matchFindings: matcher(({ before, after }) => {
      if (++calls === 2) throw new Error("Matching unavailable.");
      return {
        matches: [match([before[0]!.occurrenceId], [after[0]!.occurrenceId])],
        uncertain: [],
      };
    }),
  });
  expect(summary).toMatchObject({
    completed: 3,
    failed: 0,
    deduplication: { status: "incomplete", confirmedGroups: 1 },
  });
  expect(
    (await json(summary.findingsPath!)).findings.map(
      ({ sources }: { sources: unknown[] }) => sources.length,
    ),
  ).toEqual([2, 1]);
});

test.each([0, 1])(
  "skips matching with %i populated components",
  async (populated) => {
    const paths = await fixture();
    let calls = 0;
    const summary = await scan(paths, {
      createSecurity: client(async (_repository, options) =>
        completed(
          options,
          populated && String(options.target) === "apps/web"
            ? [finding("one")]
            : [],
        ),
      ),
      matchFindings: async () => {
        calls++;
        throw new Error("unexpected model call");
      },
    });
    expect(calls).toBe(0);
    expect(summary.deduplication).toEqual({
      status: "completed",
      confirmedGroups: 0,
      uncertainPairs: 0,
    });
  },
);

test.each(["scan", "matching"])(
  "preserves completed results when canceled during %s",
  async (phase) => {
    const paths = await fixture();
    const controller = new AbortController();
    let runs = 0;
    await expect(
      scan(paths, {
        signal: controller.signal,
        createSecurity: client(async (_repository, options) => {
          runs++;
          const result = await completed(options);
          if (phase === "scan") controller.abort();
          return result;
        }),
        matchFindings: async (_input, options) => {
          controller.abort();
          options?.signal?.throwIfAborted();
          return noMatches;
        },
      }),
    ).rejects.toThrow();
    const finished = phase === "scan" ? 1 : 3;
    expect(runs).toBe(finished);
    expect(await json(join(paths.outputDir, "summary.json"))).toMatchObject({
      completed: finished,
      failed: 3 - finished,
      completeness: "partial",
      deduplication: { status: "incomplete" },
    });
    expect(
      (await json(join(paths.outputDir, "findings.json"))).findings,
    ).toHaveLength(finished);
  },
);

test("rejects escaped component paths and output inside the enclosing worktree", async () => {
  const paths = await fixture();
  let runs = 0;
  await expect(
    scan(paths, {
      components: [...components, { name: "outside", paths: ["../"] }],
      createSecurity: client(async () => {
        runs++;
        throw new Error("unexpected");
      }),
    }),
  ).rejects.toThrow("outside the repository");
  await symlink(
    paths.root,
    join(paths.repository, "outside"),
    process.platform === "win32" ? "junction" : "dir",
  );
  await expect(
    normalizeComponentPlan(paths.repository, {
      components: [{ name: "link", paths: ["outside"] }],
    }),
  ).rejects.toThrow("outside the repository");
  expect(runs).toBe(0);
  execFileSync("git", ["-C", paths.repository, "init", "-q"]);
  await expect(
    scan(paths, {
      repository: join(paths.repository, "apps"),
      outputDir: join(paths.repository, "results"),
      components: [{ name: "API", paths: ["api"] }],
    }),
  ).rejects.toThrow();
});

test("plans from a Git inventory without tools or ignored files", async () => {
  const paths = await fixture();
  execFileSync("git", ["-C", paths.repository, "init", "-q"]);
  await writeFile(join(paths.repository, ".gitignore"), "ignored/\n");
  await mkdir(join(paths.repository, "ignored"));
  await writeFile(join(paths.repository, "ignored", "secret.txt"), "synthetic");
  const plan = await planComponents(paths.repository, {
    codex: {
      startThread(options) {
        expect(options).toMatchObject({
          threadSource: "security_scan",
          sandboxMode: "read-only",
          approvalPolicy: "never",
          networkAccessEnabled: false,
        });
        return {
          async run(prompt, options) {
            expect(prompt).toContain("apps/api");
            expect(prompt).not.toContain("secret.txt");
            expect(options.outputSchema).toBeDefined();
            return {
              finalResponse: JSON.stringify({ components: [components[0]] }),
            };
          },
        };
      },
    },
  });
  expect(plan.components).toEqual([
    components[0]!,
    {
      name: "Other files",
      paths: [".gitignore", "apps/web", "package.json", "shared"],
    },
  ]);
  await mkdir(join(paths.repository, "~"));
  await writeFile(join(paths.repository, "~", "app.ts"), "export {};\n");
  const wholeRepository = {
    components: [{ name: "Repository", paths: ["."] }],
  };
  expect(
    await planComponents(paths.repository, {
      codex: fakeCodex(() => wholeRepository),
    }),
  ).toEqual(wholeRepository);
  for (const path of ["ignored", "ignored/secret.txt"]) {
    const proposed = { components: [{ name: "Ignored", paths: [path] }] };
    await expect(
      planComponents(paths.repository, { codex: fakeCodex(() => proposed) }),
    ).rejects.toThrow("file inventory");
    expect(await normalizeComponentPlan(paths.repository, proposed)).toEqual(
      proposed,
    );
  }
});

test("keeps scoped inventories and plans aligned after a case-only Git rename", async () => {
  const paths = await fixture();
  const source = "src";
  const uppercase = source.toUpperCase();
  const git = (...args: string[]) =>
    execFileSync(
      "git",
      [
        "-C",
        paths.repository,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "core.hooksPath=" + join(paths.root, "hooks"),
        ...args,
      ],
      {
        encoding: "utf8",
        stdio: "pipe",
        env: {
          ...process.env,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: join(paths.root, "gitconfig"),
        },
      },
    ).trim();
  await mkdir(join(paths.repository, source, "nested"), { recursive: true });
  await writeFile(join(paths.repository, source, "app.ts"), "export {};\n");
  await writeFile(
    join(paths.repository, source, "nested", "util.ts"),
    "export {};\n",
  );
  await mkdir(join(paths.repository, source, "build"));
  await writeFile(
    join(paths.repository, source, "build", "tracked.ts"),
    "export {};\n",
  );
  await writeFile(join(paths.repository, ".gitignore"), "build/\n");
  git("init", "-q", "-b", "main");
  git("add", ".");
  git("add", "--force", source + "/build/tracked.ts");
  git("commit", "-qm", "Initial fixture");
  const ordinaryPaths = [
    source + "/app.ts",
    source + "/build/tracked.ts",
    source + "/nested/util.ts",
  ];
  expect(await scopedInventory(paths, source)).toEqual({
    paths: ordinaryPaths,
    count: 3,
    queries: [
      { pathspec: ":(icase,literal)" + source, count: 3 },
      { pathspec: ":(icase,literal)" + source, count: 3 },
    ],
  });
  git("switch", "-c", "case-rename");
  git("mv", source, "renaming");
  git("mv", "renaming", uppercase);
  git("commit", "-qm", "Rename source directory");
  await writeFile(
    join(paths.repository, uppercase, "build", "cache.tmp"),
    "ignored build output\n",
  );
  git("switch", "main");
  expect(git("status", "--porcelain")).toBe("");
  expect(
    git("ls-files", "-z", "--", source).split("\0").filter(Boolean),
  ).toEqual(ordinaryPaths);
  const entries = await readdir(paths.repository);
  expect(entries).toContain(uppercase);

  const inventory = async (scope: string) => {
    const { queries, ...selected } = await scopedInventory(paths, scope);
    const pathspec = scope === "." ? "." : ":(icase,literal)" + scope;
    expect(queries.map((query) => query.pathspec)).toEqual([
      pathspec,
      pathspec,
    ]);
    if (scope === ".") {
      selected.paths = (
        await Promise.all(
          selected.paths.map(async (path) =>
            relative(
              paths.repository,
              await realpath(join(paths.repository, path)),
            )
              .split(sep)
              .join("/"),
          ),
        )
      ).sort();
    }
    return selected;
  };

  const target = await normalizeTarget(paths.repository, [source]);
  const scope = target.paths[0]!;
  const expectedInventory = {
    paths: [
      scope + "/app.ts",
      scope + "/build/tracked.ts",
      scope + "/nested/util.ts",
    ],
    count: 3,
  };
  expect(await inventory(scope)).toEqual(expectedInventory);
  await writeFile(
    join(paths.repository, scope, "untracked.ts"),
    "export {};\n",
  );
  const mixedInventory = {
    paths: [...expectedInventory.paths, scope + "/untracked.ts"].sort(),
    count: 4,
  };
  expect(await scopedInventory(paths, scope)).toEqual({
    ...mixedInventory,
    queries: [
      { pathspec: ":(icase,literal)" + scope, count: 4 },
      { pathspec: ":(icase,literal)" + scope, count: 4 },
    ],
  });
  const repositoryInventory = {
    paths: [
      ".gitignore",
      "apps/api/app.ts",
      "apps/web/app.ts",
      "package.json",
      "shared/util.ts",
      ...mixedInventory.paths,
    ].sort(),
    count: 9,
  };
  expect(await inventory(".")).toEqual(repositoryInventory);
  const proposed = { components: [{ name: "Source", paths: [source] }] };
  const other = {
    name: "Other files",
    paths: [".gitignore", "apps", "package.json", "shared"],
  };
  expect(
    await planComponents(paths.repository, {
      codex: fakeCodex(() => proposed),
    }),
  ).toEqual({
    components: [{ name: "Source", paths: [scope] }, other],
  });

  if (entries.includes(source)) {
    await writeFile(
      join(paths.repository, uppercase, "app.ts"),
      "export {};\n",
    );
    expect(await inventory(source)).toEqual(mixedInventory);
    expect(await inventory(uppercase)).toEqual({
      paths: [uppercase + "/app.ts"],
      count: 1,
    });
    expect(await inventory(".")).toEqual({
      paths: [...repositoryInventory.paths, uppercase + "/app.ts"].sort(),
      count: 10,
    });
    const separate = { name: "Separate source", paths: [uppercase] };
    expect(
      await planComponents(paths.repository, {
        codex: fakeCodex(() => ({
          components: [...proposed.components, separate],
        })),
      }),
    ).toEqual({ components: [...proposed.components, separate, other] });
  }
});

test("retains tracked Unicode aliases when scoped Git matching is incomplete", async () => {
  const paths = await fixture();
  const source = "sourcé";
  const uppercase = source.toUpperCase();
  await mkdir(join(paths.repository, source, "build"), { recursive: true });
  await writeFile(join(paths.repository, source, "app.ts"), "export {};\n");
  await writeFile(
    join(paths.repository, source, "build", "tracked.ts"),
    "export {};\n",
  );
  await writeFile(join(paths.repository, ".gitignore"), "build/\n");
  const nonCased = "项目api";
  await mkdir(join(paths.repository, nonCased));
  await writeFile(join(paths.repository, nonCased, "app.ts"), "export {};\n");
  execFileSync("git", ["-C", paths.repository, "init", "-q"]);
  execFileSync("git", ["-C", paths.repository, "add", "--force", "."]);
  expect((await scopedInventory(paths, nonCased)).queries).toEqual([
    { pathspec: ":(icase,literal)" + nonCased, count: 1 },
    { pathspec: ":(icase,literal)" + nonCased, count: 1 },
  ]);
  await rename(
    join(paths.repository, source),
    join(paths.repository, "renaming"),
  );
  await rename(
    join(paths.repository, "renaming"),
    join(paths.repository, uppercase),
  );
  const aliases =
    (await realpath(join(paths.repository, source)).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return null;
        throw error;
      },
    )) !== null;
  await writeFile(
    join(paths.repository, uppercase, "untracked.ts"),
    "export {};\n",
  );
  const selected = [
    uppercase + "/app.ts",
    uppercase + "/untracked.ts",
    ...(aliases ? [uppercase + "/build/tracked.ts"] : []),
  ].sort();
  const inventory = await scopedInventory(paths, uppercase);
  const identities = async (files: string[]) =>
    (
      await Promise.all(
        files.map(async (file) => {
          const { dev, ino } = await stat(join(paths.repository, file), {
            bigint: true,
          });
          return `${dev}:${ino}`;
        }),
      )
    ).sort();
  expect(await identities(inventory.paths)).toEqual(await identities(selected));
  expect(inventory.count).toBe(selected.length);
  expect(inventory.queries.map((query) => query.pathspec)).toEqual([".", "."]);
});

test("plans plain directories and rejects unsafe or overlapping model scopes", async () => {
  const paths = await fixture();
  const proposed = { components: [{ name: "Apps", paths: ["apps"] }] };
  expect(
    (
      await planComponents(paths.repository, {
        codex: fakeCodex(() => proposed),
      })
    ).components,
  ).toEqual([
    ...proposed.components,
    { name: "Other files", paths: ["package.json", "shared"] },
  ]);
  for (const [plan, error] of [
    [
      { components: [{ name: "outside", paths: ["../"] }] },
      "outside the repository",
    ],
    [
      { components: [components[0], ...proposed.components] },
      "overlapping paths",
    ],
  ] as const) {
    await expect(
      planComponents(paths.repository, { codex: fakeCodex(() => plan) }),
    ).rejects.toThrow(error);
  }
});

test.each(["auto", "explicit", "file"])(
  "CLI saves a reusable %s plan without scanning",
  async (selection) => {
    const paths = await fixture();
    const planFile = join(paths.root, "plan.json");
    const selected = components.slice(0, 2);
    await writeFile(planFile, JSON.stringify({ components: selected }));
    const args =
      selection === "auto"
        ? ["--auto"]
        : selection === "file"
          ? ["--components-file", planFile]
          : selected.flatMap(({ paths }) => ["--component", paths[0]!]);
    const result = await cli(paths, [...args, "--plan-only"], {
      planComponents: async () => ({ components: selected }),
      createSecurity: () => {
        throw new Error("unexpected scan");
      },
    });
    expect(result.code).toBe(0);
    expect(await json(join(paths.outputDir, "components.json"))).toEqual({
      components:
        selection === "explicit"
          ? selected.map(({ paths }) => ({ name: paths[0], paths }))
          : selected,
    });
    expect(JSON.parse(result.stdout).planPath).toBe(
      join(paths.outputDir, "components.json"),
    );
  },
);

test.each(["auto", "chatgpt", "api-key"] as const)(
  "CLI uses %s authentication for planning, scans, and matching",
  async (auth) => {
    const paths = await fixture();
    const environment = {
      OPENAI_API_KEY: "synthetic-openai-key",
      CODEX_API_KEY: "synthetic-codex-key",
      CODEX_HOME: join(paths.root, "synthetic-home"),
    };
    const expectedEnvironment =
      auth === "chatgpt" ? { CODEX_HOME: environment.CODEX_HOME } : environment;
    let planned = false,
      matched = false;
    const result = await cli(
      paths,
      ["--auto", ...(auth === "auto" ? [] : ["--auth", auth])],
      {
        ...dependencies({ currentDirectory: paths.root, environment }),
        planComponents: async (_repository, options) => {
          expect(options?.auth).toBe(auth);
          expect(options?.environment).toEqual(expectedEnvironment);
          planned = true;
          return { components: components.slice(0, 2) };
        },
        createSecurity: client(async (_repository, options) => {
          expect(options.auth).toBe(auth);
          return completed(options);
        }),
        matchFindings: async (_input, options) => {
          expect(options?.auth).toBe(auth);
          expect(options?.environment).toEqual(expectedEnvironment);
          matched = true;
          return noMatches;
        },
      },
    );
    expect(result.code).toBe(0);
    expect([planned, matched]).toEqual([true, true]);
    expect(environment.OPENAI_API_KEY).toBe("synthetic-openai-key");
  },
);

test("CLI requires an explicitly selected API key before automatic planning", async () => {
  const paths = await fixture();
  let planned = false;
  const result = await cli(
    paths,
    ["--auto", "--plan-only", "--auth", "api-key"],
    {
      ...dependencies({ currentDirectory: paths.root, environment: {} }),
      planComponents: async () => {
        planned = true;
        return { components };
      },
    },
  );
  expect(result.code).toBe(2);
  expect(result.stderr).toContain("API-key authentication requires");
  expect(planned).toBe(false);
});

test("CLI forwards scan settings and returns incomplete coverage", async () => {
  const paths = await fixture();
  const planFile = join(paths.root, "plan.json");
  await writeFile(planFile, JSON.stringify({ components: [components[0]] }));
  const signals = new FakeSignals();
  let config: unknown;
  let seen: ScanOptions | undefined;
  const result = await cli(
    paths,
    [
      "--components-file",
      planFile,
      "--model",
      "gpt-5.6-terra",
      "--effort",
      "high",
      "--max-cost",
      "2",
    ],
    {
      ...dependencies({ currentDirectory: paths.root, signals }),
      createSecurity: (value) => {
        config = value;
        return client(async (_repository, options) => {
          seen = options;
          return completed(options, [], "partial");
        })();
      },
    },
  );
  expect(result.code).toBe(2);
  expect(config).toMatchObject({
    codexOverrides: { model: "gpt-5.6-terra", model_reasoning_effort: "high" },
  });
  expect(seen).toMatchObject({
    target: ["apps/api"],
    mode: "standard",
    maxCostUsd: 2,
  });
  expect(JSON.parse(result.stdout).incomplete).toBe(1);
  expect(
    [...signals.listeners.values()].every((listeners) => listeners.size === 0),
  ).toBe(true);
});

test.each([false, true])(
  "CLI reports matching completion (failure: %j)",
  async (failMatching) => {
    const paths = await fixture();
    let calls = 0;
    const result = await cli(
      paths,
      [
        "--component",
        "apps/api",
        "--component",
        "apps/web",
        "--model",
        "gpt-5.6-terra",
        "--effort",
        "high",
      ],
      {
        createSecurity: client(),
        matchFindings: async ({ before, after }, options) => {
          calls++;
          expect(options?.config?.codexOverrides).toMatchObject({
            model: "gpt-5.6-terra",
            model_reasoning_effort: "high",
          });
          if (failMatching)
            throw new Error("Authorization: Bearer SYNTHETIC_MATCH_SECRET_123");
          return {
            matches: [
              match([before[0]!.occurrenceId], [after[0]!.occurrenceId]),
            ],
            uncertain: [],
          };
        },
      },
    );
    expect([result.code, calls]).toEqual([failMatching ? 2 : 0, 1]);
    const saved = await readFile(
      join(paths.outputDir, "findings.json"),
      "utf8",
    );
    expect(JSON.parse(saved).findings).toHaveLength(failMatching ? 2 : 1);
    expect(JSON.parse(result.stdout)).toMatchObject({
      completed: 2,
      failed: 0,
      deduplication: { status: failMatching ? "incomplete" : "completed" },
    });
    expect(saved + result.stdout + result.stderr).not.toContain(
      "SYNTHETIC_MATCH_SECRET_123",
    );
  },
);

test("CLI rejects ambiguous component selection", async () => {
  const paths = await fixture();
  for (const selection of [[], ["--auto", "--component", "apps/api"]]) {
    const result = await cli(paths, selection);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain("Choose exactly one");
  }
});
