import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/scan-validator-fixture";
import { runCommand } from "./support/shell";

type Table = Record<string, unknown>;
const directory = realpathSync(mkdtempSync(join(tmpdir(), "scan-validator-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!,
  helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const documents = [
  "scan-manifest.json",
  "findings.json",
  "coverage.json",
  "report.md",
];
const env = { ...process.env, PATH: "", PYTHON: "/missing/python" };
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/scan-validator-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
async function run(requests: Request[]): Promise<Response[]> {
  const child = await runCommand(node, [fixture], {
    cwd: directory,
    input: JSON.stringify(requests),
    timeout: 0,
    env,
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
function cli(command: string, ...args: string[]) {
  return runCommand(node, [helper, command, ...args], {
    cwd: directory,
    timeout: 0,
    env,
    maxBuffer: Infinity,
  });
}
function seed(): string {
  const root = mkdtempSync(join(directory, "scan-"));
  for (const name of documents)
    copyFileSync(
      join(PLUGIN_ROOT, "examples/completed-scan", name),
      join(root, name),
    );
  return root;
}
const load = (root: string, name: string): Table =>
  JSON.parse(readFileSync(join(root, name), "utf8")) as Table;
const digest = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
const snapshot = (root: string) =>
  documents.map((name) => readFileSync(join(root, name)));
function rewrite(root: string, name: string, value: unknown): void {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + "\n");
  writeFileSync(join(root, name), bytes);
  if (name === "scan-manifest.json") return;
  const manifest = load(root, "scan-manifest.json"),
    scan = manifest["scan"] as Table;
  for (const artifact of scan["artifacts"] as Table[])
    if (artifact["path"] === name) artifact["sha256"] = digest(bytes);
  rewrite(root, "scan-manifest.json", manifest);
}
function value(response: Response): Table {
  expect(response.error).toBeUndefined();
  return JSON.parse(response.value!) as Table;
}

test("validates the shipped example and prints a sorted receipt without changing files", async () => {
  const root = seed(),
    before = snapshot(root);
  const result = value((await run([{ operation: "validate", root }]))[0]!);
  expect((result["manifest"] as Table)["scan"]).toEqual(
    load(root, "scan-manifest.json")["scan"],
  );
  expect(result["findings"]).toEqual(load(root, "findings.json"));
  expect(snapshot(root)).toEqual(before);
  const expected = {
    coveragePath: join(root, "coverage.json"),
    findingsPath: join(root, "findings.json"),
    manifestPath: join(root, "scan-manifest.json"),
    reportPath: join(root, "report.md"),
    scanDir: root,
    status: "valid",
  };
  const child = await cli("validate-scan-contract", "--scan-dir", root);
  expect(child.status, child.stderr).toBe(0);
  expect(child.stdout.replaceAll("\r\n", "\n")).toBe(
    JSON.stringify(expected)
      .replaceAll('","', '", "')
      .replaceAll('":"', '": "') + "\n",
  );
  expect(child.stderr).toBe("");
  expect(snapshot(root)).toEqual(before);
  const tracked = await cli(
    "validate-tracking-source",
    join(PLUGIN_ROOT, "examples/completed-scan"),
  );
  expect(tracked.status, tracked.stderr).toBe(0);
  expect(tracked.stdout.replaceAll("\r\n", "\n")).toBe(
    "csf_852f90d6e1177502ff113d4a\n",
  );
});

test("legacy nested evidence references are validated without changing the original findings", async () => {
  const root = seed(),
    findings = load(root, "findings.json");
  (findings["findings"] as Table[])[0]!["attackPath"] = {
    dataFlow: { evidenceRefs: ["legacy-missing-evidence"] },
  };
  rewrite(root, "findings.json", findings);
  const before = snapshot(root),
    result = value((await run([{ operation: "validate", root }]))[0]!);
  expect(result["findings"]).toEqual(findings);
  expect(snapshot(root)).toEqual(before);
});

test("accepts a canonical document beyond the previous 16 MiB limit", async () => {
  const root = seed(),
    manifest = load(root, "scan-manifest.json");
  manifest["metadata"] = "x".repeat(16 * 1024 * 1024);
  rewrite(root, "scan-manifest.json", manifest);
  const before = digest(readFileSync(join(root, "scan-manifest.json")));
  expect(
    value((await run([{ operation: "summary", root }]))[0]!)["metadataLength"],
  ).toBe(16 * 1024 * 1024);
  expect(digest(readFileSync(join(root, "scan-manifest.json")))).toBe(before);
});

test("rejects unsafe sealed extensions while retaining the scan bytes", async () => {
  for (const [unsafe, reason] of [
    [1e20, "unsafe integer-valued JSON numbers"],
    ["bad-\ud800", "well-formed Unicode"],
  ] as const) {
    const root = seed(),
      findings = load(root, "findings.json");
    (findings["findings"] as Table[])[0]!["extensions"] = { unsafe };
    rewrite(root, "findings.json", findings);
    const before = snapshot(root),
      response = (await run([{ operation: "validate", root }]))[0]!;
    expect(response.kind).toBe("ContractError");
    expect(response.error).toContain(reason);
    expect(snapshot(root)).toEqual(before);
  }
});

test("manifest checks precede artifact reads, and the report is required after canonical validation", async () => {
  const root = seed(),
    manifest = load(root, "scan-manifest.json"),
    scan = manifest["scan"] as Table;
  delete scan["sealedAt"];
  delete scan["artifacts"];
  rewrite(root, "scan-manifest.json", manifest);
  rmSync(join(root, "findings.json"));
  expect((await run([{ operation: "validate", root }]))[0]!.error).toBe(
    "manifest.scan.sealedAt: expected a non-empty string",
  );
  const missingReport = seed();
  rmSync(join(missingReport, "report.md"));
  expect(
    (await run([{ operation: "validate", root: missingReport }]))[0]!.error,
  ).toContain("report.md");
  const findings = load(missingReport, "findings.json");
  (findings["findings"] as Table[])[0]!["findingId"] = "wrong";
  rewrite(missingReport, "findings.json", findings);
  expect(
    (await run([{ operation: "validate", root: missingReport }]))[0]!.error,
  ).toContain("findingId");
});

test("tracking rejects changed seals, invalid JSON, invalid coverage and noncanonical records", async () => {
  const tampered = seed();
  writeFileSync(
    join(tampered, "findings.json"),
    readFileSync(join(tampered, "findings.json"), "utf8") + "\n",
  );
  expect(
    (await run([{ operation: "tracking", root: tampered }]))[0]!.error,
  ).toContain("sealed artifact changed");
  const invalidJson = seed(),
    manifest = load(invalidJson, "scan-manifest.json"),
    bytes = Buffer.from("{invalid json\n");
  writeFileSync(join(invalidJson, "findings.json"), bytes);
  for (const artifact of (manifest["scan"] as Table)["artifacts"] as Table[])
    if (artifact["path"] === "findings.json")
      artifact["sha256"] = digest(bytes);
  rewrite(invalidJson, "scan-manifest.json", manifest);
  expect(
    (await run([{ operation: "tracking", root: invalidJson }]))[0]!.error,
  ).toContain("findings.json: invalid JSON");
  const invalidCoverage = seed(),
    coverage = load(invalidCoverage, "coverage.json");
  coverage["scanId"] = "wrong-scan-id";
  rewrite(invalidCoverage, "coverage.json", coverage);
  expect(
    (await run([{ operation: "tracking", root: invalidCoverage }]))[0]!.error,
  ).toBe("coverage.scanId: must match manifest scan id");
  const noncanonical = seed(),
    badManifest = load(noncanonical, "scan-manifest.json");
  ((badManifest["scan"] as Table)["artifacts"] as Table[])[0]!["path"] =
    "./findings.json";
  rewrite(noncanonical, "scan-manifest.json", badManifest);
  const child = await cli("validate-tracking-source", noncanonical);
  expect(child.status).toBe(2);
  expect(child.stdout).toBe("");
  expect(child.stderr).toContain("tracking source preflight failed:");
  expect(child.stderr).not.toContain("Traceback");
  const reportOnly = mkdtempSync(join(directory, "report-only-"));
  writeFileSync(join(reportOnly, "report.html"), "<html></html>");
  expect(
    (await run([{ operation: "tracking", root: reportOnly }]))[0]!.error,
  ).toContain("scan-manifest.json");
});

test("tracking lists a full batch and selects exactly one canonical id or fingerprint", async () => {
  const root = seed(),
    manifest = load(root, "scan-manifest.json"),
    findings = load(root, "findings.json");
  const rows = findings["findings"] as Table[],
    template = rows[0]!;
  for (let index = 1; index < 25; index++) {
    const sibling = structuredClone(template);
    (sibling["identity"] as Table)["instance"] = `archive-write-${index}`;
    for (const field of ["findingId", "occurrenceId", "fingerprints"])
      delete sibling[field];
    rows.push(sibling);
  }
  const identified = value(
    (
      await run([
        {
          operation: "identities",
          root,
          source: JSON.stringify({ manifest, findings }),
        },
      ])
    )[0]!,
  );
  rewrite(root, "findings.json", identified["findings"]);
  const all = JSON.parse(
    (await run([{ operation: "tracking", root }]))[0]!.value!,
  ) as Table[];
  const ids = all.map((finding) => finding["findingId"] as string),
    last = all.at(-1)!;
  expect(ids).toHaveLength(25);
  expect(new Set(ids).size).toBe(25);
  const selected = await run([
    { operation: "tracking", root, selector: { findingId: ids.at(-1)! } },
    {
      operation: "tracking",
      root,
      selector: {
        fingerprint: (last["fingerprints"] as Table)["primary"] as string,
      },
    },
    { operation: "tracking", root, selector: { findingId: "missing" } },
    {
      operation: "tracking",
      root: join(directory, "missing"),
      selector: { findingId: "one", fingerprint: "two" },
    },
  ]);
  expect(JSON.parse(selected[0]!.value!)).toEqual([last]);
  expect(selected[1]).toEqual(selected[0]);
  expect(selected[2]!.error).toBe(
    "the selector did not resolve exactly one finding",
  );
  expect(selected[3]!.error).toBe(
    "use only one of --finding-id or --fingerprint",
  );
  const listed = await cli("validate-tracking-source", root);
  expect(listed.status, listed.stderr).toBe(0);
  expect(listed.stdout.replaceAll("\r\n", "\n")).toBe(ids.join("\n") + "\n");
  const child = await cli(
    "validate-tracking-source",
    root,
    "--finding-id",
    ids.at(-1)!,
  );
  expect(child.status, child.stderr).toBe(0);
  expect(child.stdout.replaceAll("\r\n", "\n")).toBe(ids.at(-1)! + "\n");
  expect(child.stderr).toBe("");
});

test("the finalizer and validator commands run consecutively without Python", async () => {
  const root = seed();
  rmSync(join(root, "report.md"));
  const finalized = await cli("finalize-scan-contract", "--scan-dir", root);
  expect(finalized.status, finalized.stderr).toBe(0);
  expect(finalized.stderr).toBe("");
  const child = await cli("validate-scan-contract", "--scan-dir", root);
  expect(child.status, child.stderr).toBe(0);
  expect(JSON.parse(child.stdout)["status"]).toBe("valid");
  expect(child.stderr).toBe("");
});

test("helper arguments retain abbreviations, duplicate values, end markers and selector conflicts", async () => {
  const root = seed(),
    id = "csf_852f90d6e1177502ff113d4a";
  const finding = (load(root, "findings.json")["findings"] as Table[])[0]!;
  const fingerprint = (finding["fingerprints"] as Table)["primary"] as string;
  for (const args of [
    [root, "--finding-id", id],
    ["--fingerp", "missing", "--fingerp", fingerprint, root],
    ["--", root],
  ]) {
    const child = await cli("validate-tracking-source", ...args);
    expect(child.status, child.stderr).toBe(0);
    expect(child.stdout.replaceAll("\r\n", "\n")).toBe(id + "\n");
  }
  expect(
    (await cli("validate-scan-contract", "--scan", "missing", "--scan", root))
      .status,
  ).toBe(0);
  const conflict = await cli(
    "validate-tracking-source",
    root,
    "--finding-id",
    "one",
    "--fingerprint",
    "two",
    "--help",
  );
  expect(conflict.status).toBe(2);
  expect(conflict.stderr).toContain(
    "argument --fingerprint: not allowed with argument --finding-id",
  );
  expect(
    (await cli("validate-tracking-source", "--help", "--finding-id")).status,
  ).toBe(0);
  expect(
    (await cli("validate-tracking-source", "--finding-id")).stderr,
  ).toContain("argument --finding-id: expected one argument");
  expect((await cli("validate-tracking-source", "--unknown")).stderr).toContain(
    "the following arguments are required: scan_dir",
  );
  expect((await cli("validate-scan-contract")).stderr).toContain(
    "the following arguments are required: --scan-dir",
  );
  expect(
    (await cli("validate-scan-contract", "--scan-dir", "-h x")).stderr,
  ).toContain("argument --scan-dir: expected one argument");
  for (const command of [
    "validate-scan-contract",
    "validate-tracking-source",
  ]) {
    const child = await cli(command, "--help");
    expect(child.status).toBe(0);
    expect(child.stdout).toContain(`--helper ${command}`);
    expect(child.stderr).toBe("");
  }
});

test.skipIf(process.platform === "win32")(
  "scan aliases resolve before validation and the launcher preserves home expansion",
  async () => {
    const root = seed(),
      alias = join(directory, "scan-alias");
    symlinkSync(root, alias, "dir");
    expect(
      value((await run([{ operation: "receipt", root: alias }]))[0]!)[
        "scanDir"
      ],
    ).toBe(root);
    const home = join(directory, "home");
    mkdirSync(home);
    symlinkSync(root, join(home, "scan"), "dir");
    const child = await runCommand(
      join(PLUGIN_ROOT, "scripts/launch_codex_security_mcp"),
      ["--helper", "validate-scan-contract", "--scan-dir", "~/scan"],
      {
        cwd: directory,
        env: { ...env, HOME: home, CODEX_MCP_NODE_PATH: node },
        timeout: 0,
      },
    );
    expect(child.status, child.stderr).toBe(0);
    expect(JSON.parse(child.stdout)["scanDir"]).toBe(root);
    expect(child.stderr).toBe("");
    mkdirSync(join(directory, "relative-target"));
    symlinkSync("relative-target/missing", join(directory, "relative-link"));
    symlinkSync(
      join(directory, "relative-target/missing"),
      join(directory, "absolute-link"),
    );
    expect(
      (await cli("validate-scan-contract", "--scan-dir", "relative-link"))
        .stderr,
    ).toBe(
      "scan contract validation failed: [Errno 2] No such file or directory: 'relative-target/missing'\n",
    );
    expect(
      (await cli("validate-scan-contract", "--scan-dir", "absolute-link"))
        .stderr,
    ).toBe(
      `scan contract validation failed: [Errno 2] No such file or directory: '${join(directory, "relative-target/missing")}'\n`,
    );
  },
);
