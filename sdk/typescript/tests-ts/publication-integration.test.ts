import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import * as fileSystem from "node:fs/promises";
import {
  appendFile,
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { NetworkLinearError } from "@linear/sdk";
import { main } from "../src/cli.js";
import {
  linearPublicationArguments,
  prepareScanPublication,
} from "../src/publication.js";
import { recordPublishedIssues } from "../src/publication-store.js";
import type {
  CoverageDocument,
  Finding,
  FindingsDocument,
  ScanManifest,
} from "../src/models.js";
import {
  checkScanPublicationInternal,
  forceTerminatePublicationProcesses,
  publishScanInternal,
  type PublishScanDependencies,
  type PublishScanProgress,
  type PublishScanResult,
  type PublishedScanIssue,
} from "../src/publish.js";
import { runWorkbench } from "../src/runtime.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const SCAN_ID = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_ID = "22222222-2222-4222-8222-222222222222";
const OPTIONS = {
  destination: "linear",
  teamId: "team-example",
  projectId: "project-example",
} as const;

const NODE_EXECUTABLE = execFileSync("node", ["-p", "process.execPath"], {
  encoding: "utf8",
}).trim();
const temporaryDirectories: string[] = [];

interface PublicationFixture {
  python: string;
  scanDirectory: string;
  stateDirectory: string;
  environment: NodeJS.ProcessEnv;
  findings: Finding[];
}

interface PromptFinding {
  findingId: string;
  occurrenceId: string;
  arguments: Record<string, unknown>;
}

interface PublicationPrompt {
  scanId: string;
  destination: { type: "linear"; teamId: string; projectId?: string };
  handoffFile: string;
  publicationFile: string;
  batches: Array<Array<Omit<PromptFinding, "arguments">>>;
}

interface StoredPublication {
  scan_id: string;
  finding_id: string;
  occurrence_id: string;
  destination_type: string;
  team_id: string;
  project_id: string | null;
  external_id: string;
  external_url: string;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function setFindingIdentity(manifest: ScanManifest, finding: Finding): void {
  const fingerprint = `codex-security/v1:sha256:${sha256(
    [
      "codex-security/v1",
      manifest.scan.target.targetId,
      finding.ruleId,
      finding.identity.anchor,
      finding.identity.instance ?? "",
    ].join("\0"),
  )}`;
  finding.fingerprints = {
    algorithm: "codex-security/v1",
    primary: fingerprint,
  };
  finding.findingId = `csf_${sha256(fingerprint).slice(0, 24)}`;
  finding.occurrenceId = `occ_${sha256(
    [manifest.scan.id, fingerprint].join("\0"),
  ).slice(0, 24)}`;
}

async function fixture(count: number): Promise<PublicationFixture> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-publication-integration-")),
  );
  temporaryDirectories.push(root);
  const scanDirectory = join(root, "scan");
  const stateDirectory = join(root, "state");
  const repository = join(root, "repository");
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDirectory, {
    recursive: true,
  });
  await mkdir(stateDirectory, { mode: 0o700 });
  await mkdir(repository, { mode: 0o700 });
  if (process.platform !== "win32") await chmod(scanDirectory, 0o700);

  const manifestPath = join(scanDirectory, "scan-manifest.json");
  const findingsPath = join(scanDirectory, "findings.json");
  const coveragePath = join(scanDirectory, "coverage.json");
  const manifest = JSON.parse(
    await readFile(manifestPath, "utf8"),
  ) as ScanManifest;
  const findings = JSON.parse(
    await readFile(findingsPath, "utf8"),
  ) as FindingsDocument;
  const coverage = JSON.parse(
    await readFile(coveragePath, "utf8"),
  ) as CoverageDocument;
  manifest.scan.id = SCAN_ID;
  findings.scanId = SCAN_ID;
  coverage.scanId = SCAN_ID;
  const example = findings.findings[0]!;
  findings.findings = Array.from({ length: count }, (_, index) => {
    const finding = structuredClone(example);
    finding.identity.anchor = `${example.identity.anchor}-${index + 1}`;
    finding.title = `Synthetic finding ${index + 1}`;
    setFindingIdentity(manifest, finding);
    return finding;
  });
  await writeFile(findingsPath, `${JSON.stringify(findings, null, 2)}\n`);
  await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = sha256(
      await readFile(join(scanDirectory, artifact.path)),
    );
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error("A Python interpreter is required for publication tests.");
  }
  const environment: NodeJS.ProcessEnv = {
    PATH: process.env["PATH"],
    ...(process.env["SystemRoot"] === undefined
      ? {}
      : { SystemRoot: process.env["SystemRoot"] }),
    PYTHON: python,
    CODEX_SECURITY_STATE_DIR: stateDirectory,
  };
  await runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, [
    "database-info",
  ]);

  const seedFile = join(root, "seed.json");
  await writeFile(
    seedFile,
    JSON.stringify({
      scanId: SCAN_ID,
      workspaceId: WORKSPACE_ID,
      scanDirectory,
      repository,
      findings: findings.findings,
    }),
  );
  const seed = [
    "import json, sqlite3, sys",
    "from pathlib import Path",
    "payload = json.loads(Path(sys.argv[2]).read_text())",
    "connection = sqlite3.connect(sys.argv[1])",
    "connection.execute('PRAGMA foreign_keys = ON')",
    "timestamp = '2026-08-15T00:00:00Z'",
    "connection.execute('INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)', (payload['workspaceId'], timestamp, timestamp))",
    "connection.execute('INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (payload['scanId'], payload['workspaceId'], payload['repository'], 'deadbeef', '.', 'standard', payload['scanDirectory'], 'complete', 'reporting', timestamp, timestamp, timestamp))",
    "for finding in payload['findings']:",
    "    connection.execute('INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)', (finding['findingId'], finding['fingerprints']['primary'], finding['ruleId'], finding['identity']['anchor'], timestamp, timestamp))",
    "    connection.execute('INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, confidence, remediation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (finding['occurrenceId'], finding['findingId'], payload['scanId'], finding['title'], finding['summary'], finding['severity']['level'], finding['confidence']['level'], finding['remediation'], timestamp))",
    "connection.commit()",
    "connection.close()",
  ].join("\n");
  execFileSync(
    python,
    [
      "-I",
      "-B",
      "-c",
      seed,
      join(stateDirectory, "workbench.sqlite3"),
      seedFile,
    ],
    { encoding: "utf8", env: environment },
  );

  return {
    python,
    scanDirectory,
    stateDirectory,
    environment,
    findings: findings.findings,
  };
}

async function publicationPayload(
  value: string,
): Promise<
  Omit<PublicationPrompt, "batches"> & { batches: PromptFinding[][] }
> {
  const json = value
    .split("BEGIN UNTRUSTED PUBLICATION DATA\n")[1]!
    .split("\nEND UNTRUSTED PUBLICATION DATA")[0]!;
  const prompt = JSON.parse(json) as PublicationPrompt;
  const publication = JSON.parse(
    await readFile(prompt.publicationFile, "utf8"),
  ) as { batches: PromptFinding[][] };
  return { ...prompt, batches: publication.batches };
}

async function artifactDigests(
  scanDirectory: string,
): Promise<Record<string, string>> {
  const names = (await readdir(scanDirectory)).sort();
  return Object.fromEntries(
    await Promise.all(
      names.map(async (name) => [
        name,
        sha256(await readFile(join(scanDirectory, name))),
      ]),
    ),
  );
}

async function waitForProcessExit(pid: number): Promise<void> {
  if (!Number.isSafeInteger(pid) || pid < 1) {
    throw new Error(`Invalid test process ID: ${pid}`);
  }
  for (let attempt = 0; attempt < 250; attempt += 1) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return;
      throw error;
    }
    if (process.platform === "linux") {
      const state = await readFile(`/proc/${pid}/stat`, "utf8").catch(
        () => undefined,
      );
      if (state === undefined || /\) Z /u.test(state)) return;
    }
    await Bun.sleep(20);
  }
  throw new Error(`Test process ${pid} did not exit.`);
}

async function readProcessId(path: string): Promise<number> {
  return Number(await readFile(path, "utf8").catch(() => "0"));
}

function killTestProcess(pid: number): void {
  if (!Number.isSafeInteger(pid) || Math.abs(pid) < 2) return;
  if (process.platform === "win32" && pid < 0) return;
  try {
    process.kill(pid, "SIGKILL");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
}

function storedPublications(fixture: PublicationFixture): StoredPublication[] {
  const script = [
    "import json, sqlite3, sys",
    "connection = sqlite3.connect(sys.argv[1])",
    "connection.row_factory = sqlite3.Row",
    "rows = connection.execute('SELECT scan_id, finding_id, occurrence_id, destination_type, team_id, project_id, external_id, external_url FROM finding_publications ORDER BY id').fetchall()",
    "print(json.dumps([dict(row) for row in rows]))",
  ].join("\n");
  return JSON.parse(
    execFileSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        script,
        join(fixture.stateDirectory, "workbench.sqlite3"),
      ],
      { encoding: "utf8", env: fixture.environment },
    ),
  ) as StoredPublication[];
}

function receiptPath(fixture: PublicationFixture): string {
  return join(
    fixture.stateDirectory,
    "publications",
    "linear",
    `${sha256(SCAN_ID)}.json`,
  );
}

describe("database-backed Linear publication integration", () => {
  test.each([false, true])(
    "one attempt cannot resolve another attempt's unknown mutation (recover earlier=%j)",
    async (recoverEarlier) => {
      const completed = await fixture(1);
      const handoffs: string[] = [];
      let launches = 0;
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        recordPublishedIssues: async (...args) => {
          if (recoverEarlier && launches === 1)
            throw new Error("Synthetic SQLite interruption");
          return recordPublishedIssues(...args);
        },
        runCodex: async (_command, _args, prompt) => {
          launches++;
          const payload = await publicationPayload(prompt);
          handoffs.push(payload.handoffFile);
          if (launches === (recoverEarlier ? 2 : 1))
            throw new Error("Synthetic unknown remote outcome");
          await writeFile(
            payload.handoffFile,
            JSON.stringify({
              scanId: payload.scanId,
              ...payload.batches.flat()[0]!,
              issueIdentifier: "EXAMPLE-1",
            }) + "\n",
          );
          return { exitCode: 0, stdout: "", stderr: "" };
        },
      };
      await expect(
        publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
      ).rejects.toThrow();
      const second = publishScanInternal(
        completed.scanDirectory,
        OPTIONS,
        runtime,
      );
      if (recoverEarlier) {
        await expect(second).rejects.toThrow("unknown remote outcome");
      } else {
        await second;
      }
      const root = dirname(dirname(handoffs[0]!));
      const entries = await readdir(root, { withFileTypes: true });
      entries.sort(
        (a, b) =>
          handoffs.findIndex((path) => basename(dirname(path)) === a.name) -
          handoffs.findIndex((path) => basename(dirname(path)) === b.name),
      );
      const readDirectory = fileSystem.readdir;
      const listing = spyOn(fileSystem, "readdir").mockImplementation(((
        ...args: Parameters<typeof fileSystem.readdir>
      ) =>
        args[0] === root
          ? Promise.resolve(entries)
          : readDirectory(...args)) as typeof fileSystem.readdir);
      try {
        for (let retry = 0; retry < 2; retry++) {
          await expect(
            publishScanInternal(
              completed.scanDirectory,
              {
                ...OPTIONS,
                skipExisting: true,
              },
              runtime,
            ),
          ).rejects.toThrow("outcome is unknown");
          expect(
            storedPublications(completed).map((row) => row.external_id),
          ).toEqual(["EXAMPLE-1"]);
          expect(launches).toBe(2);
        }
      } finally {
        listing.mockRestore();
      }
    },
  );

  test.each(["completed", "unknown", "missing-receipt"])(
    "a disappearing Linear handoff requires its completed host receipt (%s)",
    async (mode) => {
      const completed = await fixture(1);
      let handoff = "";
      let entered!: () => void;
      const started = new Promise<void>((resolve) => {
        entered = resolve;
      });
      let release!: () => void;
      const response = new Promise<void>((resolve) => {
        release = resolve;
      });
      let launches = 0;
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        runCodex: async (_command, _args, prompt) => {
          launches++;
          const payload = await publicationPayload(prompt);
          handoff = payload.handoffFile;
          entered();
          await response;
          await writeFile(
            handoff,
            JSON.stringify({
              scanId: payload.scanId,
              ...payload.batches.flat()[0]!,
              issueIdentifier: "EXAMPLE-1",
            }) + "\n",
          );
          return { exitCode: 0, stdout: "", stderr: "" };
        },
      };
      const first = publishScanInternal(
        completed.scanDirectory,
        OPTIONS,
        runtime,
      );
      await started;
      const directory = dirname(handoff);
      const root = dirname(directory);
      const hostReceipt = join(dirname(root), `${basename(directory)}.json`);
      const readDirectory = fileSystem.readdir;
      const listing = spyOn(fileSystem, "readdir").mockImplementation((async (
        ...args: Parameters<typeof fileSystem.readdir>
      ) => {
        const entries = await readDirectory(...args);
        if (args[0] === root) {
          if (mode === "completed") {
            release();
            await first;
          } else {
            await rm(directory, { recursive: true });
            if (mode === "missing-receipt") await rm(hostReceipt);
          }
        }
        return entries;
      }) as typeof fileSystem.readdir);
      try {
        const retry = publishScanInternal(
          completed.scanDirectory,
          { ...OPTIONS, skipExisting: true },
          runtime,
        );
        if (mode === "completed") {
          expect((await retry).skipped).toMatchObject([
            { issueIdentifier: "EXAMPLE-1" },
          ]);
          expect(
            JSON.parse(await readFile(hostReceipt, "utf8")).recovered,
          ).toBe(true);
        } else await expect(retry).rejects.toThrow("outcome is unknown");
        expect(launches).toBe(1);
      } finally {
        listing.mockRestore();
        release();
        await first.catch(() => undefined);
      }
    },
  );

  test.each([false, true])(
    "a manual SQLite mapping confirms only one unknown attempt (competing claim=%j)",
    async (competingClaim) => {
      const completed = await fixture(1);
      const prepared = await prepareScanPublication(completed.scanDirectory, {
        ...OPTIONS,
        environment: completed.environment,
      });
      const issue = prepared.issues[0]!;
      const mapping = (issueIdentifier: string) => ({
        findingId: issue.findingId,
        occurrenceId: issue.occurrenceId,
        issueIdentifier,
      });
      const handoffs: string[] = [];
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        runCodex: async (_command, _args, prompt) => {
          handoffs.push((await publicationPayload(prompt)).handoffFile);
          throw new Error("Synthetic unknown remote outcome");
        },
      };
      for (let attempt = 0; attempt < 2; attempt++)
        await expect(
          publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
        ).rejects.toThrow("unknown remote outcome");
      await recordPublishedIssues(
        prepared,
        [mapping("EXAMPLE-1")],
        completed.environment,
      );
      const root = dirname(dirname(handoffs[0]!));
      const entries = await readdir(root, { withFileTypes: true });
      entries.sort(
        (a, b) =>
          handoffs.findIndex((path) => basename(dirname(path)) === a.name) -
          handoffs.findIndex((path) => basename(dirname(path)) === b.name),
      );
      const readDirectory = fileSystem.readdir;
      const listing = spyOn(fileSystem, "readdir").mockImplementation(((
        ...args: Parameters<typeof fileSystem.readdir>
      ) =>
        args[0] === root
          ? Promise.resolve(entries)
          : readDirectory(...args)) as typeof fileSystem.readdir);
      if (competingClaim)
        runtime.recordPublishedIssues = async (...args) => {
          await recordPublishedIssues(
            args[0],
            args[1],
            args[2],
            entries[1]!.name,
          );
          return recordPublishedIssues(...args);
        };
      const completedReceipts = async () =>
        Promise.all(
          handoffs.map(async (file) =>
            JSON.parse(
              await readFile(
                join(dirname(root), `${basename(dirname(file))}.json`),
                "utf8",
              ),
            ),
          ),
        );
      try {
        for (let retry = 0; retry < 2; retry++) {
          await expect(
            publishScanInternal(
              completed.scanDirectory,
              { ...OPTIONS, skipExisting: true },
              runtime,
            ),
          ).rejects.toThrow("outcome is unknown");
          expect(
            (await completedReceipts()).filter((receipt) => receipt.recovered),
          ).toHaveLength(competingClaim ? 0 : 1);
          expect(handoffs).toHaveLength(2);
        }
        delete runtime.recordPublishedIssues;
        await recordPublishedIssues(
          prepared,
          [mapping("EXAMPLE-2")],
          completed.environment,
        );
        await publishScanInternal(
          completed.scanDirectory,
          { ...OPTIONS, skipExisting: true },
          runtime,
        );
        const recovered = await completedReceipts();
        expect(recovered.every((receipt) => receipt.recovered)).toBe(true);
        expect(
          new Set(
            recovered.map(
              (receipt) => receipt.outcome.created[0].issueIdentifier,
            ),
          ).size,
        ).toBe(2);
        expect(handoffs).toHaveLength(2);
      } finally {
        listing.mockRestore();
      }
    },
  );

  test.each(["rejected", "unsubmitted"])(
    "a %s attempt cannot claim a later unknown attempt's manual confirmation",
    async (firstOutcome) => {
      const completed = await fixture(1);
      const prepared = await prepareScanPublication(completed.scanDirectory, {
        ...OPTIONS,
        environment: completed.environment,
      });
      const issue = prepared.issues[0]!;
      const controller = new AbortController();
      const options = {
        ...OPTIONS,
        linearApiKey: "lin_api_SYNTHETIC_CONFIRMATION",
      };
      type LinearClient = ReturnType<
        NonNullable<PublishScanDependencies["linearClient"]>
      >;
      let unknown = false;
      let mutations = 0;
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        linearClient: () =>
          ({
            createIssue: async () => {
              mutations++;
              if (unknown) throw new NetworkLinearError();
              return { success: false, issue: Promise.resolve(undefined) };
            },
          }) as unknown as LinearClient,
      };
      const append = fileSystem.appendFile;
      const journal = spyOn(fileSystem, "appendFile").mockImplementation(
        async (...args) => {
          await append(...args);
          if (
            firstOutcome === "unsubmitted" &&
            basename(String(args[0])) === "started-batches.jsonl"
          )
            controller.abort();
        },
      );
      try {
        await expect(
          publishScanInternal(
            completed.scanDirectory,
            {
              ...options,
              signal: controller.signal,
              onProgress: (event) => {
                if (event.type === "handoff_recorded") controller.abort();
              },
            },
            runtime,
          ),
        ).rejects.toThrow("interrupted");
      } finally {
        journal.mockRestore();
      }
      const root = join(
        completed.stateDirectory,
        "publications",
        "linear",
        "handoffs",
      );
      const first = (await readdir(root))[0]!;
      expect(mutations).toBe(firstOutcome === "rejected" ? 1 : 0);
      unknown = true;
      await expect(
        publishScanInternal(completed.scanDirectory, options, runtime),
      ).rejects.toThrow("could not verify every completed mutation");
      const entries = await readdir(root, { withFileTypes: true });
      entries.sort(
        (a, b) => Number(b.name === first) - Number(a.name === first),
      );
      expect(entries).toHaveLength(2);
      const second = entries[1]!.name;
      await recordPublishedIssues(
        prepared,
        [
          {
            findingId: issue.findingId,
            occurrenceId: issue.occurrenceId,
            issueIdentifier: "EXAMPLE-1",
          },
        ],
        completed.environment,
      );
      const readDirectory = fileSystem.readdir;
      const listing = spyOn(fileSystem, "readdir").mockImplementation(((
        ...args: Parameters<typeof fileSystem.readdir>
      ) =>
        args[0] === root
          ? Promise.resolve(entries)
          : readDirectory(...args)) as typeof fileSystem.readdir);
      try {
        for (let retry = 0; retry < 2; retry++) {
          const result = await publishScanInternal(
            completed.scanDirectory,
            { ...options, skipExisting: true },
            runtime,
          );
          expect(result.created).toEqual([]);
          expect(result.skipped).toMatchObject([
            { issueIdentifier: "EXAMPLE-1" },
          ]);
          expect(mutations).toBe(firstOutcome === "rejected" ? 2 : 1);
        }
        const receipts = await Promise.all(
          [first, second].map(async (attempt) =>
            JSON.parse(
              await readFile(join(dirname(root), `${attempt}.json`), "utf8"),
            ),
          ),
        );
        expect(receipts.every((receipt) => receipt.recovered)).toBe(true);
        expect(receipts[0].outcome.created).toEqual([]);
        expect(receipts[0].outcome.failed).toHaveLength(1);
        expect(receipts[1].outcome.created).toMatchObject([
          { issueIdentifier: "EXAMPLE-1" },
        ]);
        expect(
          JSON.parse(
            execFileSync(
              completed.python,
              [
                "-I",
                "-B",
                "-c",
                "import json, sqlite3, sys; connection = sqlite3.connect(sys.argv[1]); print(json.dumps(connection.execute('SELECT attempt_id FROM finding_publications').fetchall()))",
                join(completed.stateDirectory, "workbench.sqlite3"),
              ],
              { encoding: "utf8", env: completed.environment },
            ),
          ),
        ).toEqual([[second]]);
      } finally {
        listing.mockRestore();
      }
    },
  );

  test("partial handoff cleanup retains the host recovery receipt", async () => {
    const completed = await fixture(1);
    let handoff = "";
    let launches = 0;
    const remove = fileSystem.rm;
    const cleanup = spyOn(fileSystem, "rm").mockImplementation(
      async (path, options) => {
        if (handoff && path === dirname(handoff) && options?.recursive) {
          await remove(handoff);
          throw Object.assign(new Error("Synthetic sharing violation"), {
            code: "EPERM",
          });
        }
        return remove(path, options);
      },
    );
    const runtime: PublishScanDependencies = {
      environment: completed.environment,
      resolveCodex: () => ({ command: "synthetic-codex" }),
      runCodex: async (_command, _args, prompt) => {
        launches++;
        const payload = await publicationPayload(prompt);
        handoff = payload.handoffFile;
        await writeFile(
          handoff,
          JSON.stringify({
            scanId: payload.scanId,
            ...payload.batches.flat()[0]!,
            issueIdentifier: "EXAMPLE-1",
          }) + "\n",
        );
        return { exitCode: 0, stdout: "", stderr: "" };
      },
    };
    try {
      const first = await publishScanInternal(
        completed.scanDirectory,
        OPTIONS,
        runtime,
      );
      expect(first.created).toHaveLength(1);
    } finally {
      cleanup.mockRestore();
    }
    const directory = dirname(handoff);
    const receipt = join(
      dirname(dirname(directory)),
      `${basename(directory)}.json`,
    );
    expect(
      JSON.parse(await readFile(receipt, "utf8")).outcome.created,
    ).toHaveLength(1);
    const retry = await publishScanInternal(
      completed.scanDirectory,
      { ...OPTIONS, skipExisting: true },
      runtime,
    );
    expect(retry.skipped).toHaveLength(1);
    expect(storedPublications(completed)).toHaveLength(1);
    expect(launches).toBe(1);
  });

  test.each(["cleanup", "marker", "unknown"])(
    "saved API failures survive cleanup without authorizing unknown mutations (%s)",
    async (failure) => {
      const indeterminate = failure === "unknown";
      const completed = await fixture(2);
      const handoffs = join(
        completed.stateDirectory,
        "publications",
        "linear",
        "handoffs",
      );
      const remove = fileSystem.rm;
      const cleanup = spyOn(fileSystem, "rm").mockImplementation(
        async (path, options) => {
          if (
            failure !== "marker" &&
            typeof path === "string" &&
            dirname(path) === handoffs &&
            options?.recursive
          ) {
            await remove(join(path, "issues.jsonl"));
            throw Object.assign(new Error("Synthetic sharing violation"), {
              code: "EPERM",
            });
          }
          return remove(path, options);
        },
      );
      const rename = fileSystem.rename;
      const checkpoint = spyOn(fileSystem, "rename").mockImplementation(
        async (source, target) => {
          if (
            failure === "marker" &&
            typeof target === "string" &&
            dirname(target) === dirname(handoffs) &&
            JSON.parse(await readFile(source, "utf8")).recovered
          )
            throw new Error("Synthetic completed receipt write failure");
          return rename(source, target);
        },
      );
      type LinearClient = ReturnType<
        NonNullable<PublishScanDependencies["linearClient"]>
      >;
      type IssueInput = Parameters<LinearClient["createIssue"]>[0];
      const attempted: string[] = [];
      let retry = false;
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        linearClient: () =>
          ({
            createIssue: async (input: IssueInput) => {
              const finding = completed.findings.find(({ findingId }) =>
                input.description?.includes(findingId),
              )!;
              attempted.push(finding.findingId);
              const second = finding === completed.findings[1];
              if (second && !retry)
                return {
                  success: indeterminate,
                  issue: Promise.resolve(undefined),
                };
              return {
                success: true,
                issue: Promise.resolve({
                  identifier: second ? "EXAMPLE-2" : "EXAMPLE-1",
                }),
              };
            },
          }) as unknown as LinearClient,
      };
      const options = {
        ...OPTIONS,
        linearApiKey: "lin_api_SYNTHETIC_CLEANUP",
      };
      try {
        const first = publishScanInternal(
          completed.scanDirectory,
          options,
          runtime,
        );
        if (indeterminate) {
          await expect(first).rejects.toThrow("could not verify");
        } else {
          const result = await first;
          expect(result.created).toHaveLength(1);
          expect(result.failed).toHaveLength(1);
        }
      } finally {
        cleanup.mockRestore();
        checkpoint.mockRestore();
      }
      const directory = join(handoffs, (await readdir(handoffs))[0]!);
      if (indeterminate) await rm(join(directory, "issues.jsonl"));
      const receipt = JSON.parse(
        await readFile(
          join(dirname(handoffs), `${basename(directory)}.json`),
          "utf8",
        ),
      );
      expect(receipt.outcome.indeterminate === true).toBe(indeterminate);
      expect(receipt.outcome.failed).toHaveLength(1);
      expect(receipt.recovered === true).toBe(failure === "cleanup");
      expect((await readdir(directory)).includes("issues.jsonl")).toBe(
        failure === "marker",
      );
      expect(
        await readFile(join(directory, "started-batches.jsonl"), "utf8"),
      ).toContain(completed.findings[1]!.findingId);
      retry = true;
      const result = publishScanInternal(
        completed.scanDirectory,
        { ...options, skipExisting: true },
        runtime,
      );
      if (indeterminate) {
        await expect(result).rejects.toThrow("outcome is unknown");
        expect(attempted).toHaveLength(2);
        expect(storedPublications(completed)).toHaveLength(1);
      } else {
        const recovered = await result;
        expect(recovered.skipped).toHaveLength(1);
        expect(recovered.created).toHaveLength(1);
        expect(attempted).toEqual([
          ...completed.findings.map((finding) => finding.findingId),
          completed.findings[1]!.findingId,
        ]);
        expect(storedPublications(completed)).toHaveLength(2);
      }
    },
  );

  test("an empty legacy publication plan cannot authorize replay", async () => {
    const completed = await fixture(1);
    let handoff = "";
    let launches = 0;
    const runtime: PublishScanDependencies = {
      environment: completed.environment,
      resolveCodex: () => ({ command: "synthetic-codex" }),
      runCodex: async (_command, _args, prompt) => {
        launches++;
        handoff = (await publicationPayload(prompt)).handoffFile;
        throw new Error("Synthetic unknown remote outcome");
      },
    };
    await expect(
      publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
    ).rejects.toThrow("unknown remote outcome");
    const directory = dirname(handoff);
    await rm(join(dirname(dirname(directory)), `${basename(directory)}.json`));
    const path = join(directory, "publication.json");
    const plan = JSON.parse(await readFile(path, "utf8"));
    plan.batches = [];
    await writeFile(path, JSON.stringify(plan));
    await expect(
      publishScanInternal(
        completed.scanDirectory,
        { ...OPTIONS, skipExisting: true },
        runtime,
      ),
    ).rejects.toThrow("Reconcile");
    expect(launches).toBe(1);
    expect(storedPublications(completed)).toEqual([]);
  });

  test("a recorded mapping does not hide an additional acknowledged native mutation", async () => {
    const completed = await fixture(1);
    let launches = 0;
    const runtime: PublishScanDependencies = {
      environment: completed.environment,
      resolveCodex: () => ({ command: "synthetic-codex" }),
      runCodex: async (_command, _args, prompt) => {
        launches++;
        const payload = await publicationPayload(prompt);
        const request = payload.batches.flat()[0]!;
        return {
          exitCode: 0,
          stderr: "",
          stdout: [1, 2]
            .map((index) =>
              JSON.stringify({
                type: "item.completed",
                item: {
                  id: `synthetic-create-${index}`,
                  type: "mcp_tool_call",
                  server: "codex_apps",
                  tool: "linear_save_issue",
                  status: "completed",
                  arguments: request.arguments,
                  result: {
                    content: [],
                    structured_content: { identifier: `EXAMPLE-${index}` },
                  },
                },
              }),
            )
            .join("\n"),
        };
      },
    };
    await expect(
      publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
    ).rejects.toThrow("could not verify");
    const prepared = await prepareScanPublication(completed.scanDirectory, {
      ...OPTIONS,
      environment: completed.environment,
    });
    const issue = prepared.issues[0]!;
    await recordPublishedIssues(
      prepared,
      [
        {
          findingId: issue.findingId,
          occurrenceId: issue.occurrenceId,
          issueIdentifier: "EXAMPLE-1",
        },
      ],
      completed.environment,
    );
    await expect(
      publishScanInternal(
        completed.scanDirectory,
        { ...OPTIONS, skipExisting: true },
        runtime,
      ),
    ).rejects.toThrow("outcome is unknown");
    expect(storedPublications(completed)).toHaveLength(1);
    expect(launches).toBe(1);
  });

  test.each([false, true])(
    "unknown repeated attempts require a new acknowledgement or SQLite mapping (legacy=%j)",
    async (legacy) => {
      const completed = await fixture(1);
      const prepared = await prepareScanPublication(completed.scanDirectory, {
        ...OPTIONS,
        environment: completed.environment,
      });
      const issue = prepared.issues[0]!;
      const mapping = (issueIdentifier: string) => ({
        findingId: issue.findingId,
        occurrenceId: issue.occurrenceId,
        issueIdentifier,
      });
      for (const identifier of ["EXAMPLE-1", "EXAMPLE-2"])
        await recordPublishedIssues(
          prepared,
          [mapping(identifier)],
          completed.environment,
        );
      let launches = 0;
      let handoff = "";
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        runCodex: async (_command, _args, prompt) => {
          launches++;
          handoff = (await publicationPayload(prompt)).handoffFile;
          throw new Error("Synthetic interruption with unknown remote outcome");
        },
      };
      await expect(
        publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
      ).rejects.toThrow("unknown remote outcome");
      expect(await readFile(handoff, "utf8")).toBe("");
      const directory = dirname(handoff);
      const receipt = join(
        dirname(dirname(directory)),
        `${basename(directory)}.json`,
      );
      expect(
        JSON.parse(
          await readFile(receipt, "utf8"),
        ).previousIssueIdentifiers.sort(),
      ).toEqual(["EXAMPLE-1", "EXAMPLE-2"]);
      if (legacy) await rm(receipt);
      await expect(
        publishScanInternal(
          completed.scanDirectory,
          { ...OPTIONS, skipExisting: true },
          runtime,
        ),
      ).rejects.toThrow("outcome is unknown");
      if (legacy)
        await expect(readFile(receipt, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
      else
        expect(
          JSON.parse(await readFile(receipt, "utf8")).recovered,
        ).toBeUndefined();
      expect(storedPublications(completed)).toHaveLength(2);
      expect(launches).toBe(1);

      await recordPublishedIssues(
        prepared,
        [mapping("EXAMPLE-3")],
        completed.environment,
      );
      if (legacy) {
        await expect(
          publishScanInternal(
            completed.scanDirectory,
            { ...OPTIONS, skipExisting: true },
            runtime,
          ),
        ).rejects.toThrow("outcome is unknown");
        const saved = JSON.parse(
          await readFile(join(directory, "publication.json"), "utf8"),
        );
        await writeFile(
          handoff,
          JSON.stringify({
            scanId: prepared.scanId,
            ...saved.batches.flat()[0],
            issueIdentifier: "EXAMPLE-3",
          }) + "\n",
        );
      }
      await publishScanInternal(
        completed.scanDirectory,
        { ...OPTIONS, skipExisting: true },
        runtime,
      );
      const recovered = JSON.parse(await readFile(receipt, "utf8"));
      expect(recovered.recovered).toBe(true);
      expect(recovered.outcome.created).toEqual([mapping("EXAMPLE-3")]);
      expect(storedPublications(completed)).toHaveLength(3);
      expect(launches).toBe(1);
    },
  );

  test.each(["receipt", "handoff", "rewritten-handoff"])(
    "recovers a distinct repeated publication issue (%s)",
    async (mode) => {
      const completed = await fixture(1);
      let launches = 0;
      let failPersistence = true;
      let handoff = "";
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        recordPublishedIssues: async (...args) => {
          if (launches === 2 && failPersistence)
            throw new Error("Synthetic SQLite interruption");
          return recordPublishedIssues(...args);
        },
        runCodex: async (_command, _args, prompt) => {
          launches++;
          const payload = await publicationPayload(prompt);
          handoff = payload.handoffFile;
          await writeFile(
            handoff,
            JSON.stringify({
              scanId: payload.scanId,
              ...payload.batches.flat()[0]!,
              issueIdentifier: `EXAMPLE-${launches}`,
            }) + "\n",
          );
          if (launches === 2 && mode === "handoff")
            throw new Error("Synthetic process interruption");
          return { exitCode: 0, stdout: "", stderr: "" };
        },
      };
      await publishScanInternal(completed.scanDirectory, OPTIONS, runtime);
      await expect(
        publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
      ).rejects.toThrow("interruption");
      expect(
        storedPublications(completed).map((row) => row.external_id),
      ).toEqual(["EXAMPLE-1"]);
      if (mode === "rewritten-handoff") {
        const record = JSON.parse(await readFile(handoff, "utf8"));
        record.issueIdentifier = "EXAMPLE-3";
        await writeFile(handoff, JSON.stringify(record) + "\n");
      }
      failPersistence = false;
      for (let attempt = 0; attempt < 2; attempt++) {
        await publishScanInternal(
          completed.scanDirectory,
          { ...OPTIONS, skipExisting: true },
          runtime,
        );
        expect(
          storedPublications(completed)
            .map((row) => row.external_id)
            .sort(),
        ).toEqual(["EXAMPLE-1", "EXAMPLE-2"]);
        expect(launches).toBe(2);
      }
    },
  );

  test.each([false, true])(
    "recovers legacy mappings in source order (reversed manifest=%j)",
    async (reverseManifest) => {
      const completed = await fixture(2);
      const prepared = await prepareScanPublication(completed.scanDirectory, {
        ...OPTIONS,
        environment: completed.environment,
      });
      const earlier = prepared.issues[1]!;
      await recordPublishedIssues(
        prepared,
        [
          {
            findingId: earlier.findingId,
            occurrenceId: earlier.occurrenceId,
            issueIdentifier: "EXAMPLE-10",
          },
        ],
        completed.environment,
      );
      let launches = 0;
      let failPersistence = true;
      let handoff = "";
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        recordPublishedIssues: async (...args) => {
          if (failPersistence) throw new Error("Synthetic SQLite interruption");
          return recordPublishedIssues(...args);
        },
        runCodex: async (_command, _args, prompt) => {
          launches++;
          const payload = await publicationPayload(prompt);
          handoff = payload.handoffFile;
          await writeFile(
            handoff,
            payload.batches
              .flat()
              .map((request, index) =>
                JSON.stringify({
                  scanId: payload.scanId,
                  ...request,
                  issueIdentifier: `EXAMPLE-${index + 1}`,
                }),
              )
              .join("\n") + "\n",
          );
          return { exitCode: 0, stdout: "", stderr: "" };
        },
      };
      await expect(
        publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
      ).rejects.toThrow("Synthetic SQLite interruption");
      expect(
        storedPublications(completed).map((row) => row.external_id),
      ).toEqual(["EXAMPLE-10"]);
      const directory = dirname(handoff);
      await rm(
        join(dirname(dirname(directory)), `${basename(directory)}.json`),
      );
      if (reverseManifest) {
        const path = join(directory, "publication.json");
        const saved = JSON.parse(await readFile(path, "utf8"));
        saved.batches = [saved.batches.flat().reverse()];
        await writeFile(path, JSON.stringify(saved));
      }
      failPersistence = false;
      for (let attempt = 0; attempt < 2; attempt++) {
        const result = await publishScanInternal(
          completed.scanDirectory,
          { ...OPTIONS, skipExisting: true },
          runtime,
        );
        expect(result.created).toEqual([]);
        expect(result.skipped?.map((issue) => issue.findingId)).toEqual(
          prepared.issues.map((issue) => issue.findingId),
        );
        expect(
          storedPublications(completed)
            .sort((a, b) => a.external_id.localeCompare(b.external_id))
            .map((row) => [row.finding_id, row.external_id]),
        ).toEqual([
          [prepared.issues[0]!.findingId, "EXAMPLE-1"],
          [earlier.findingId, "EXAMPLE-10"],
          [earlier.findingId, "EXAMPLE-2"],
        ]);
        expect(launches).toBe(1);
      }
    },
  );

  test("recovers mixed recorded legacy findings after classification narrows", async () => {
    const { classifyScanDirectorySeverity } = await import(
      "../src/classify-scan-severity.js"
    );
    const completed = await fixture(2);
    const rubricPath = join(completed.stateDirectory, "policy.md");
    await writeFile(rubricPath, "Classify bounded impact as Medium.");
    const classify = (findingIds: string[]) =>
      classifyScanDirectorySeverity(completed.scanDirectory, {
        environment: completed.environment,
        rubricPath,
        findingIds,
        codex: {
          startThread: () => ({
            run: async (prompt) => {
              const findingId = findingIds.find((id) => prompt.includes(id))!;
              return {
                finalResponse: JSON.stringify({
                  findingId,
                  decision: "assessed",
                  level: "medium",
                  rubricLabel: "MEDIUM",
                  rationale: "Only bounded impact is established.",
                  confidence: "high",
                  reviewTrigger: null,
                }),
              };
            },
          }),
        },
      });
    await classify(completed.findings.map((finding) => finding.findingId));
    let launches = 0;
    let failPersistence = true;
    let handoff = "";
    const runtime: PublishScanDependencies = {
      environment: completed.environment,
      resolveCodex: () => ({ command: "synthetic-codex" }),
      recordPublishedIssues: async (publication, issues, environment) => {
        if (failPersistence) {
          await recordPublishedIssues(publication, [issues[0]!], environment);
          throw new Error("Synthetic partial SQLite interruption");
        }
        return recordPublishedIssues(publication, issues, environment);
      },
      runCodex: async (_command, _args, prompt) => {
        launches++;
        const payload = await publicationPayload(prompt);
        handoff = payload.handoffFile;
        await writeFile(
          handoff,
          payload.batches
            .flat()
            .map((request, index) =>
              JSON.stringify({
                scanId: payload.scanId,
                ...request,
                issueIdentifier: `EXAMPLE-${index + 1}`,
              }),
            )
            .join("\n") + "\n",
        );
        return { exitCode: 0, stdout: "", stderr: "" };
      },
    };
    await expect(
      publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
    ).rejects.toThrow("Synthetic partial SQLite interruption");
    expect(storedPublications(completed)).toHaveLength(1);
    const directory = dirname(handoff);
    await rm(join(dirname(dirname(directory)), `${basename(directory)}.json`));
    const pendingId = completed.findings[1]!.findingId;
    await classify([pendingId]);
    failPersistence = false;
    const result = await publishScanInternal(
      completed.scanDirectory,
      { ...OPTIONS, skipExisting: true },
      runtime,
    );
    expect(result.skipped?.map((issue) => issue.findingId)).toEqual([
      pendingId,
    ]);
    expect(storedPublications(completed)).toHaveLength(2);
    expect(launches).toBe(1);
  });

  test("legacy handoffs cannot expand the authorized finding selection", async () => {
    const completed = await fixture(2);
    const options = {
      ...OPTIONS,
      findingIds: [completed.findings[0]!.findingId],
    };
    let launches = 0;
    let failPersistence = true;
    let handoff = "";
    const runtime: PublishScanDependencies = {
      environment: completed.environment,
      resolveCodex: () => ({ command: "synthetic-codex" }),
      recordPublishedIssues: async (...args) => {
        if (failPersistence) throw new Error("Synthetic SQLite interruption");
        return recordPublishedIssues(...args);
      },
      runCodex: async (_command, _args, prompt) => {
        launches++;
        const payload = await publicationPayload(prompt);
        handoff = payload.handoffFile;
        await writeFile(
          handoff,
          JSON.stringify({
            scanId: payload.scanId,
            ...payload.batches.flat()[0]!,
            issueIdentifier: "EXAMPLE-1",
          }) + "\n",
        );
        return { exitCode: 0, stdout: "", stderr: "" };
      },
    };
    await expect(
      publishScanInternal(completed.scanDirectory, options, runtime),
    ).rejects.toThrow("Synthetic SQLite interruption");
    const directory = dirname(handoff);
    await rm(join(dirname(dirname(directory)), `${basename(directory)}.json`));
    const manifestPath = join(directory, "publication.json");
    const manifestText = await readFile(manifestPath, "utf8");
    const handoffText = await readFile(handoff, "utf8");
    const manifest = JSON.parse(manifestText);
    const full = await prepareScanPublication(completed.scanDirectory, {
      ...OPTIONS,
      environment: completed.environment,
      uploadedAt: manifest.uploadedAt,
    });
    const extra = full.issues.find(
      (issue) => issue.findingId === completed.findings[1]!.findingId,
    )!;
    const request = {
      findingId: extra.findingId,
      occurrenceId: extra.occurrenceId,
      arguments: linearPublicationArguments(full.destination, extra),
    };
    manifest.batches.push([request]);
    await writeFile(manifestPath, JSON.stringify(manifest));
    await appendFile(
      handoff,
      JSON.stringify({
        scanId: full.scanId,
        ...request,
        issueIdentifier: "EXAMPLE-2",
      }) + "\n",
    );
    failPersistence = false;
    await expect(
      publishScanInternal(
        completed.scanDirectory,
        { ...options, skipExisting: true },
        runtime,
      ),
    ).rejects.toThrow("Reconcile");
    expect(storedPublications(completed)).toEqual([]);
    expect(launches).toBe(1);

    await writeFile(manifestPath, manifestText);
    await writeFile(handoff, handoffText);
    const result = await publishScanInternal(
      completed.scanDirectory,
      { ...options, skipExisting: true },
      runtime,
    );
    expect(result.skipped?.map((issue) => issue.findingId)).toEqual(
      options.findingIds,
    );
    expect(storedPublications(completed).map((row) => row.finding_id)).toEqual(
      options.findingIds,
    );
    expect(launches).toBe(1);
  });

  test("recovers the original selection before retrying a narrower selection", async () => {
    const completed = await fixture(2);
    const controller = new AbortController();
    let launches = 0;
    const runtime: PublishScanDependencies = {
      environment: completed.environment,
      resolveCodex: () => ({ command: "synthetic-codex" }),
      runCodex: async (_command, _args, prompt) => {
        launches++;
        const payload = await publicationPayload(prompt);
        await writeFile(
          payload.handoffFile,
          payload.batches
            .flat()
            .map((issue, index) =>
              JSON.stringify({
                scanId: payload.scanId,
                findingId: issue.findingId,
                occurrenceId: issue.occurrenceId,
                arguments: issue.arguments,
                issueIdentifier: `SEC-${index + 1}`,
              }),
            )
            .join("\n") + "\n",
        );
        controller.abort();
        return { exitCode: 1, stdout: "", stderr: "Synthetic interruption" };
      },
    };
    await expect(
      publishScanInternal(
        completed.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        runtime,
      ),
    ).rejects.toThrow("interrupted");
    expect(storedPublications(completed)).toHaveLength(2);
    const result = await publishScanInternal(
      completed.scanDirectory,
      {
        ...OPTIONS,
        findingIds: [completed.findings[1]!.findingId],
        skipExisting: true,
      },
      runtime,
    );
    expect(result.skipped?.map(({ findingId }) => findingId)).toEqual([
      completed.findings[1]!.findingId,
    ]);
    expect(result.created).toEqual([]);
    expect(launches).toBe(1);
    expect(storedPublications(completed)).toHaveLength(2);
  });

  test("recovers a verified UUID-only connector handoff into SQLite without optional event logs", async () => {
    const completed = await fixture(1);
    const entityId = "22222222-2222-4222-8222-222222222222";
    let launches = 0;
    let failPersistence = true;
    let handoff = "";
    const runtime: PublishScanDependencies = {
      environment: completed.environment,
      resolveCodex: () => ({ command: "synthetic-codex" }),
      writeEvents: async () => {
        throw new Error("Synthetic optional event log failure");
      },
      recordPublishedIssues: async (...args) => {
        if (failPersistence) throw new Error("Synthetic SQLite interruption");
        return recordPublishedIssues(...args);
      },
      runCodex: async (_command, _args, prompt) => {
        launches++;
        const payload = await publicationPayload(prompt);
        const request = payload.batches.flat()[0]!;
        handoff = payload.handoffFile;
        await writeFile(
          handoff,
          JSON.stringify({
            scanId: payload.scanId,
            ...request,
            issueIdentifier: entityId,
          }) + "\n",
        );
        return {
          exitCode: 0,
          stderr: "",
          stdout: JSON.stringify({
            type: "item.completed",
            item: {
              id: "synthetic-create",
              type: "mcp_tool_call",
              server: "codex_apps",
              tool: "linear_save_issue",
              status: "completed",
              arguments: request.arguments,
              result: {
                content: [],
                structured_content: { id: entityId, identifier: "SEC-991" },
              },
            },
          }),
        };
      },
    };
    await expect(
      publishScanInternal(completed.scanDirectory, OPTIONS, runtime),
    ).rejects.toThrow("Synthetic SQLite interruption");
    expect(storedPublications(completed)).toHaveLength(0);
    expect(
      (await readdir(dirname(handoff))).some((name) =>
        name.startsWith("events-"),
      ),
    ).toBe(false);
    failPersistence = false;
    const result = await publishScanInternal(
      completed.scanDirectory,
      { ...OPTIONS, skipExisting: true },
      runtime,
    );
    expect(result.skipped).toEqual([
      expect.objectContaining({ issueIdentifier: "SEC-991" }),
    ]);
    expect(storedPublications(completed)).toHaveLength(1);
    expect(launches).toBe(1);
  });

  test.each(["completed", "interrupted", "legacy-interrupted", "legacy-uuid"])(
    "publishes classified selections while preserving earlier tickets (%s)",
    async (mode) => {
      const { classifyScanDirectorySeverity } = await import(
        "../src/classify-scan-severity.js"
      );
      const completed = await fixture(2);
      const rubricPath = join(completed.stateDirectory, "policy.md");
      await writeFile(rubricPath, "Classify bounded impact as Medium.");
      type LinearClient = ReturnType<
        NonNullable<PublishScanDependencies["linearClient"]>
      >;
      type IssueInput = Parameters<LinearClient["createIssue"]>[0];
      const created: IssueInput[] = [];
      const runtime: PublishScanDependencies = {
        environment: completed.environment,
        linearClient: () =>
          ({
            createIssue: async (input: IssueInput) => {
              created.push(input);
              return {
                success: true,
                issue: Promise.resolve({
                  identifier: `EXAMPLE-${created.length}`,
                }),
              };
            },
          }) as unknown as LinearClient,
      };
      for (const [index, finding] of completed.findings.entries()) {
        await classifyScanDirectorySeverity(completed.scanDirectory, {
          environment: completed.environment,
          rubricPath,
          findingIds: [finding.findingId],
          codex: {
            startThread: () => ({
              run: async () => ({
                finalResponse: JSON.stringify({
                  findingId: finding.findingId,
                  decision: "assessed",
                  level: "medium",
                  rubricLabel: "MEDIUM",
                  rationale: "Only bounded impact is established.",
                  confidence: "high",
                  reviewTrigger: null,
                }),
              }),
            }),
          },
        });
        const controller = new AbortController();
        const interrupted = mode !== "completed" && index === 0;
        const attempt = publishScanInternal(
          completed.scanDirectory,
          {
            ...OPTIONS,
            linearApiKey: "lin_api_SYNTHETIC_CLASSIFICATION",
            skipExisting: true,
            signal: controller.signal,
            onProgress: (event) => {
              if (interrupted && event.type === "handoff_recorded")
                controller.abort();
            },
          },
          runtime,
        );
        if (interrupted) {
          await expect(attempt).rejects.toThrow("interrupted");
          expect(storedPublications(completed)).toHaveLength(1);
          if (mode.startsWith("legacy-")) {
            const handoffs = join(
              completed.stateDirectory,
              "publications",
              "linear",
              "handoffs",
            );
            const directory = join(handoffs, (await readdir(handoffs))[0]!);
            await rm(join(dirname(handoffs), `${basename(directory)}.json`));
            const file = join(directory, "issues.jsonl");
            const record = JSON.parse((await readFile(file, "utf8")).trim());
            const {
              issueIdentifier: _identifier,
              url: _url,
              ...request
            } = record;
            await writeFile(
              file,
              `${JSON.stringify({ ...request, ...(mode === "legacy-uuid" ? { issueIdentifier: "22222222-2222-4222-8222-222222222222" } : { error: "The model omitted the created issue" }) })}\n${JSON.stringify(record)}\n`,
            );
            const manifest = JSON.parse(
              await readFile(join(directory, "publication.json"), "utf8"),
            );
            delete manifest.transport;
            delete manifest.uploadedAt;
            await writeFile(
              join(directory, "publication.json"),
              JSON.stringify(manifest),
            );
          }
        } else {
          const result = await attempt;
          expect(result.created).toHaveLength(1);
          expect(result.created[0]!.findingId).toBe(finding.findingId);
        }
        expect(created.at(-1)!.priority).toBe(3);
      }
      const repeated = await publishScanInternal(
        completed.scanDirectory,
        {
          ...OPTIONS,
          linearApiKey: "lin_api_SYNTHETIC_CLASSIFICATION",
          skipExisting: true,
        },
        runtime,
      );
      expect(repeated.created).toEqual([]);
      expect(repeated.skipped).toHaveLength(1);
      expect(created).toHaveLength(2);
      expect(storedPublications(completed)).toHaveLength(2);
    },
  );

  test("checks and retries a partial publication without duplicating recorded successes", async () => {
    const completed = await fixture(2);
    const sealed = await artifactDigests(completed.scanDirectory);
    const environment = {
      ...completed.environment,
      CODEX_SECURITY_LINEAR_API_KEY: "lin_api_SYNTHETIC_RETRY_KEY",
    };
    const cli = dependencies({ environment });
    type LinearClient = ReturnType<
      NonNullable<PublishScanDependencies["linearClient"]>
    >;
    type IssueInput = Parameters<LinearClient["createIssue"]>[0];
    const attempted: string[] = [];
    let failSecond = true;
    let issueNumber = 500;
    cli.publishScan = (directory, options) =>
      publishScanInternal(directory, options, {
        environment,
        resolveCodex: () => {
          throw new Error("Direct publication must not start Codex.");
        },
        linearClient: () =>
          ({
            users: async () => {
              throw new Error("Unassigned publication must not look up users.");
            },
            createIssue: async (input: IssueInput) => {
              const index = completed.findings.findIndex(({ findingId }) =>
                input.description?.includes(findingId),
              );
              expect(index).toBeGreaterThanOrEqual(0);
              attempted.push(completed.findings[index]!.findingId);
              if (failSecond && index === 1)
                throw new Error("Synthetic creation failure.");
              const identifier = `EXAMPLE-${++issueNumber}`;
              return {
                success: true,
                issue: Promise.resolve({
                  identifier,
                  url: `https://linear.app/example/issue/${identifier}`,
                }),
              };
            },
          }) as unknown as LinearClient,
      });
    const command = [
      "publish",
      "scan",
      completed.scanDirectory,
      "--to",
      "linear",
      "--linear-team",
      OPTIONS.teamId,
      "--project",
      OPTIONS.projectId,
      "--json",
    ];
    const run = async (flags: string[] = []) => {
      const stdout = capture();
      const stderr = capture();
      const code = await main(
        [...command, ...flags],
        stdout.stream,
        stderr.stream,
        cli,
      );
      return { code, result: JSON.parse(stdout.text()) as PublishScanResult };
    };

    const initial = await run();
    expect(initial.code).toBe(2);
    expect(initial.result.counts).toEqual({
      findings: 2,
      created: 1,
      failed: 1,
    });
    expect(storedPublications(completed)).toHaveLength(1);

    const localEnvironment = {
      ...completed.environment,
      CODEX_SECURITY_LINEAR_API_KEY: undefined,
    };
    const checkCli = dependencies({ environment: localEnvironment });
    checkCli.checkScanPublication = (directory, options) =>
      checkScanPublicationInternal(directory, options, {
        environment: localEnvironment,
      });
    const checkOutput = capture();
    const database = join(completed.stateDirectory, "workbench.sqlite3");
    const before = sha256(await readFile(database));
    expect(
      await main(
        [
          "publish",
          "check",
          completed.scanDirectory,
          "--to",
          "linear",
          "--linear-team",
          OPTIONS.teamId,
          "--project",
          OPTIONS.projectId,
          "--json",
        ],
        checkOutput.stream,
        capture().stream,
        checkCli,
      ),
    ).toBe(0);
    const checked = JSON.parse(checkOutput.text());
    expect(checked.counts).toEqual({ findings: 2, recorded: 1, pending: 1 });
    expect(checked.access.issueCreation).toBe("not-tested");
    expect(checked.recorded).toEqual(initial.result.created);
    expect(sha256(await readFile(database))).toBe(before);

    failSecond = false;
    attempted.length = 0;
    const retry = await run(["--skip-existing"]);
    expect(retry.code).toBe(0);
    expect(attempted).toEqual([completed.findings[1]!.findingId]);
    expect(retry.result.skipped).toEqual(initial.result.created);
    expect(retry.result.counts).toEqual({
      findings: 2,
      created: 1,
      failed: 0,
      skipped: 1,
    });
    expect(storedPublications(completed)).toHaveLength(2);

    const receipt = await readFile(receiptPath(completed), "utf8");
    attempted.length = 0;
    const repeated = await run(["--skip-existing"]);
    expect(repeated.code).toBe(0);
    expect(repeated.result.counts).toEqual({
      findings: 2,
      created: 0,
      failed: 0,
      skipped: 2,
    });
    expect(attempted).toEqual([]);
    expect(await readFile(receiptPath(completed), "utf8")).toBe(receipt);
    expect(storedPublications(completed)).toHaveLength(2);

    expect((await run()).result.counts).toEqual({
      findings: 2,
      created: 2,
      failed: 0,
    });
    expect(storedPublications(completed)).toHaveLength(4);
    expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
  });

  test("persists unassigned direct team-only publication", async () => {
    const completed = await fixture(23);
    const sealed = await artifactDigests(completed.scanDirectory);
    const key = "lin_api_SYNTHETIC_INTEGRATION_KEY";
    const environment = {
      ...completed.environment,
      CODEX_SECURITY_LINEAR_API_KEY: key,
    };
    const stdout = capture();
    const stderr = capture();
    const created: string[] = [];
    const cli = dependencies({ environment });
    type LinearClient = ReturnType<
      NonNullable<PublishScanDependencies["linearClient"]>
    >;
    type IssueInput = Parameters<LinearClient["createIssue"]>[0];

    cli.publishScan = async (directory, options) =>
      publishScanInternal(directory, options, {
        environment,
        resolveCodex: () => {
          throw new Error("Direct publication must not start Codex.");
        },
        linearClient: ({ apiKey }) => {
          expect(apiKey).toBe(key);
          return {
            users: async () => {
              throw new Error("Unassigned publication must not look up users.");
            },
            createIssue: async (input: IssueInput) => {
              const index = completed.findings.findIndex(({ findingId }) =>
                input.description?.includes(findingId),
              );
              expect(index).toBeGreaterThanOrEqual(0);
              expect(input).toMatchObject({
                teamId: OPTIONS.teamId,
                priority: 2,
              });
              expect(input).not.toHaveProperty("assigneeId");
              expect(input).not.toHaveProperty("projectId");
              if (index >= 20)
                expect(created.length).toBeGreaterThanOrEqual(20);
              const identifier = `SEC-${index + 1}`;
              created.push(identifier);
              return {
                success: true,
                issue: Promise.resolve({
                  identifier,
                  url: `https://linear.app/example/issue/${identifier}`,
                }),
              };
            },
          } as unknown as LinearClient;
        },
      });

    expect(
      await main(
        [
          "publish",
          "scan",
          completed.scanDirectory,
          "--to",
          "linear",
          "--linear-team",
          OPTIONS.teamId,
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        cli,
      ),
    ).toBe(0);

    const result = JSON.parse(stdout.text()) as PublishScanResult;
    expect(result.destination).toEqual({
      type: "linear",
      teamId: OPTIONS.teamId,
    });
    expect(result.counts).toEqual({ findings: 23, created: 23, failed: 0 });
    expect(storedPublications(completed)).toEqual(
      completed.findings.map((finding, index) => ({
        scan_id: SCAN_ID,
        finding_id: finding.findingId,
        occurrence_id: finding.occurrenceId,
        destination_type: "linear",
        team_id: OPTIONS.teamId,
        project_id: null,
        external_id: `SEC-${index + 1}`,
        external_url: `https://linear.app/example/issue/SEC-${index + 1}`,
      })),
    );
    expect(JSON.parse(await readFile(receiptPath(completed), "utf8"))).toEqual(
      result,
    );
    expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
    expect(stdout.text()).not.toContain(key);
  });

  test("publishes 23 sealed findings through a durable handoff without Codex JSON", async () => {
    const completed = await fixture(23);
    const sealed = await artifactDigests(completed.scanDirectory);
    const stdout = capture();
    const stderr = capture();
    const progress: PublishScanProgress[] = [];
    const cli = dependencies({ environment: completed.environment });
    let sdkResult: PublishScanResult | undefined;
    let handoffFile = "";
    cli.publishScan = async (directory, options) => {
      sdkResult = await publishScanInternal(
        directory,
        {
          ...options,
          onProgress: (event) => {
            progress.push(event);
            options.onProgress?.(event);
          },
        },
        {
          environment: completed.environment,
          resolveCodex: () => ({ command: "synthetic-codex" }),
          runCodex: async (_command, args, prompt, _environment, onEvent) => {
            const payload = await publicationPayload(prompt);
            handoffFile = payload.handoffFile;
            expect(args[args.indexOf("--sandbox") + 1]).toBe("workspace-write");
            expect(args[args.indexOf("--cd") + 1]).toBe(dirname(handoffFile));
            expect(handoffFile.startsWith(completed.scanDirectory)).toBe(false);
            expect(prompt).toContain("concurrently with Promise.allSettled");
            expect(payload.scanId).toBe(SCAN_ID);
            expect(payload.destination).toEqual({
              type: "linear",
              teamId: OPTIONS.teamId,
              projectId: OPTIONS.projectId,
            });
            expect(payload.batches.map((batch) => batch.length)).toEqual([
              20, 3,
            ]);

            const indices = new Map(
              completed.findings.map(({ findingId }, index) => [
                findingId,
                index,
              ]),
            );
            for (const batch of payload.batches) {
              const settled = await Promise.all(
                batch.map(async (finding) => {
                  const index = indices.get(finding.findingId)!;
                  expect(finding.occurrenceId).toBe(
                    completed.findings[index]!.occurrenceId,
                  );
                  expect(finding.arguments).toMatchObject({
                    team: OPTIONS.teamId,
                    project: OPTIONS.projectId,
                    title: `[Codex Security][HIGH] Synthetic finding ${index + 1}`,
                    priority: 2,
                  });
                  expect(finding.arguments["description"]).toContain(
                    finding.findingId,
                  );
                  const identifier = `SEC-${700 + index}`;
                  return {
                    scanId: payload.scanId,
                    findingId: finding.findingId,
                    occurrenceId: finding.occurrenceId,
                    issueIdentifier: identifier,
                    url: `https://linear.app/example/issue/${identifier}`,
                    arguments: finding.arguments,
                  };
                }),
              );
              await appendFile(
                payload.handoffFile,
                `${settled
                  .reverse()
                  .map((record) => JSON.stringify(record))
                  .join("\n")}\n`,
              );
            }
            onEvent?.({
              type: "item.completed",
              item: {
                id: "agent-message-1",
                type: "agent_message",
                text: "Created zero issues: {not valid JSON; imaginary SEC-999999}",
              },
            });
            return { exitCode: 0, stdout: "not valid JSON\n", stderr: "" };
          },
        },
      );
      return sdkResult;
    };

    expect(
      await main(
        [
          "publish",
          "scan",
          completed.scanDirectory,
          "--to",
          "linear",
          "--linear-team",
          OPTIONS.teamId,
          "--project",
          OPTIONS.projectId,
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        cli,
      ),
    ).toBe(0);

    expect(sdkResult?.counts).toEqual({
      findings: 23,
      created: 23,
      failed: 0,
    });
    expect(
      sdkResult?.created.map(({ issueIdentifier }) => issueIdentifier),
    ).toEqual(Array.from({ length: 23 }, (_, index) => `SEC-${700 + index}`));
    expect(JSON.parse(stdout.text())).toEqual(sdkResult);
    expect(stdout.text()).not.toContain("not valid JSON");
    expect(stdout.text()).not.toContain("SEC-999999");
    expect(JSON.parse(await readFile(receiptPath(completed), "utf8"))).toEqual(
      sdkResult,
    );

    const persisted = storedPublications(completed);
    expect(persisted).toHaveLength(23);
    expect(persisted).toEqual(
      completed.findings.map((finding, index) => ({
        scan_id: SCAN_ID,
        finding_id: finding.findingId,
        occurrence_id: finding.occurrenceId,
        destination_type: "linear",
        team_id: OPTIONS.teamId,
        project_id: OPTIONS.projectId,
        external_id: `SEC-${700 + index}`,
        external_url: `https://linear.app/example/issue/SEC-${700 + index}`,
      })),
    );
    expect(
      progress.filter(({ type }) => type === "issue_completed"),
    ).toHaveLength(23);
    expect(progress.at(-1)).toEqual({
      type: "completed",
      created: 23,
      failed: 0,
      total: 23,
    });
    expect(stderr.text()).toContain("Published 23/23 findings.");
    expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
    expect(
      await readFile(handoffFile).then(
        () => true,
        () => false,
      ),
    ).toBe(false);
  });

  test("retains team-only database-backed partial successes when a later batch fails", async () => {
    const completed = await fixture(22);
    const sealed = await artifactDigests(completed.scanDirectory);
    const stdout = capture();
    const stderr = capture();
    const cli = dependencies({ environment: completed.environment });
    cli.publishScan = async (directory, options) =>
      await publishScanInternal(directory, options, {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        runCodex: async (_command, _args, prompt) => {
          const payload = await publicationPayload(prompt);
          expect(payload.destination).toEqual({
            type: "linear",
            teamId: OPTIONS.teamId,
          });
          expect(payload.batches.map((batch) => batch.length)).toEqual([20, 2]);
          for (const [batchIndex, batch] of payload.batches.entries()) {
            const records = batch.map((finding, index) => {
              expect(finding.arguments).not.toHaveProperty("project");
              return {
                scanId: payload.scanId,
                findingId: finding.findingId,
                occurrenceId: finding.occurrenceId,
                arguments: finding.arguments,
                ...(batchIndex === 1 && index === 0
                  ? { error: "The second batch issue failed." }
                  : {
                      issueIdentifier: `SEC-${900 + batchIndex * 20 + index}`,
                    }),
              };
            });
            await appendFile(
              payload.handoffFile,
              `${records.map((record) => JSON.stringify(record)).join("\n")}\n`,
            );
          }
          return { exitCode: 0, stdout: "", stderr: "" };
        },
      });

    expect(
      await main(
        [
          "publish",
          "scan",
          completed.scanDirectory,
          "--to",
          "linear",
          "--linear-team",
          OPTIONS.teamId,
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        cli,
      ),
    ).toBe(2);

    const result = JSON.parse(stdout.text()) as PublishScanResult;
    expect(result.destination).toEqual({
      type: "linear",
      teamId: OPTIONS.teamId,
    });
    expect(result.counts).toEqual({ findings: 22, created: 21, failed: 1 });
    expect(result.failed).toEqual([
      {
        findingId: completed.findings[20]!.findingId,
        error: "The second batch issue failed.",
      },
    ]);
    const persisted = storedPublications(completed);
    expect(persisted).toHaveLength(21);
    expect(persisted.every(({ project_id }) => project_id === null)).toBe(true);
    expect(
      persisted.some(
        ({ finding_id }) => finding_id === result.failed[0]!.findingId,
      ),
    ).toBe(false);
    expect(persisted.map(({ external_id }) => external_id)).toEqual(
      result.created.map(({ issueIdentifier }) => issueIdentifier),
    );
    expect(JSON.parse(await readFile(receiptPath(completed), "utf8"))).toEqual(
      result,
    );
    expect(stderr.text()).toContain("Published 21/22 findings (1 failed).");
    expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
  });

  test("keeps SQLite-backed Linear issues successful when their optional receipt cannot be saved", async () => {
    const completed = await fixture(2);
    const sealed = await artifactDigests(completed.scanDirectory);
    const stdout = capture();
    const stderr = capture();
    const cli = dependencies({ environment: completed.environment });
    let publicationAttempts = 0;

    cli.publishScan = async (directory, options) =>
      await publishScanInternal(directory, options, {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        runCodex: async (_command, _args, prompt) => {
          publicationAttempts += 1;
          const payload = await publicationPayload(prompt);
          await appendFile(
            payload.handoffFile,
            `${payload.batches[0]!.map((finding, index) =>
              JSON.stringify({
                scanId: payload.scanId,
                findingId: finding.findingId,
                occurrenceId: finding.occurrenceId,
                arguments: finding.arguments,
                issueIdentifier: `SEC-${801 + index}`,
              }),
            ).join("\n")}\n`,
          );
          return { exitCode: 0, stdout: "", stderr: "" };
        },
        writeReceipt: async () => {
          throw new Error(
            "Receipt storage unavailable: sk-proj-SYNTHETIC_RECEIPT_SECRET",
          );
        },
      });

    expect(
      await main(
        [
          "publish",
          "scan",
          completed.scanDirectory,
          "--to",
          "linear",
          "--linear-team",
          OPTIONS.teamId,
          "--project",
          OPTIONS.projectId,
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        cli,
      ),
    ).toBe(0);

    const result = JSON.parse(stdout.text()) as PublishScanResult & {
      warnings?: string[];
    };
    expect(result.counts).toEqual({ findings: 2, created: 2, failed: 0 });
    expect(
      result.created.map(({ issueIdentifier }) => issueIdentifier),
    ).toEqual(["SEC-801", "SEC-802"]);
    expect(result.warnings).toEqual([
      "Could not save the publication receipt: [redacted]. Linear issues were already created; do not retry publication.",
    ]);
    expect(stderr.text()).toContain(result.warnings![0]!);
    expect(stdout.text()).not.toContain("SYNTHETIC_RECEIPT_SECRET");
    expect(stderr.text()).not.toContain("SYNTHETIC_RECEIPT_SECRET");
    expect(publicationAttempts).toBe(1);
    expect(
      storedPublications(completed).map(({ external_id }) => external_id),
    ).toEqual(["SEC-801", "SEC-802"]);
    expect(
      await readFile(receiptPath(completed), "utf8").catch(() => null),
    ).toBe(null);
    expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
  });

  test.each([false, true])(
    "keeps conflicting connector identities out of CLI history and retains recovery evidence with skipExisting=%j",
    async (skipExisting) => {
      const completed = await fixture(1 + Number(skipExisting));
      const sealed = await artifactDigests(completed.scanDirectory);
      const recorded: PublishedScanIssue[] = [];
      if (skipExisting) {
        const prepared = await prepareScanPublication(
          completed.scanDirectory,
          OPTIONS,
        );
        recorded.push({
          findingId: prepared.issues[0]!.findingId,
          occurrenceId: prepared.issues[0]!.occurrenceId,
          issueIdentifier: "SEC-500",
        });
        await recordPublishedIssues(prepared, recorded, completed.environment);
      }
      const storedBefore = storedPublications(completed);
      const pending = completed.findings[Number(skipExisting)]!;
      const stdout = capture();
      const stderr = capture();
      const cli = dependencies({ environment: completed.environment });
      let handoffFile = "";
      let handoffLine = "";
      let completedEvent = "";

      cli.publishScan = async (directory, options) =>
        publishScanInternal(directory, options, {
          environment: completed.environment,
          resolveCodex: () => ({ command: "synthetic-codex" }),
          runCodex: async (_command, _args, prompt) => {
            const payload = await publicationPayload(prompt);
            expect(
              payload.batches.flat().map((finding) => finding.findingId),
            ).toEqual([pending.findingId]);
            const finding = payload.batches[0]![0]!;
            handoffFile = payload.handoffFile;
            handoffLine = JSON.stringify({
              scanId: payload.scanId,
              findingId: finding.findingId,
              occurrenceId: finding.occurrenceId,
              issueIdentifier: "SYNTH-A",
              arguments: finding.arguments,
            });
            await appendFile(handoffFile, `${handoffLine}\n`, "utf8");
            completedEvent = JSON.stringify({
              type: "item.completed",
              item: {
                id: "tool-conflicting-publication",
                type: "mcp_tool_call",
                server: "codex_apps",
                tool: "linear.save_issue",
                arguments: finding.arguments,
                status: "completed",
                result: {
                  structured_content: { identifier: "SYNTH-A" },
                  content: [
                    {
                      type: "text",
                      text: JSON.stringify({ identifier: "SYNTH-B" }),
                    },
                  ],
                },
              },
            });
            return { exitCode: 0, stdout: completedEvent, stderr: "" };
          },
        });

      expect(
        await main(
          [
            "publish",
            "scan",
            completed.scanDirectory,
            "--to",
            "linear",
            "--linear-team",
            OPTIONS.teamId,
            "--project",
            OPTIONS.projectId,
            ...(skipExisting ? ["--skip-existing"] : []),
            "--json",
          ],
          stdout.stream,
          stderr.stream,
          cli,
        ),
      ).toBe(2);

      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        "could not verify every completed mutation",
      );
      expect(stderr.text()).toContain(handoffFile);
      expect(storedPublications(completed)).toEqual(storedBefore);
      const receipt = JSON.parse(
        await readFile(receiptPath(completed), "utf8"),
      ) as PublishScanResult;
      expect(receipt.skipped).toEqual(skipExisting ? recorded : undefined);
      expect(receipt).toMatchObject({
        indeterminate: true,
        created: [],
        failed: [
          {
            findingId: pending.findingId,
            error:
              "The connected Linear app returned conflicting created issue identifiers or URLs.",
          },
        ],
        counts: {
          findings: completed.findings.length,
          created: 0,
          failed: 1,
          ...(skipExisting ? { skipped: 1 } : {}),
        },
      });
      expect(await readFile(handoffFile, "utf8")).toBe(`${handoffLine}\n`);
      const eventDirectory = dirname(dirname(dirname(handoffFile)));
      const eventFiles = (await readdir(eventDirectory)).filter(
        (name) =>
          name.startsWith(`${basename(dirname(handoffFile))}-events-`) &&
          name.endsWith(".jsonl"),
      );
      expect(eventFiles).toHaveLength(1);
      expect(await readFile(join(eventDirectory, eventFiles[0]!), "utf8")).toBe(
        `${completedEvent}\n`,
      );
      expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
    },
  );

  test.skipIf(process.platform === "win32")(
    "keeps no-signal SDK publication in the host process group",
    async () => {
      const completed = await fixture(1);
      const root = dirname(completed.scanDirectory);
      const preload = join(root, "sdk-publication-child.cjs");
      const publisherPidFile = join(root, "sdk-publication-child.pid");
      await writeFile(
        preload,
        'const fs = require("node:fs");fs.readFileSync(0, "utf8");fs.writeFileSync(process.env.CODEX_PUBLICATION_PARENT_PID, String(process.pid));const waiter = new Int32Array(new SharedArrayBuffer(4));for (;;) Atomics.wait(waiter, 0, 0, 1000);',
        { mode: 0o600 },
      );
      const publishing = publishScanInternal(completed.scanDirectory, OPTIONS, {
        environment: {
          PATH: completed.environment["PATH"],
          PYTHON: completed.python,
          CODEX_SECURITY_STATE_DIR: completed.stateDirectory,
          NODE_OPTIONS: `--require=${JSON.stringify(preload)}`,
          CODEX_PUBLICATION_PARENT_PID: publisherPidFile,
        },
        resolveCodex: () => ({ command: NODE_EXECUTABLE }),
      });

      try {
        let publisherPid = await readProcessId(publisherPidFile);
        for (let attempt = 0; publisherPid < 2 && attempt < 250; attempt += 1) {
          await Bun.sleep(20);
          publisherPid = await readProcessId(publisherPidFile);
        }
        expect(publisherPid).toBeGreaterThan(1);
        const groups = execFileSync(
          "ps",
          ["-o", "pgid=", "-p", `${process.pid},${publisherPid}`],
          { encoding: "utf8" },
        )
          .trim()
          .split(/\s+/u);
        expect(groups).toHaveLength(2);
        expect(new Set(groups).size).toBe(1);
        forceTerminatePublicationProcesses({
          platform: "win32",
          runTaskkill: () => {
            throw new Error("No-signal publication entered force registry.");
          },
        });
      } finally {
        const publisherPid = await readProcessId(publisherPidFile);
        killTestProcess(publisherPid);
        await publishing.catch(() => undefined);
      }
    },
    30_000,
  );

  test("applies connected-publication signal escalation without delivery duplicates", async () => {
    for (const [secondSignal, elapsed, expectedForced] of [
      ["SIGINT", 0, []],
      ["SIGTERM", 0, ["1:terminated", "0:SIGTERM"]],
      ["SIGINT", 500, ["1:terminated", "0:SIGINT"]],
    ] as const) {
      const signals = new FakeSignals();
      const forced: string[] = [];
      let now = 0;
      const cli = dependencies({ signals });
      cli.environment["CODEX_SECURITY_LINEAR_TEAM"] = OPTIONS.teamId;
      cli.now = () => now;
      const record = (value: string): number =>
        forced.push(`${signals.listeners.get("SIGINT")?.size}:${value}`);
      cli.terminatePublishers = () => record("terminated");
      cli.forceExit = record;
      cli.publishScan = async () => {
        signals.emit("SIGINT");
        now = elapsed;
        signals.emit(secondSignal);
        throw new Error("Synthetic interrupted connected publication.");
      };

      expect(
        await main(
          ["publish", "scan", "completed-scan", "--to", "linear"],
          capture().stream,
          capture().stream,
          cli,
        ),
      ).toBe(130);
      expect(forced).toEqual([...expectedForced]);
    }
  });

  test("kills connected publication descendants before a later signal forces exit", async () => {
    const completed = await fixture(1);
    const root = dirname(completed.scanDirectory);
    const preload = join(root, "publisher.cjs");
    const publisherPidFile = join(root, "publisher.pid");
    const descendantPidFile = join(root, "descendant.pid");
    const descendant =
      'const fs = require("node:fs");process.on("SIGINT", () => {});process.on("SIGTERM", () => {});fs.writeFileSync(process.env.CODEX_PUBLICATION_DESCENDANT_PID, String(process.pid));setInterval(() => {}, 1000);';
    await writeFile(
      preload,
      `const fs = require("node:fs"); const { spawn } = require("node:child_process");
const prompt = fs.readFileSync(0, "utf8"); const payload = JSON.parse(prompt.split("BEGIN UNTRUSTED PUBLICATION DATA\\n")[1].split("\\nEND UNTRUSTED PUBLICATION DATA")[0]); const finding = JSON.parse(fs.readFileSync(payload.publicationFile, "utf8")).batches[0][0];
fs.appendFileSync(payload.handoffFile, JSON.stringify({ scanId: payload.scanId, findingId: finding.findingId, occurrenceId: finding.occurrenceId, error: "Synthetic connected publication may have completed.", possibleMutation: true, arguments: finding.arguments }) + "\\n"); fs.writeFileSync(process.env.CODEX_PUBLICATION_PARENT_PID, String(process.pid));
spawn(process.execPath, ["-e", ${JSON.stringify(descendant)}], { env: { ...(process.platform === "win32" ? { SystemRoot: process.env.SystemRoot } : {}), CODEX_PUBLICATION_DESCENDANT_PID: process.env.CODEX_PUBLICATION_DESCENDANT_PID }, stdio: "ignore" });
const waiter = new Int32Array(new SharedArrayBuffer(4)); for (let attempts = 0; !fs.existsSync(process.env.CODEX_PUBLICATION_DESCENDANT_PID); attempts += 1) { if (attempts === 500) process.exit(3); Atomics.wait(waiter, 0, 0, 10); }
process.on("SIGINT", () => {}); process.on("SIGTERM", () => {}); fs.writeSync(1, '{"type":"synthetic.publisher_ready"}\\n');
for (;;) Atomics.wait(waiter, 0, 0, 1000);`,
      { mode: 0o600 },
    );
    const environment = {
      ...(process.platform === "win32"
        ? { SystemRoot: process.env["SystemRoot"] }
        : {}),
      PATH: completed.environment["PATH"],
      PYTHON: completed.python,
      CODEX_SECURITY_STATE_DIR: completed.stateDirectory,
      CODEX_SECURITY_LINEAR_TEAM: OPTIONS.teamId,
      NODE_OPTIONS: `--require=${JSON.stringify(preload)}`,
      CODEX_PUBLICATION_PARENT_PID: publisherPidFile,
      CODEX_PUBLICATION_DESCENDANT_PID: descendantPidFile,
    };
    const signals = new FakeSignals();
    const cli = dependencies({
      currentDirectory: completed.scanDirectory,
      environment,
      signals,
    });
    cli.forceExit = () => undefined;
    cli.publishScan = async (directory, options) =>
      await publishScanInternal(
        directory,
        {
          ...options,
          onProgress: (event) => {
            options.onProgress?.(event);
            if (event.type !== "codex_event") return;
            signals.emit("SIGINT");
            signals.emit("SIGTERM");
          },
        },
        {
          environment,
          resolveCodex: () => ({ command: NODE_EXECUTABLE }),
        },
      );

    try {
      expect(
        await Promise.race([
          main(
            ["publish", "scan", completed.scanDirectory, "--to", "linear"],
            capture().stream,
            capture().stream,
            cli,
          ),
          Bun.sleep(20_000).then(() => -1),
        ]),
      ).toBe(130);
      const publisherPid = await readProcessId(publisherPidFile);
      const descendantPid = await readProcessId(descendantPidFile);
      await Promise.all([
        waitForProcessExit(publisherPid),
        waitForProcessExit(descendantPid),
      ]);
      const handoffRoot = join(root, "state/publications/linear/handoffs");
      const handoffs = await readdir(handoffRoot);
      expect(handoffs).toHaveLength(1);
      const handoff = join(handoffRoot, handoffs[0]!);
      expect(await readFile(join(handoff, "issues.jsonl"), "utf8")).toContain(
        '"possibleMutation":true',
      );
      expect(
        await readFile(join(handoff, "publication.json"), "utf8"),
      ).toContain(completed.findings[0]!.findingId);
    } finally {
      const publisherPid = await readProcessId(publisherPidFile);
      const descendantPid = await readProcessId(descendantPidFile);
      killTestProcess(-publisherPid);
      killTestProcess(publisherPid);
      killTestProcess(descendantPid);
    }
  }, 30_000);

  test("recovers verified SQLite publications before an interrupted CLI exits", async () => {
    const completed = await fixture(3);
    const sealed = await artifactDigests(completed.scanDirectory);
    const stdout = capture();
    const stderr = capture();
    const signals = new FakeSignals();
    const cli = dependencies({ environment: completed.environment, signals });
    let handoffFile = "";

    cli.publishScan = async (directory, options) =>
      await publishScanInternal(directory, options, {
        environment: completed.environment,
        resolveCodex: () => ({ command: "synthetic-codex" }),
        runCodex: async (
          _command,
          _args,
          prompt,
          _environment,
          _onEvent,
          signal,
        ) => {
          const payload = await publicationPayload(prompt);
          const recorded = payload.batches[0]![0]!;
          const salvaged = payload.batches[0]![1]!;
          handoffFile = payload.handoffFile;
          await appendFile(
            handoffFile,
            `${JSON.stringify({
              scanId: payload.scanId,
              findingId: recorded.findingId,
              occurrenceId: recorded.occurrenceId,
              arguments: recorded.arguments,
              issueIdentifier: "SEC-701",
              url: "https://linear.app/example/issue/SEC-701",
            })}\n`,
          );

          signals.emit("SIGINT");
          expect(signal?.aborted).toBe(true);
          expect(signal?.reason).toBe("SIGINT");

          return {
            exitCode: 1,
            stdout: JSON.stringify({
              type: "item.completed",
              item: {
                id: "tool-salvaged-publication",
                type: "mcp_tool_call",
                server: "codex_apps",
                tool: "linear.save_issue",
                arguments: salvaged.arguments,
                status: "completed",
                result: {
                  content: [],
                  structured_content: {
                    identifier: "SEC-702",
                    url: "https://linear.app/example/issue/SEC-702",
                  },
                },
              },
            }),
            stderr: "Publication interrupted.",
          };
        },
      });

    expect(
      await main(
        [
          "publish",
          "scan",
          completed.scanDirectory,
          "--to",
          "linear",
          "--linear-team",
          OPTIONS.teamId,
          "--project",
          OPTIONS.projectId,
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        cli,
      ),
    ).toBe(130);

    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Publication canceled by Ctrl-C.");
    expect(stderr.text()).toContain(handoffFile);
    expect(stderr.text()).toContain("avoid creating duplicate issues");
    expect(
      storedPublications(completed).map(({ external_id }) => external_id),
    ).toEqual(["SEC-701", "SEC-702"]);

    const receipt = JSON.parse(
      await readFile(receiptPath(completed), "utf8"),
    ) as PublishScanResult;
    expect(receipt.counts).toEqual({ findings: 3, created: 2, failed: 1 });
    expect(
      receipt.created.map(({ issueIdentifier }) => issueIdentifier),
    ).toEqual(["SEC-701", "SEC-702"]);
    expect(
      (await readFile(handoffFile, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as { issueIdentifier: string })
        .map(({ issueIdentifier }) => issueIdentifier),
    ).toEqual(["SEC-701"]);
    expect(
      JSON.parse(
        await readFile(
          join(
            dirname(dirname(dirname(handoffFile))),
            `${basename(dirname(handoffFile))}.json`,
          ),
          "utf8",
        ),
      ),
    ).toMatchObject({
      outcome: {
        created: [
          expect.objectContaining({ issueIdentifier: "SEC-701" }),
          expect.objectContaining({ issueIdentifier: "SEC-702" }),
        ],
      },
    });
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
  });
});
