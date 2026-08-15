import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
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
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type {
  CoverageDocument,
  Finding,
  FindingsDocument,
  ScanManifest,
} from "../src/models.js";
import { recordPublishedIssues } from "../src/publication-store.js";
import {
  publishScanInternal,
  type PublishScanProgress,
  type PublishScanResult,
} from "../src/publish.js";
import { runWorkbench } from "../src/runtime.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { mockLinearClient } from "./support/linear-client.js";

const SCAN_ID = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_ID = "22222222-2222-4222-8222-222222222222";
const OPTIONS = {
  destination: "linear",
  teamId: "team-example",
  projectId: "project-example",
} as const;
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

async function fixture(
  count: number,
  includeCodeEvidence = false,
): Promise<PublicationFixture> {
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
    if (includeCodeEvidence) {
      finding.codeEvidence = [
        {
          id: `synthetic-evidence-${index + 1}`,
          label: "Untrusted archive destination",
          path: "src/extract.py",
          startLine: 41,
          language: "python",
          code: `write(destination_${index + 1}, user_input)`,
          explanation: "The requested archive path reaches a filesystem write.",
        },
      ];
    }
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
  test("publishes 23 sealed findings directly through authenticated GraphQL and real SQLite", async () => {
    const completed = await fixture(23, true);
    const sealed = await artifactDigests(completed.scanDirectory);
    const key = "opaque-sqlite-direct-api-secret-31415";
    const stdout = capture();
    const stderr = capture();
    const progress: PublishScanProgress[] = [];
    const requests: Array<{
      query: string;
      variables: Record<string, unknown>;
    }> = [];
    const createdIssues = new Map<string, Record<string, unknown>>();
    let active = 0;
    let maximum = 0;
    let settled = 0;
    let sdkResult: PublishScanResult | undefined;
    const cli = dependencies({ environment: completed.environment });
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
          resolveCodex: () => {
            throw new Error("direct API publication must not resolve Codex");
          },
          runCodex: async () => {
            throw new Error("direct API publication must not invoke Codex");
          },
          linearClient: mockLinearClient((async (
            resource: Parameters<typeof fetch>[0],
            init?: Parameters<typeof fetch>[1],
          ) => {
            expect(String(resource)).toBe("https://api.linear.app/graphql");
            expect(init?.method).toBe("POST");
            expect(init?.redirect).toBe("error");
            expect(new Headers(init?.headers).get("authorization")).toBe(key);
            const request = JSON.parse(String(init?.body)) as {
              query: string;
              variables: Record<string, unknown>;
            };
            requests.push(request);

            const operation = request.query.match(
              /\b(?:query|mutation)\s+(\w+)/u,
            )?.[1];
            if (operation === "viewer") {
              return Response.json({ data: { viewer: { id: "viewer-self" } } });
            }
            if (operation === "team") {
              expect(request.variables).toEqual({ id: OPTIONS.teamId });
              return Response.json({ data: { team: { id: OPTIONS.teamId } } });
            }
            if (operation === "project") {
              expect(request.variables).toEqual({ id: OPTIONS.projectId });
              return Response.json({
                data: { project: { id: OPTIONS.projectId } },
              });
            }
            if (operation === "project_teams") {
              return Response.json({
                data: {
                  project: {
                    teams: {
                      nodes: [{ id: OPTIONS.teamId }],
                      pageInfo: { hasNextPage: false, hasPreviousPage: false },
                    },
                  },
                },
              });
            }
            if (operation === "users") {
              expect(request.variables).toEqual({
                filter: {
                  email: { eqIgnoreCase: "owner@example.test" },
                },
                first: 2,
              });
              return Response.json({
                data: {
                  users: {
                    nodes: [
                      { id: "assigned-owner", email: "owner@example.test" },
                    ],
                    pageInfo: { hasNextPage: false, hasPreviousPage: false },
                  },
                },
              });
            }
            if (operation === "issue") {
              return Response.json({
                data: {
                  issue: {
                    ...createdIssues.get(String(request.variables["id"])),
                    sharedAccess: { sharedWithUsers: [] },
                    reactions: [],
                  },
                },
              });
            }

            const input = request.variables["input"] as Record<string, unknown>;
            const description = input["description"];
            const index = completed.findings.findIndex(
              (finding) =>
                typeof description === "string" &&
                description.includes(finding.findingId),
            );
            expect(index).toBeGreaterThanOrEqual(0);
            expect(input).toEqual({
              teamId: OPTIONS.teamId,
              projectId: OPTIONS.projectId,
              title: `[Codex Security][HIGH] Synthetic finding ${index + 1}`,
              description,
              priority: 2,
              assigneeId: "assigned-owner",
            });
            expect(description).toContain("## Source-code evidence");
            expect(description).toContain(
              `write(destination_${index + 1}, user_input)`,
            );
            if (index >= 20) expect(settled).toBeGreaterThanOrEqual(20);
            active += 1;
            maximum = Math.max(maximum, active);
            await new Promise((resolve) => setTimeout(resolve, 1));
            active -= 1;
            settled += 1;
            const identifier = `SEC-${900 + index}`;
            const issue = {
              id: `issue-${index + 1}`,
              identifier,
              url: `https://linear.app/example/issue/${identifier}`,
              title: input["title"],
              description,
              priority: input["priority"],
              team: { id: input["teamId"] },
              project: { id: input["projectId"] },
              assignee: { id: input["assigneeId"] },
            };
            createdIssues.set(issue.id, issue);
            return Response.json({
              data: {
                issueCreate: {
                  success: true,
                  issue: { id: issue.id },
                },
              },
            });
          }) as typeof fetch),
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
          "--linear-api-key",
          key,
          "--assignee-id",
          "owner@example.test",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        cli,
      ),
    ).toBe(0);

    expect(requests).toHaveLength(51);
    expect(maximum).toBe(20);
    expect(sdkResult?.counts).toEqual({
      findings: 23,
      created: 23,
      failed: 0,
    });
    expect(
      sdkResult?.created.map(({ issueIdentifier }) => issueIdentifier),
    ).toEqual(Array.from({ length: 23 }, (_, index) => `SEC-${900 + index}`));
    expect(JSON.parse(stdout.text())).toEqual(sdkResult);
    expect(JSON.parse(await readFile(receiptPath(completed), "utf8"))).toEqual(
      sdkResult,
    );
    expect(storedPublications(completed)).toEqual(
      completed.findings.map((finding, index) => ({
        scan_id: SCAN_ID,
        finding_id: finding.findingId,
        occurrence_id: finding.occurrenceId,
        destination_type: "linear",
        team_id: OPTIONS.teamId,
        project_id: OPTIONS.projectId,
        external_id: `SEC-${900 + index}`,
        external_url: `https://linear.app/example/issue/SEC-${900 + index}`,
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
    expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
    expect(stdout.text()).not.toContain(key);
    expect(stderr.text()).not.toContain(key);
    expect(await readFile(receiptPath(completed), "utf8")).not.toContain(key);
    expect(
      (
        await readFile(join(completed.stateDirectory, "workbench.sqlite3"))
      ).includes(Buffer.from(key)),
    ).toBe(false);
  });

  test("publishes a sealed finding directly to a team without a project", async () => {
    const completed = await fixture(1, true);
    const key = "lin_api_SYNTHETIC_TEAM_ONLY_INTEGRATION";
    const environment = {
      ...completed.environment,
      CODEX_SECURITY_LINEAR_API_KEY: key,
    };
    const stdout = capture();
    const stderr = capture();
    const requests: Array<{
      query: string;
      variables: Record<string, unknown>;
    }> = [];
    let createdIssue: Record<string, unknown> | undefined;
    let sdkResult: PublishScanResult | undefined;
    const cli = dependencies({ environment });
    cli.publishScan = async (directory, options) => {
      sdkResult = await publishScanInternal(directory, options, {
        environment,
        recordPublishedIssues: async (
          publication,
          issues,
          currentEnvironment,
        ) => {
          const handoffs = join(
            completed.stateDirectory,
            "publications",
            "linear",
            "handoffs",
          );
          const directories = await readdir(handoffs);
          expect(directories).toHaveLength(1);
          const records = (
            await readFile(
              join(handoffs, directories[0]!, "issues.jsonl"),
              "utf8",
            )
          )
            .trim()
            .split(/\r?\n/u)
            .map((line) => JSON.parse(line) as { arguments: unknown });
          expect(records).toHaveLength(issues.length);
          for (const record of records) {
            expect(record.arguments).not.toHaveProperty("project");
          }
          return recordPublishedIssues(publication, issues, currentEnvironment);
        },
        resolveCodex: () => {
          throw new Error("direct API publication must not resolve Codex");
        },
        runCodex: async () => {
          throw new Error("direct API publication must not invoke Codex");
        },
        linearClient: mockLinearClient((async (
          resource: Parameters<typeof fetch>[0],
          init?: Parameters<typeof fetch>[1],
        ) => {
          expect(String(resource)).toBe("https://api.linear.app/graphql");
          expect(new Headers(init?.headers).get("authorization")).toBe(key);
          const request = JSON.parse(String(init?.body)) as {
            query: string;
            variables: Record<string, unknown>;
          };
          requests.push(request);

          const operation = request.query.match(
            /\b(?:query|mutation)\s+(\w+)/u,
          )?.[1];
          if (operation === "viewer") {
            return Response.json({
              data: {
                viewer: { id: "viewer-self" },
              },
            });
          }
          if (operation === "team") {
            expect(request.variables).toEqual({ id: OPTIONS.teamId });
            return Response.json({ data: { team: { id: OPTIONS.teamId } } });
          }
          if (operation === "issue") {
            return Response.json({
              data: {
                issue: {
                  ...createdIssue,
                  sharedAccess: { sharedWithUsers: [] },
                  reactions: [],
                },
              },
            });
          }

          const input = request.variables["input"] as Record<string, unknown>;
          expect(input).not.toHaveProperty("projectId");
          const description = input["description"] as string;
          expect(input).toEqual({
            teamId: OPTIONS.teamId,
            title: "[Codex Security][HIGH] Synthetic finding 1",
            description,
            priority: 2,
            assigneeId: "viewer-self",
          });
          expect(description).toContain(completed.findings[0]!.findingId);
          expect(description).toContain("write(destination_1, user_input)");
          createdIssue = {
            id: "issue-950",
            identifier: "SEC-950",
            url: "https://linear.app/example/issue/SEC-950",
            title: input["title"],
            description,
            priority: input["priority"],
            team: { id: input["teamId"] },
            project: null,
            assignee: { id: input["assigneeId"] },
          };
          return Response.json({
            data: {
              issueCreate: {
                success: true,
                issue: { id: createdIssue["id"] },
              },
            },
          });
        }) as typeof fetch),
      });
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
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        cli,
      ),
    ).toBe(0);

    expect(requests).toHaveLength(4);
    expect(sdkResult?.destination).toMatchObject({
      type: "linear",
      teamId: OPTIONS.teamId,
    });
    expect(sdkResult?.destination).not.toHaveProperty("projectId");
    expect(sdkResult?.counts).toEqual({
      findings: 1,
      created: 1,
      failed: 0,
    });
    expect(JSON.parse(stdout.text())).toEqual(sdkResult);
    expect(JSON.parse(await readFile(receiptPath(completed), "utf8"))).toEqual(
      sdkResult,
    );
    expect(storedPublications(completed)).toEqual([
      {
        scan_id: SCAN_ID,
        finding_id: completed.findings[0]!.findingId,
        occurrence_id: completed.findings[0]!.occurrenceId,
        destination_type: "linear",
        team_id: OPTIONS.teamId,
        project_id: null,
        external_id: "SEC-950",
        external_url: "https://linear.app/example/issue/SEC-950",
      },
    ]);
    expect(stdout.text()).not.toContain(key);
    expect(stderr.text()).not.toContain(key);
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
    ).toEqual(["SEC-701", "SEC-702"]);
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    expect(await artifactDigests(completed.scanDirectory)).toEqual(sealed);
  });
});
