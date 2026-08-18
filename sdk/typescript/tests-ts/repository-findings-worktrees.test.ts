import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexSecurity } from "../src/index.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const fixtures = createApiTestFixtures();
const TestClient = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
) => CodexSecurity;

afterEach(fixtures.cleanup);

describe("repository findings across linked worktrees", () => {
  test("matches only repository-identity-scoped history from another worktree", async () => {
    const root = await fixtures.temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });

    const targetId = "target_sha256_example";
    const linkedFinding = {
      findingId: "linked_worktree_finding",
      occurrenceId: "linked_worktree_occurrence",
      scanId: "linked_worktree_scan",
      targetId: "target_linked_worktree",
    };
    const unrelatedFinding = {
      findingId: "independent_clone_finding",
      occurrenceId: "independent_clone_occurrence",
      scanId: "independent_clone_scan",
      targetId: "target_independent_clone",
    };
    const currentFinding = {
      findingId: "csf_852f90d6e1177502ff113d4a",
      occurrenceId: "occ_e79cb19591e696572a1c22be",
      scanId: "scan_example_001",
      targetId,
    };
    const mergedFinding = {
      ...linkedFinding,
      title: "Unsafe archive extraction",
      summary: "Archive entries can escape their destination.",
      severity: { level: "high" as const },
      status: "open" as const,
      confirmedInLatestScan: true,
      knownScanIds: [linkedFinding.scanId, currentFinding.scanId],
    };
    const commands: Array<readonly string[]> = [];
    const matchedInputs: Array<{
      before: readonly Record<string, unknown>[];
      after: readonly Record<string, unknown>[];
    }> = [];

    const client = new TestClient(
      {},
      {
        environment: {},
        prepareRuntime: async () => preparedRuntime(codexHome),
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (_options: unknown, args: readonly string[]) => {
          commands.push(args);
          if (args[0] === "register-cli-scan") {
            return {
              scanId: currentFinding.scanId,
              targetId,
              targetRevision: "deadbeef",
              scanDir: args[args.indexOf("--scan-dir") + 1],
              contract: { target: { allowedKinds: ["git_revision"] } },
            };
          }
          if (args[0] === "get-scan-feedback") {
            return {
              scanId: currentFinding.scanId,
              targetId,
              falsePositives: [],
            };
          }
          if (args[0] === "list-global-findings") {
            expect(args).toContain("--target-id");
            expect(args).toContain(targetId);
            return {
              findings: args.includes("--status")
                ? [mergedFinding]
                : [linkedFinding, currentFinding],
            };
          }
          if (args[0] === "list-unmatched-scan-pairs") {
            return {
              batches: [
                {
                  afterScanId: currentFinding.scanId,
                  afterFindings: [currentFinding],
                  beforeScans: [
                    {
                      scanId: linkedFinding.scanId,
                      findings: [linkedFinding],
                    },
                    {
                      scanId: unrelatedFinding.scanId,
                      findings: [unrelatedFinding],
                    },
                  ],
                },
              ],
            };
          }
          return {};
        },
        async matchFindings(input: (typeof matchedInputs)[number]) {
          matchedInputs.push(input);
          return {
            matches: [
              {
                beforeOccurrenceIds: [linkedFinding.occurrenceId],
                afterOccurrenceIds: [currentFinding.occurrenceId],
                confidence: "high",
                reason: "The linked worktree has the same root cause.",
              },
            ],
            uncertain: [],
          };
        },
        createCodex: () => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              await fixtures.copyCompletedScan(root);
              return { events: completedEvents() };
            },
          }),
        }),
      },
    );

    const result = await client.run(repository);

    expect(matchedInputs).toEqual([
      { before: [linkedFinding], after: [currentFinding] },
    ]);
    expect(
      commands.filter(([command]) => command === "save-scan-comparison"),
    ).toEqual([
      [
        "save-scan-comparison",
        "--before-scan-id",
        linkedFinding.scanId,
        "--after-scan-id",
        currentFinding.scanId,
        "--matches-json",
        JSON.stringify({
          matches: [
            {
              beforeOccurrenceIds: [linkedFinding.occurrenceId],
              afterOccurrenceIds: [currentFinding.occurrenceId],
              confidence: "high",
              reason: "The linked worktree has the same root cause.",
            },
          ],
          uncertain: [],
        }),
      ],
    ]);
    expect(result.repositoryFindings).toEqual([mergedFinding]);
    await client.close();
  });
});
