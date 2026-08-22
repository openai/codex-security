import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ThreadOptions, TurnOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import {
  comparisonForScan,
  comparisonEnvironment,
  matchCompletedScan,
  matchScanFindings,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function finding(occurrenceId: string): ScanComparisonInput["before"][number] {
  return { occurrenceId };
}

function fakeCodex(response: unknown) {
  const calls: {
    prompt?: string;
    threadOptions?: ThreadOptions;
    turnOptions?: TurnOptions;
  } = {};
  const codex: NonNullable<ScanComparisonOptions["codex"]> = {
    startThread(options) {
      calls.threadOptions = options;
      return {
        async run(prompt, turnOptions) {
          calls.prompt = prompt;
          calls.turnOptions = turnOptions;
          return {
            finalResponse:
              typeof response === "string"
                ? response
                : JSON.stringify(response),
          };
        },
      };
    },
  };
  return { codex, calls };
}

describe("semantic scan comparison", () => {
  test("preserves environment API-key precedence over managed credentials", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    let statusProbed = false;
    const account = async () => {
      statusProbed = true;
      return { authenticated: true, details: "Logged in using ChatGPT" };
    };

    const environment = await comparisonEnvironment(
      {
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-key-must-not-be-used",
        CODEX_API_KEY: "synthetic-secondary-must-not-be-used",
      },
      account,
    );

    expect(environment["CODEX_SECURITY_STATE_DIR"]).toBe(stateDirectory);
    expect(environment["OPENAI_API_KEY"]).toBe(
      "synthetic-key-must-not-be-used",
    );
    expect(environment["CODEX_API_KEY"]).toBe(
      "synthetic-secondary-must-not-be-used",
    );
    expect(environment["CODEX_HOME"]).toBeUndefined();
    const provider = {
      CODEX_SECURITY_STATE_DIR: stateDirectory,
      CODEX_SECURITY_SCAN_ID: "scan",
      CODEX_HOME: "/provider-home",
      FIREWORKS_API_KEY: "provider-key",
    };
    expect(await comparisonEnvironment(provider, account)).toEqual(provider);
    expect(statusProbed).toBe(false);
  });

  test.skipIf(process.platform !== "win32")(
    "recognizes provider scan variables regardless of Windows casing",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const stateDirectory = join(root, "state");
      const providerHome = join(root, "provider-home");
      await mkdir(join(stateDirectory, "codex-home"), {
        recursive: true,
        mode: 0o700,
      });
      let statusProbed = false;
      const provider = {
        codex_security_scan_id: "scan",
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        codex_home: providerHome,
        FIREWORKS_API_KEY: "synthetic-provider-key",
      };

      const environment = await comparisonEnvironment(provider, async () => {
        statusProbed = true;
        return { authenticated: true, details: "Logged in using ChatGPT" };
      });

      expect(environment).toEqual(provider);
      expect(statusProbed).toBe(false);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "replaces differently cased Windows CODEX_HOME variables",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const stateDirectory = join(root, "state");
      const credentialHome = join(stateDirectory, "codex-home");
      await mkdir(credentialHome, { recursive: true, mode: 0o700 });

      const environment = await comparisonEnvironment(
        {
          CODEX_SECURITY_STATE_DIR: stateDirectory,
          codex_home: join(root, "ambient-home"),
        },
        async () => ({
          authenticated: true,
          details: "Logged in using ChatGPT",
        }),
        undefined,
        async () => await realpath(credentialHome),
      );

      expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
      expect(environment["codex_home"]).toBeUndefined();
    },
  );

  test("reuses managed keyring credentials when no environment key is present", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    let probedHome: string | undefined;

    const environment = await comparisonEnvironment(
      { CODEX_SECURITY_STATE_DIR: stateDirectory },
      async (_command, storedEnvironment) => {
        probedHome = storedEnvironment["CODEX_HOME"];
        return { authenticated: true, details: "Logged in using ChatGPT" };
      },
    );

    expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
    expect(probedHome).toBe(await realpath(credentialHome));
  });

  test.skipIf(process.platform === "win32")(
    "uses the canonical keyring identity when the state parent is symlinked",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const actualState = join(root, "actual-state");
      const linkedState = join(root, "linked-state");
      const credentialHome = join(actualState, "codex-home");
      await mkdir(credentialHome, { recursive: true, mode: 0o700 });
      await symlink(actualState, linkedState, "dir");
      let probedHome: string | undefined;

      const environment = await comparisonEnvironment(
        { CODEX_SECURITY_STATE_DIR: linkedState },
        async (_command, storedEnvironment) => {
          probedHome = storedEnvironment["CODEX_HOME"];
          return { authenticated: true, details: "Logged in using ChatGPT" };
        },
      );

      expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
      expect(probedHome).toBe(await realpath(credentialHome));
    },
  );

  test("forwards cancellation to managed credential-status checks", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    await mkdir(join(stateDirectory, "codex-home"), {
      recursive: true,
      mode: 0o700,
    });
    const controller = new AbortController();
    let observedSignal: AbortSignal | undefined;
    let statusStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      statusStarted = resolve;
    });

    const waiting = comparisonEnvironment(
      { CODEX_SECURITY_STATE_DIR: stateDirectory },
      async (_command, _environment, signal) => {
        observedSignal = signal;
        statusStarted();
        return await new Promise((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
        });
      },
      controller.signal,
    );
    await started;
    controller.abort(new DOMException("canceled", "AbortError"));

    await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
    expect(observedSignal).toBe(controller.signal);
  });

  test("retains API-key authentication when the managed home is not signed in", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const ambientHome = join(root, "ambient-codex-home");
    await mkdir(ambientHome, { mode: 0o700 });
    await mkdir(join(stateDirectory, "codex-home"), {
      recursive: true,
      mode: 0o700,
    });

    const environment = await comparisonEnvironment(
      {
        CODEX_HOME: ambientHome,
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-comparison-key",
      },
      async () => ({ authenticated: false, details: "Not logged in" }),
    );

    expect(environment["OPENAI_API_KEY"]).toBe("synthetic-comparison-key");
    expect(environment["CODEX_HOME"]).toBe(ambientHome);
  });

  test.skipIf(process.platform !== "win32")(
    "recognizes stored credentials under a backslash home-relative path",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const ambientHome = join(root, "ambient-codex-home");
      await mkdir(ambientHome);
      await writeFile(join(ambientHome, "auth.json"), "{}");
      const environment = await comparisonEnvironment({
        CODEX_HOME: "~\\ambient-codex-home",
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        OPENAI_API_KEY: "",
        USERPROFILE: root,
      });

      expect(environment["OPENAI_API_KEY"]).toBeUndefined();
    },
  );

  test("compares all findings with one restricted structured-output turn", async () => {
    const input: ScanComparisonInput = {
      before: [finding("before-1"), finding("before-2")],
      after: [finding("after-1"), finding("after-2"), finding("after-3")],
    };
    const result = {
      matches: [
        {
          beforeOccurrenceIds: ["before-1"],
          afterOccurrenceIds: ["after-1", "after-2"],
          confidence: "high",
          reason: "The later scan split the same vulnerable extractor.",
        },
      ],
      uncertain: [
        {
          beforeOccurrenceId: "before-2",
          afterOccurrenceId: "after-3",
          reason: "A second entry point might be independently exploitable.",
        },
      ],
    } satisfies ScanComparisonResult;
    const { codex, calls } = fakeCodex(result);
    const controller = new AbortController();

    expect(
      await matchScanFindings(input, {
        codex,
        model: "comparison-model",
        reasoningEffort: "high",
        signal: controller.signal,
        workingDirectory: "/tmp/comparison",
      }),
    ).toEqual(result);
    expect(calls.threadOptions).toEqual({
      model: "comparison-model",
      modelReasoningEffort: "high",
      sandboxMode: "read-only",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      workingDirectory: "/tmp/comparison",
      skipGitRepoCheck: true,
    });
    expect(calls.turnOptions).toMatchObject({ signal: controller.signal });
    expect(calls.turnOptions?.outputSchema).toMatchObject({
      required: ["matches", "uncertain", "related", "request"],
    });
    const strictObjects = (schema: unknown): void => {
      if (schema === null || typeof schema !== "object") return;
      const object = schema as Record<string, unknown>;
      if (object["type"] === "object") {
        expect(object["required"]).toEqual(
          Object.keys(object["properties"] as object),
        );
        expect(object["additionalProperties"]).toBe(false);
      }
      for (const value of Object.values(object)) strictObjects(value);
    };
    strictObjects(calls.turnOptions?.outputSchema);
    expect(JSON.stringify(calls.turnOptions?.outputSchema)).toContain(
      '"type":"null"',
    );
    expect(calls.prompt).toContain(
      "same underlying root cause and remediation",
    );
    expect(calls.prompt).toContain(
      "same vulnerable helper share one root cause",
    );
    expect(calls.prompt).toContain("every earlier occurrence in one group");
    expect(calls.prompt).toContain("untrusted data");
    expect(calls.prompt).toContain(JSON.stringify(input));
  });

  test("rejects a confirmed match with conflicting same-scan uncertainty", async () => {
    const open = { findingId: "open", occurrenceId: "old-open" };
    const dismissed = { findingId: "dismissed", occurrenceId: "old-dismissed" };
    const after = { findingId: "renamed", occurrenceId: "new-renamed" };
    const commands: Array<{ args: readonly string[]; input?: string }> = [];
    let input: ScanComparisonInput | undefined;
    await expect(
      matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: [open],
        falsePositives: [{ findingId: "dismissed", sourceScanId: "prior" }],
        findings: [after],
        environment: {
          CODEX_HOME: "/provider-home",
          CODEX_SECURITY_SCAN_ID: "current",
          FIREWORKS_API_KEY: "synthetic-provider-key",
        },
        async workbench(args, commandInput) {
          commands.push({ args, input: commandInput });
          return args[0] === "list-unmatched-scan-pairs"
            ? {
                batches: [
                  {
                    afterScanId: "current",
                    afterFindings: [after],
                    beforeScans: [
                      {
                        scanId: "another-target",
                        findings: [{ ...dismissed, occurrenceId: "foreign" }],
                      },
                      { scanId: "prior", findings: [open, dismissed] },
                    ],
                  },
                ],
              }
            : {};
        },
        async matchFindings(value, options) {
          input = value;
          expect(options).toMatchObject({
            environment: {
              CODEX_HOME: "/provider-home",
              CODEX_SECURITY_SCAN_ID: "current",
            },
          });
          const response = {
            matches: [
              {
                beforeOccurrenceIds: ["old-dismissed"],
                afterOccurrenceIds: ["new-renamed"],
                confidence: "high",
                reason: "Same dismissed root cause.",
              },
            ],
            uncertain: [
              {
                beforeOccurrenceId: "old-open",
                afterOccurrenceId: "new-renamed",
                reason: "Possible match.",
              },
            ],
          };
          return await matchScanFindings(value, {
            ...options,
            codex: fakeCodex(response).codex,
          });
        },
      }),
    ).rejects.toThrow("conflicting confirmed and uncertain findings");
    expect(input).toEqual({ before: [open, dismissed], after: [after] });
    expect(commands.map(({ args: [command] }) => command)).toEqual([
      "list-unmatched-scan-pairs",
    ]);
  });

  test("compares complete selected scans before caching automatic matches", async () => {
    const firstShared = { findingId: "shared", occurrenceId: "first-shared" };
    const firstOther = { findingId: "other", occurrenceId: "first-other" };
    const latestShared = { findingId: "shared", occurrenceId: "latest-shared" };
    const unselected = { findingId: "unselected", occurrenceId: "unselected" };
    const after = { findingId: "renamed", occurrenceId: "current-renamed" };
    const saved = new Map<string, ScanComparisonResult>();
    let observed: ScanComparisonInput | undefined;
    const model = fakeCodex({
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: latestShared.occurrenceId,
          afterOccurrenceId: after.occurrenceId,
          reason: "The synthetic control may have moved.",
        },
      ],
    });

    await matchCompletedScan({
      scanId: "current",
      repository: "/repository",
      previousFindings: [firstOther, latestShared],
      falsePositives: [],
      findings: [after],
      async workbench(args, commandInput) {
        if (args[0] === "list-unmatched-scan-pairs") {
          return {
            batches: [
              {
                afterScanId: "current",
                afterFindings: [after],
                beforeScans: [
                  { scanId: "unselected", findings: [unselected] },
                  { scanId: "first", findings: [firstShared, firstOther] },
                  { scanId: "latest", findings: [latestShared] },
                ],
              },
            ],
          };
        }
        saved.set(args[2]!, JSON.parse(commandInput!) as ScanComparisonResult);
        return {};
      },
      matchFindings(input, options) {
        observed = input;
        return matchScanFindings(input, { ...options, codex: model.codex });
      },
    });

    expect(observed).toEqual({
      before: [firstShared, firstOther, latestShared],
      after: [after],
    });
    expect([...saved.keys()]).toEqual(["first", "latest"]);
    for (const [scanId, occurrenceId] of [
      ["first", firstShared.occurrenceId],
      ["latest", latestShared.occurrenceId],
    ] as const) {
      expect(saved.get(scanId)).toEqual({
        matches: [],
        uncertain: [
          {
            beforeOccurrenceId: occurrenceId,
            afterOccurrenceId: after.occurrenceId,
            reason: "The synthetic control may have moved.",
          },
        ],
      });
    }
  });

  test.each([
    ["no history", false, false, false, 0, false],
    ["a stable identity", true, false, true, 2, false],
    ["a renamed dismissed identity", false, true, false, 2, true],
  ] as const)(
    "only starts a model turn when needed for %s",
    async (
      _scenario,
      open,
      dismissed,
      stable,
      expectedCalls,
      expectedModel,
    ) => {
      const before = { findingId: "previous", occurrenceId: "old" };
      const after = {
        findingId: stable ? "previous" : "new",
        occurrenceId: "new",
      };
      let calls = 0;
      const model = fakeCodex({ matches: [], uncertain: [] });
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: open ? [before] : [],
        falsePositives: dismissed
          ? [{ findingId: "previous", sourceScanId: "prior" }]
          : [],
        findings: [after],
        async workbench(args) {
          calls += 1;
          return args[0] === "list-unmatched-scan-pairs"
            ? {
                batches: [
                  {
                    afterScanId: "current",
                    afterFindings: [after],
                    beforeScans: [{ scanId: "prior", findings: [before] }],
                  },
                ],
              }
            : {};
        },
        matchFindings: (input, options) =>
          matchScanFindings(input, { ...options, codex: model.codex }),
      });
      expect(calls).toBe(expectedCalls);
      expect(model.calls.prompt !== undefined).toBe(expectedModel);
    },
  );

  test.each(["split", "combined", "confirmed alias"] as const)(
    "retains known identities when a later finding is %s",
    async (scenario) => {
      const oldA = { findingId: "identity-a", occurrenceId: "old-a" };
      const oldB = { findingId: "identity-b", occurrenceId: "old-b" };
      const newA = { findingId: "identity-a", occurrenceId: "new-a" };
      const newB = { findingId: "identity-b", occurrenceId: "new-b" };
      const before = scenario === "combined" ? [oldA, oldB] : [oldA];
      const after =
        scenario === "split"
          ? [newA, newB]
          : scenario === "combined"
            ? [newA]
            : [newB];
      const knownFindingGroups =
        scenario === "confirmed alias"
          ? [["identity-a", "identity-b"]]
          : undefined;
      const model = fakeCodex({
        matches: [
          {
            beforeOccurrenceIds: before.map(({ occurrenceId }) => occurrenceId),
            afterOccurrenceIds: after.map(({ occurrenceId }) => occurrenceId),
            confidence: "high",
            reason: "The scan split or combined the same defective control.",
          },
        ],
        uncertain: [],
      });
      const saved: ScanComparisonResult[] = [];
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: before,
        falsePositives: [],
        findings: after,
        async workbench(args, commandInput) {
          if (args[0] === "list-unmatched-scan-pairs") {
            return {
              batches: [
                {
                  afterScanId: "current",
                  afterFindings: after,
                  beforeScans: [{ scanId: "prior", findings: before }],
                  knownFindingGroups,
                },
              ],
            };
          }
          saved.push(JSON.parse(commandInput!) as ScanComparisonResult);
          return {};
        },
        async matchFindings(input, options) {
          expect(input).toEqual({
            before,
            after,
            ...(knownFindingGroups === undefined ? {} : { knownFindingGroups }),
          });
          return await matchScanFindings(input, {
            ...options,
            codex: model.codex,
          });
        },
      });
      expect(model.calls.prompt !== undefined).toBe(
        scenario !== "confirmed alias",
      );
      expect(saved).toEqual([
        {
          matches: [
            expect.objectContaining({
              beforeOccurrenceIds: before.map(
                ({ occurrenceId }) => occurrenceId,
              ),
              afterOccurrenceIds: after.map(({ occurrenceId }) => occurrenceId),
            }),
          ],
          uncertain: [],
        },
      ]);
    },
  );

  test.each(["new", "resolved", "split", "combined"] as const)(
    "preserves deterministic matches while reconciling a %s issue",
    async (scenario) => {
      const oldA = { findingId: "identity-a", occurrenceId: "old-a" };
      const oldB = { findingId: "identity-b", occurrenceId: "old-b" };
      const newA = { findingId: "identity-a", occurrenceId: "new-a" };
      const newB = { findingId: "identity-b", occurrenceId: "new-b" };
      const before =
        scenario === "resolved" || scenario === "combined"
          ? [oldA, oldB]
          : [oldA];
      const after =
        scenario === "new" || scenario === "split" ? [newA, newB] : [newA];
      const extendsKnown = scenario === "split" || scenario === "combined";
      const saved: ScanComparisonResult[] = [];
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: before,
        falsePositives: [],
        findings: after,
        async workbench(args, commandInput) {
          if (args[0] === "list-unmatched-scan-pairs")
            return {
              batches: [
                {
                  afterScanId: "current",
                  afterFindings: after,
                  beforeScans: [{ scanId: "prior", findings: before }],
                },
              ],
            };
          saved.push(JSON.parse(commandInput!) as ScanComparisonResult);
          return {};
        },
        async matchFindings(input, options) {
          const response = {
            matches: extendsKnown
              ? [
                  {
                    beforeOccurrenceIds: [
                      scenario === "split"
                        ? oldA.occurrenceId
                        : oldB.occurrenceId,
                    ],
                    afterOccurrenceIds: [
                      scenario === "split"
                        ? newB.occurrenceId
                        : newA.occurrenceId,
                    ],
                    confidence: "high",
                    reason: "The same control was split or combined.",
                  },
                ]
              : [],
            uncertain: extendsKnown
              ? []
              : [
                  {
                    beforeOccurrenceId: oldA.occurrenceId,
                    afterOccurrenceId: newA.occurrenceId,
                    reason: "The model omitted the proven identity.",
                  },
                ],
            related:
              scenario === "resolved"
                ? []
                : [
                    {
                      beforeOccurrenceId: oldA.occurrenceId,
                      afterOccurrenceId:
                        scenario === "new"
                          ? newB.occurrenceId
                          : newA.occurrenceId,
                      reason: "A related control.",
                    },
                  ],
          };
          return await matchScanFindings(input, {
            ...options,
            codex: fakeCodex(response).codex,
          });
        },
      });
      expect(saved).toHaveLength(1);
      expect(saved[0]!.matches).toHaveLength(1);
      expect(new Set(saved[0]!.matches[0]!.beforeOccurrenceIds)).toEqual(
        new Set(
          (extendsKnown ? before : [oldA]).map(
            ({ occurrenceId }) => occurrenceId,
          ),
        ),
      );
      expect(new Set(saved[0]!.matches[0]!.afterOccurrenceIds)).toEqual(
        new Set(
          (extendsKnown ? after : [newA]).map(
            ({ occurrenceId }) => occurrenceId,
          ),
        ),
      );
      expect(saved[0]!.uncertain).toEqual([]);
      expect(saved[0]!.related).toHaveLength(scenario === "new" ? 1 : 0);
    },
  );

  test("rejects malformed model JSON", async () => {
    const { codex } = fakeCodex("not-json");
    await expect(
      matchScanFindings(
        { before: [finding("before")], after: [finding("after")] },
        { codex },
      ),
    ).rejects.toThrow("invalid JSON");
  });

  test("does not start Codex when either scan has no findings", async () => {
    const codex: NonNullable<ScanComparisonOptions["codex"]> = {
      startThread() {
        throw new Error("No model is needed.");
      },
    };
    for (const input of [
      { before: [], after: [finding("after")] },
      { before: [finding("before")], after: [] },
    ]) {
      expect(await matchScanFindings(input, { codex })).toEqual({
        matches: [],
        uncertain: [],
      });
    }
  });

  test.each([
    ["empty", { before: [finding(" ")], after: [] }],
    [
      "same-scan duplicate",
      { before: [finding("duplicate"), finding("duplicate")], after: [] },
    ],
    [
      "cross-scan duplicate",
      {
        before: [finding("duplicate")],
        after: [finding("duplicate")],
      },
    ],
  ])("rejects %s occurrence IDs before matching", async (_, input) => {
    const codex: NonNullable<ScanComparisonOptions["codex"]> = {
      startThread() {
        throw new Error("No model should start for invalid input.");
      },
    };

    await expect(matchScanFindings(input, { codex })).rejects.toThrow(
      "must be nonempty and globally unique",
    );
  });

  test("allows cross-history uncertainty without relaxing two-scan matching", async () => {
    const input: ScanComparisonInput = {
      before: [
        { occurrenceId: "before-confirmed", findingId: "shared" },
        { occurrenceId: "before-uncertain", findingId: "other" },
      ],
      after: [{ occurrenceId: "after-shared", findingId: "shared" }],
    };
    const modelResponse = {
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: "before-uncertain",
          afterOccurrenceId: "after-shared",
          reason: "Uncertain in another historical scan.",
        },
      ],
    } satisfies ScanComparisonResult;

    await expect(
      matchScanFindings(input, { codex: fakeCodex(modelResponse).codex }),
    ).rejects.toThrow("invalid uncertain pair");
    const response = await matchScanFindings(input, {
      codex: fakeCodex(modelResponse).codex,
      allowHistoricalUncertainty: true,
    });
    expect(response).toEqual({
      matches: [
        {
          beforeOccurrenceIds: ["before-confirmed"],
          afterOccurrenceIds: ["after-shared"],
          confidence: "high",
          reason:
            "The findings share a stable identity or a previously confirmed link.",
        },
      ],
      uncertain: modelResponse.uncertain,
    });
    expect(comparisonForScan(response, [input.before[0]!])).toEqual({
      matches: response.matches,
      uncertain: [],
    });
    expect(comparisonForScan(response, [input.before[1]!])).toEqual({
      matches: [],
      uncertain: modelResponse.uncertain,
    });
    expect(() => comparisonForScan(response, input.before)).toThrow(
      "conflicting confirmed and uncertain findings",
    );
  });

  const match = (beforeOccurrenceIds = ["before-1"]) => ({
    beforeOccurrenceIds,
    afterOccurrenceIds: ["after-1"],
    confidence: "high" as const,
    reason: "Same root cause.",
  });
  const uncertain = (afterOccurrenceId = "after-1") => ({
    beforeOccurrenceId: "before-1",
    afterOccurrenceId,
    reason: "Possible root cause.",
  });

  test.each([
    {
      label: "missing arrays",
      result: {},
      error: "invalid match result",
    },
    {
      label: "unexpected result fields",
      result: { matches: [], uncertain: [], unexpected: true },
      error: "invalid match result",
    },
    {
      label: "blank match reasons",
      result: { matches: [{ ...match(), reason: " " }], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "malformed related pairs",
      result: {
        matches: [],
        uncertain: [],
        related: [{ ...uncertain(), beforeOccurrenceId: 1 }],
      },
      error: "invalid match result",
    },
    {
      label: "low confidence",
      result: { matches: [{ ...match(), confidence: "low" }], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "empty groups",
      result: { matches: [match([])], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "invented occurrences",
      result: { matches: [match(["invented"])], uncertain: [] },
      error: "unknown before occurrence",
    },
    {
      label: "repeated occurrences",
      result: { matches: [match(), match()], uncertain: [] },
      error: "before occurrence more than once",
    },
    {
      label: "invented uncertain occurrences",
      result: { matches: [], uncertain: [uncertain("invented")] },
      error: "invalid uncertain pair",
    },
    {
      label: "uncertainty already matched with confidence",
      result: { matches: [match()], uncertain: [uncertain()] },
      error: "invalid uncertain pair",
    },
    {
      label: "duplicate uncertain pairs",
      result: { matches: [], uncertain: [uncertain(), uncertain()] },
      error: "duplicate uncertain pair",
    },
  ])("rejects $label", async ({ result, error }) => {
    const { codex } = fakeCodex(result);
    await expect(
      matchScanFindings(
        { before: [finding("before-1")], after: [finding("after-1")] },
        { codex },
      ),
    ).rejects.toThrow(error);
  });
});
