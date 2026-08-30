import {
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Codex,
  type CodexOptions,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { resolveCodexCommand, runCodexCommand } from "../src/runtime.js";
import {
  comparisonEnvironment,
  matchCompletedScan,
  matchScanFindings,
  matchScanFindingsInternal,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map(async (path) => {
      // Bun 1.3.13 ignores fs.rm's retry options.
      for (let attempt = 0; ; attempt++) {
        try {
          await rm(path, { recursive: true, force: true });
          return;
        } catch (error) {
          if (
            (error as NodeJS.ErrnoException).code !== "EBUSY" ||
            attempt === 10
          )
            throw error;
          await Bun.sleep(100 * (attempt + 1));
        }
      }
    }),
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
  test("uses comparison attribution for CLI comparison turns", async () => {
    const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
    await matchScanFindingsInternal(
      { before: [], after: [] },
      { codex },
      { surface: "cli" },
    );
    expect(calls.threadOptions?.threadSource).toBe("security_scan_comparison");
  });

  test("disables explicit and inherited MCP servers for read-only helper turns", async () => {
    const home = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(home);
    await writeFile(
      join(home, "config.toml"),
      '[mcp_servers.inherited]\ncommand = "synthetic-inherited"\n',
    );
    const executable = join(
      home,
      process.platform === "win32" ? "custom-codex.exe" : "custom-codex",
    );
    await copyFile(resolveCodexCommand({}).command, executable);
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: home,
      CODEX_CLI_PATH: executable,
      OPENAI_API_KEY: "synthetic-key",
    };
    const { codex } = fakeCodex({ matches: [], uncertain: [] });
    let config: CodexOptions["config"];
    let codexPath: string | undefined;
    const startThread = spyOn(
      Codex.prototype,
      "startThread",
    ).mockImplementation(function (this: Codex, options) {
      config = (this as unknown as { options: CodexOptions }).options.config;
      codexPath = (this as unknown as { options: CodexOptions }).options
        .codexPathOverride;
      return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
    });
    try {
      await matchScanFindings(
        { before: [], after: [] },
        {
          environment,
          workingDirectory: home,
          config: {
            codexOverrides: {
              mcp_servers: {
                synthetic: { command: "synthetic-integration", enabled: true },
              },
            },
          },
        },
      );
      expect(config?.["mcp_servers"]).toEqual({
        synthetic: { command: "synthetic-integration", enabled: false },
        inherited: { enabled: false },
      });
      expect(codexPath).toBe(executable);
      const effective = await runCodexCommand(
        resolveCodexCommand(environment),
        [
          "-C",
          home,
          "-c",
          'mcp_servers.synthetic.command="synthetic-integration"',
          ...Object.keys(config!["mcp_servers"]!).flatMap((name) => [
            "-c",
            `mcp_servers.${name}.enabled=false`,
          ]),
          "mcp",
          "list",
          "--json",
        ],
        environment,
      );
      expect(effective.success).toBe(true);
      expect(
        JSON.parse(effective.stdout).map(
          (server: { name: string; enabled: boolean }) => ({
            name: server.name,
            enabled: server.enabled,
          }),
        ),
      ).toEqual([
        { name: "inherited", enabled: false },
        { name: "synthetic", enabled: false },
      ]);
    } finally {
      startThread.mockRestore();
    }
  });

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
      CODEX_CLI_PATH: "/compatible-codex",
      CODEX_SAFETY_IDENTIFIER: "synthetic-user",
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
      threadSource: "security_scan_comparison",
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
      required: ["matches", "uncertain"],
    });
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

  test("uses the requested scan model and effort for component matching", async () => {
    const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
    const config = {
      codexOverrides: {
        model: "configured-model",
        model_reasoning_effort: "high",
        model_provider: "synthetic-provider",
      },
    };
    await matchScanFindings({ before: [], after: [] }, { config, codex });
    expect(calls.threadOptions).toMatchObject({
      model: "configured-model",
      modelReasoningEffort: "high",
      sandboxMode: "read-only",
      networkAccessEnabled: false,
    });
    await matchScanFindings(
      { before: [], after: [] },
      { config, codex, model: "explicit-model", reasoningEffort: "low" },
    );
    expect(calls.threadOptions).toMatchObject({
      model: "explicit-model",
      modelReasoningEffort: "low",
    });
  });

  test("matches open and dismissed findings from the same target", async () => {
    const open = { findingId: "open", occurrenceId: "old-open" };
    const dismissed = { findingId: "dismissed", occurrenceId: "old-dismissed" };
    const after = { findingId: "renamed", occurrenceId: "new-renamed" };
    const commands: Array<{ args: readonly string[]; input?: string }> = [];
    let input: ScanComparisonInput | undefined;
    await matchCompletedScan({
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
        return {
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
      },
    });
    expect(input).toEqual({ before: [open, dismissed], after: [after] });
    expect(commands.map(({ args: [command] }) => command)).toEqual([
      "list-unmatched-scan-pairs",
      "save-scan-comparison",
    ]);
    expect(commands[1]!.args.at(-1)).toBe("--matches-json-stdin");
    const saved = JSON.parse(commands[1]!.input!) as ScanComparisonResult;
    expect(
      saved.matches.map(({ beforeOccurrenceIds }) => beforeOccurrenceIds),
    ).toEqual([["old-dismissed"]]);
    expect(saved.uncertain).toEqual([]);
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
      let modelCalled = false;
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
        async matchFindings() {
          modelCalled = true;
          return { matches: [], uncertain: [] };
        },
      });
      expect(calls).toBe(expectedCalls);
      expect(modelCalled).toBe(expectedModel);
    },
  );

  test("rejects malformed model JSON", async () => {
    const { codex } = fakeCodex("not-json");
    await expect(
      matchScanFindings({ before: [], after: [] }, { codex }),
    ).rejects.toThrow("invalid JSON");
  });

  test("allows cross-history uncertainty without relaxing two-scan matching", async () => {
    const input: ScanComparisonInput = {
      before: [finding("before-confirmed"), finding("before-uncertain")],
      after: [finding("after-shared")],
    };
    const response = {
      matches: [
        {
          beforeOccurrenceIds: ["before-confirmed"],
          afterOccurrenceIds: ["after-shared"],
          confidence: "high",
          reason: "Confirmed in one historical scan.",
        },
      ],
      uncertain: [
        {
          beforeOccurrenceId: "before-uncertain",
          afterOccurrenceId: "after-shared",
          reason: "Uncertain in another historical scan.",
        },
      ],
    } satisfies ScanComparisonResult;

    await expect(
      matchScanFindings(input, { codex: fakeCodex(response).codex }),
    ).rejects.toThrow("invalid uncertain pair");
    expect(
      await matchScanFindings(input, {
        codex: fakeCodex(response).codex,
        allowHistoricalUncertainty: true,
      }),
    ).toEqual(response);
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
