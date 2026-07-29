import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ThreadOptions, TurnOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import {
  comparisonEnvironment,
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
  test("reuses managed keyring credentials without exposing environment API keys", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    let probedEnvironment: Record<string, string | undefined> | undefined;

    const environment = await comparisonEnvironment(
      {
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-key-must-not-be-used",
        CODEX_API_KEY: "synthetic-secondary-must-not-be-used",
      },
      async (_command, storedEnvironment) => {
        probedEnvironment = storedEnvironment;
        return {
          authenticated: true,
          details: "Logged in using ChatGPT",
        };
      },
    );

    expect(environment["CODEX_HOME"]).toBe(credentialHome);
    expect(environment["CODEX_SECURITY_STATE_DIR"]).toBe(stateDirectory);
    expect(environment["OPENAI_API_KEY"]).toBeUndefined();
    expect(environment["CODEX_API_KEY"]).toBeUndefined();
    expect(probedEnvironment?.["CODEX_HOME"]).toBe(credentialHome);
    expect(probedEnvironment?.["OPENAI_API_KEY"]).toBeUndefined();
    expect(probedEnvironment?.["CODEX_API_KEY"]).toBeUndefined();
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
