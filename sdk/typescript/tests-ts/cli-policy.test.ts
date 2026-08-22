import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  securityPolicyDiff,
  type SecurityPolicyDraft,
  type SecurityPolicyOptions,
} from "../src/index.js";
import { formatSecurityPolicyText } from "../src/security-policy.js";
import type { PolicyPrompt } from "../src/security-policy-cli.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import {
  POLICY,
  PYTHON,
  policyFixture,
  stageResult,
} from "./support/security-policy.js";

const fixtures: Awaited<ReturnType<typeof policyFixture>>[] = [];
async function fixture() {
  const f = await policyFixture();
  fixtures.push(f);
  return f;
}
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((f) => f.cleanup()));
});

function prompt(overrides: Partial<PolicyPrompt> = {}): PolicyPrompt {
  return {
    isInteractive: () => false,
    input: async () => {
      throw new Error("Unexpected input prompt");
    },
    ...overrides,
  };
}

function policyDependencies(
  f: Awaited<ReturnType<typeof policyFixture>>,
  options: {
    draft?: SecurityPolicyDraft;
    prompt?: PolicyPrompt;
    onGenerate?: (
      repository: string,
      options: SecurityPolicyOptions,
    ) => void | Promise<void>;
    onPreflight?: (
      repository: string,
      options: SecurityPolicyOptions,
    ) => void | Promise<void>;
    onClose?: () => void;
    onConfig?: (config: unknown) => void;
    signals?: FakeSignals;
  } = {},
) {
  return {
    ...dependencies({
      currentDirectory: f.repository,
      signals: options.signals,
    }),
    policyPrompt: options.prompt ?? prompt(),
    createPolicySecurity: (config: unknown) => {
      options.onConfig?.(config);
      return {
        generatePolicy: async (
          repository: string,
          generation: SecurityPolicyOptions,
        ) => {
          await options.onGenerate?.(repository, generation);
          generation.onOutputDirReady?.(f.outputDir);
          generation.onStage?.("architecture");
          generation.onStage?.("threat_model");
          generation.onStage?.("policy");
          return (
            options.draft ??
            (await f.generate({
              path: generation.path,
              answerQuestions: generation.answerQuestions,
            }))
          );
        },
        preflightPolicy: async (
          repository: string,
          generation: SecurityPolicyOptions,
        ) => {
          await options.onPreflight?.(repository, generation);
          return {
            repository: f.repository,
            scope: ".",
            targetPath: join(f.repository, "SECURITY.md"),
            outputDir: null,
            authentication: {
              method: "stored_credentials" as const,
              verified: false as const,
            },
            model: "gpt-5.6-sol",
            reasoningEffort: "xhigh",
          };
        },
        previewPolicy: async (
          draft: SecurityPolicyDraft,
          preview: { signal?: AbortSignal } = {},
        ) =>
          formatSecurityPolicyText(
            await securityPolicyDiff(draft, PYTHON, preview.signal),
            true,
          ),
        close: async () => {
          options.onClose?.();
        },
      };
    },
  };
}

describe("policy CLI", () => {
  test("documents the policy workflow in help", async () => {
    const stdout = capture();
    expect(
      await main(
        ["policy", "--help"],
        stdout.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("SECURITY.md");
    expect(stdout.text()).not.toContain("--apply");
    expect(stdout.text()).not.toContain("--write");
    expect(stdout.text()).toContain("--headless");
    expect(stdout.text()).not.toContain("--outputDir");
    expect(stdout.text()).not.toContain("--write true");
    expect(stdout.text()).toContain(
      "--headless --output-dir /path/outside/repository/policy --json",
    );
  });

  test("generates a headless draft with machine-readable paths and no source edits", async () => {
    const f = await fixture();
    const stdout = capture();
    const stderr = capture();
    let closed = false;
    let config: unknown;
    expect(
      await main(
        [
          "policy",
          ".",
          "--headless",
          "--model",
          "gpt-5.6-terra",
          "--effort",
          "high",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        policyDependencies(f, {
          onClose: () => {
            closed = true;
          },
          onConfig: (value) => {
            config = value;
          },
        }),
      ),
    ).toBe(0);
    const result = JSON.parse(stdout.text());
    expect(result.status).toBe("draft");
    expect(result.targetPath).toBe(join(f.repository, "SECURITY.md"));
    expect(result.threatModelPath).toBe(join(f.outputDir, "THREAT_MODEL.md"));
    expect(stderr.text()).toContain("[1/3]");
    expect(stderr.text()).not.toContain("+Requests must be authorized");
    expect(config).toMatchObject({
      codexOverrides: {
        model: "gpt-5.6-terra",
        model_reasoning_effort: "high",
      },
    });
    expect(await readdir(f.repository)).toEqual([]);
    expect(closed).toBe(true);
  });

  test("offers the scan credential chooser before interactive policy generation", async () => {
    const f = await fixture();
    const draft = await f.generate();
    for (const [source, selection] of [
      ["OPENAI_API_KEY", "chatgpt"],
      ["CODEX_API_KEY", "api-key"],
    ] as const) {
      let selected: SecurityPolicyOptions["auth"];
      let question = "";
      let choices: readonly { label: string; value: string }[] = [];
      const stderr = capture(true);
      const deps = policyDependencies(f, {
        draft,
        prompt: prompt({
          isInteractive: () => true,
        }),
        onGenerate: (_repository, options) => {
          selected = options.auth;
        },
      });
      deps.environment = { [source]: "synthetic-private-key" };
      deps.hasStoredChatGPTSignIn = async () => true;
      deps.scanAuthenticationPrompt = {
        isInteractive: () => true,
        select: async <Value extends string>(
          message: string,
          options: readonly { label: string; value: Value }[],
        ): Promise<Value> => {
          question = message;
          choices = options;
          return options.find((option) => option.value === selection)!.value;
        },
      };
      expect(
        await main(["policy"], capture(true).stream, stderr.stream, deps),
      ).toBe(0);
      expect(selected).toBe(selection);
      expect(question).toContain("policy generation");
      expect(choices.map((choice) => choice.value)).toEqual([
        "chatgpt",
        "api-key",
      ]);
      expect(stderr.text()).toContain(source);
      expect(stderr.text()).not.toContain("synthetic-private-key");
    }
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("does not choose credentials for automated, explicit policy requests", async () => {
    const f = await fixture();
    const draft = await f.generate();
    for (const scenario of [
      { args: ["--headless"] },
      { args: ["--json"] },
      { args: ["--format", "toon"] },
      { args: ["--dry-run"] },
      { args: ["--auth", "chatgpt"] },
      { args: ["--auth", "api-key"] },
      { args: ["--provider", "openrouter", "--model", "vendor/model"] },
      { args: [], ci: true },
      { args: [], stored: false },
      { args: [], key: false },
      { args: [], terminal: false },
      { args: [], inputInteractive: false },
    ]) {
      let choices = 0;
      const deps = policyDependencies(f, {
        draft,
        prompt: prompt({
          isInteractive: () => scenario.inputInteractive !== false,
        }),
      });
      deps.environment = {
        ...(scenario.key === false
          ? {}
          : { OPENAI_API_KEY: "synthetic-private-key" }),
        ...(scenario.ci ? { CI: "1" } : {}),
      };
      deps.hasStoredChatGPTSignIn = async () => scenario.stored !== false;
      deps.scanAuthenticationPrompt = {
        isInteractive: () => true,
        select: async <Value extends string>(
          _message: string,
          options: readonly { label: string; value: Value }[],
        ): Promise<Value> => {
          choices++;
          return options[0]!.value;
        },
      };
      expect(
        await main(
          ["policy", ...scenario.args],
          capture().stream,
          capture(scenario.terminal !== false).stream,
          deps,
        ),
      ).toBe(0);
      expect(choices).toBe(0);
    }
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("cancels credential selection before starting the policy runtime", async () => {
    for (const phase of ["status", "prompt"] as const) {
      const f = await fixture();
      const signals = new FakeSignals();
      let initialized = false;
      const deps = policyDependencies(f, {
        signals,
        prompt: prompt({ isInteractive: () => true }),
        onConfig: () => {
          initialized = true;
        },
      });
      deps.environment = { OPENAI_API_KEY: "synthetic-private-key" };
      deps.hasStoredChatGPTSignIn = async (signal) => {
        expect(signal).toBeDefined();
        if (phase === "status") {
          queueMicrotask(() => signals.emit("SIGTERM"));
          return await new Promise<boolean>(() => {});
        }
        return true;
      };
      deps.scanAuthenticationPrompt = {
        isInteractive: () => true,
        select: async <Value extends string>(
          _message: string,
          _options: readonly { label: string; value: Value }[],
          _presentation?: { header?: string },
          signal?: AbortSignal,
        ): Promise<Value> => {
          expect(signal).toBeDefined();
          queueMicrotask(() => signals.emit("SIGTERM"));
          return await new Promise<Value>(() => {});
        },
      };
      expect(
        await main(["policy"], capture().stream, capture(true).stream, deps),
      ).toBe(143);
      expect(initialized).toBe(false);
      expect(await readdir(f.outputDir)).toEqual([]);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    }
  });

  test("does not present a partial cost as the final estimate", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["policy", "--headless", "--json"],
        stdout.stream,
        stderr.stream,
        policyDependencies(f, {
          draft,
          onGenerate: (_repository, options) =>
            options.onCost?.({
              model: "synthetic-model",
              inputTokens: 1,
              cachedInputTokens: 0,
              cacheWriteInputTokens: 0,
              outputTokens: 1,
              estimatedUsd: 0.5,
            }),
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).cost).toBeNull();
    expect(stderr.text()).not.toContain("$0.50");
  });

  test("preserves a headless result when optional progress writes throw", async () => {
    const f = await fixture();
    const stdout = capture();
    expect(
      await main(
        ["policy", "--headless", "--json"],
        stdout.stream,
        {
          write: () => {
            throw new Error("Progress output failed");
          },
        },
        policyDependencies(f),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).status).toBe("draft");
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("preserves a completed draft when runtime cleanup fails", async () => {
    const f = await fixture();
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["policy", "--headless", "--json"],
        stdout.stream,
        stderr.stream,
        policyDependencies(f, {
          onClose: () => {
            throw new Error("synthetic cleanup failure");
          },
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).status).toBe("draft");
    expect(stderr.text()).toContain("Could not clean up the policy runtime");
  });

  test("isolates asynchronous progress stream errors", async () => {
    const f = await fixture();
    const stdout = capture();
    const stderr = new Writable({
      autoDestroy: false,
      write(_chunk, _encoding, callback) {
        queueMicrotask(() => callback(new Error("Progress output failed")));
      },
    });
    const failure = new Promise<Error>((resolve) =>
      stderr.once("error", resolve),
    );
    expect(
      await main(
        ["policy", "--headless", "--json"],
        stdout.stream,
        stderr,
        policyDependencies(f),
      ),
    ).toBe(0);
    await expect(failure).resolves.toMatchObject({
      message: "Progress output failed",
    });
    expect(JSON.parse(stdout.text()).status).toBe("draft");
  });

  test("reports a failed interactive preview without changing source", async () => {
    const f = await fixture();
    const draft = await f.generate();
    expect(
      await main(
        ["policy"],
        capture(true).stream,
        {
          isTTY: true,
          write: () => {
            throw new Error("Preview output failed");
          },
        },
        policyDependencies(f, {
          draft,
          prompt: prompt({ isInteractive: () => true }),
        }),
      ),
    ).toBe(2);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("honors cancellation while the interactive preview is backpressured", async () => {
    for (const [signal, exitCode] of [
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ] as const) {
      const f = await fixture();
      const draft = await f.generate();
      const signals = new FakeSignals();
      let interrupted = false;
      let closed = false;
      const stderr = Object.assign(
        new Writable({
          write(chunk, _encoding, callback) {
            if (!interrupted && String(chunk).includes("\nPolicy target:")) {
              interrupted = true;
              queueMicrotask(() => {
                signals.emit(signal);
                queueMicrotask(callback);
              });
            } else callback();
          },
        }),
        { isTTY: true },
      );
      expect(
        await main(
          ["policy"],
          capture(true).stream,
          stderr,
          policyDependencies(f, {
            draft,
            signals,
            prompt: prompt({ isInteractive: () => true }),
            onClose: () => {
              closed = true;
            },
          }),
        ),
      ).toBe(exitCode);
      expect(interrupted).toBe(true);
      expect(closed).toBe(true);
      expect(signals.listeners.get(signal)?.size).toBe(0);
      expect(await readdir(f.repository)).toEqual([]);
    }
  });

  test("asks owner questions and previews the exact draft without writing source", async () => {
    const f = await fixture();
    const stderr = capture(true);
    let asked = 0;
    expect(
      await main(
        ["policy"],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            input: async (question) => {
              asked++;
              expect(question).toContain("internet-facing");
              return "Private service";
            },
          }),
        }),
      ),
    ).toBe(0);
    expect(asked).toBe(1);
    expect(stderr.text()).toContain("--- /dev/null");
    expect(stderr.text()).toContain("+Requests must be authorized");
    expect(stderr.text()).toContain("Owner review:");
    expect(stderr.text()).toContain("No repository files changed");
    expect(await readFile(join(f.outputDir, "SECURITY.md"), "utf8")).toBe(
      POLICY,
    );
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("preserves significant trailing spaces in the proposed diff", async () => {
    const f = await fixture();
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy"
          ? { markdown: "# Policy\n\nLast line  \n" }
          : {}),
      }),
    });
    const stderr = capture(true);
    expect(
      await main(
        ["policy"],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          draft,
          prompt: prompt({
            isInteractive: () => true,
          }),
        }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain("+Last line  \n");
  });

  test("preflights without generation", async () => {
    const f = await fixture();
    const stdout = capture();
    const deps = policyDependencies(f, {
      onGenerate: () => {
        throw new Error("Must not generate");
      },
    });
    expect(
      await main(
        ["policy", "--dry-run", "--json"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).dryRun).toBe(true);
    expect(await readdir(f.outputDir)).toEqual([]);
  });

  test("propagates dry-run cancellation and never returns false success", async () => {
    for (const [signal, exitCode] of [
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ] as const) {
      for (const cooperative of [false, true]) {
        const f = await fixture();
        const signals = new FakeSignals();
        const stdout = capture();
        let closed = false;
        expect(
          await main(
            ["policy", "--dry-run", "--json"],
            stdout.stream,
            capture().stream,
            policyDependencies(f, {
              signals,
              onPreflight: (_repository, options) => {
                signals.emit(signal);
                expect(options.signal?.aborted).toBe(true);
                if (cooperative) options.signal!.throwIfAborted();
              },
              onClose: () => {
                closed = true;
              },
            }),
          ),
        ).toBe(exitCode);
        expect(stdout.text()).toBe("");
        expect(closed).toBe(true);
        expect(signals.listeners.get(signal)?.size).toBe(0);
        expect(await readdir(f.outputDir)).toEqual([]);
      }
    }
  });

  test("returns only policy Markdown on stdout in Markdown mode", async () => {
    const f = await fixture();
    const markdown = `${POLICY.trimEnd()}  `;
    const draft = await f.generate({
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy" ? { markdown } : {}),
      }),
    });
    const stdout = capture();
    expect(
      await main(
        ["policy", "--format", "md"],
        stdout.stream,
        capture().stream,
        policyDependencies(f, { draft }),
      ),
    ).toBe(0);
    expect(stdout.text()).toBe(markdown);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("returns policy metadata for explicit formats and filters without prompting", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const deps = policyDependencies(f, {
      draft,
      prompt: prompt({ isInteractive: () => true }),
      onGenerate: (_repository, options) =>
        expect(options.answerQuestions).toBeUndefined(),
    });
    for (const [args, marker] of [
      [["--json"], '"status": "draft"'],
      [["--format", "jsonl"], '"status":"draft"'],
      [["--format", "toon"], "status: draft"],
      [["--format=toon"], "status: draft"],
      [["--format", "yaml"], "status: draft"],
      [["--full-output"], "ok: true"],
      [["--filter-output", "status"], "draft"],
      [["--format", "md", "--filter-output", "status"], "draft"],
    ] as const) {
      const stdout = capture(true);
      const stderr = capture(true);
      expect(
        await main(["policy", ...args], stdout.stream, stderr.stream, deps),
      ).toBe(0);
      expect(stdout.text()).toContain(marker);
      expect(stderr.text()).not.toContain(
        draft.content.split("\n").filter(Boolean).at(-1)!,
      );
      expect(stderr.text()).not.toContain(draft.reviewNotes[0]!);
    }
    const stdout = capture();
    expect(
      await main(
        ["policy", "--json", "--full-output"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      ok: true,
      data: { status: "draft", draftPath: draft.draftPath },
    });
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("honors token transforms for policy metadata and Markdown", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const deps = policyDependencies(f, {
      draft,
      prompt: prompt({ isInteractive: () => true }),
    });
    for (const format of [[], ["--format", "md"]]) {
      for (const transform of [
        ["--token-count"],
        ["--token-limit", "4"],
        ["--token-offset", "1"],
        ["--token-offset", "1", "--token-limit", "4"],
      ]) {
        const stdout = capture();
        const stderr = capture();
        expect(
          await main(
            ["policy", ...format, ...transform],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(0);
        expect(stderr.text()).not.toContain(
          draft.content.split("\n").filter(Boolean).at(-1)!,
        );
        expect(stderr.text()).not.toContain(draft.reviewNotes[0]!);
        if (transform[0] === "--token-count") {
          expect(stdout.text().trim()).toMatch(/^\d+$/u);
          expect(Number(stdout.text())).toBeGreaterThan(0);
        } else {
          expect(stdout.text()).toContain("[truncated: showing tokens ");
          expect(stdout.text()).not.toContain(POLICY);
        }
      }
    }
    const stdout = capture();
    expect(
      await main(
        ["policy", "--format", "md", "--full-output"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("## data");
    expect(stdout.text()).toContain(POLICY.trim());
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("renders TOON metadata safely while preserving JSON and Markdown", async () => {
    const f = await fixture();
    const scope = "component\u202ename";
    const note = "Review\u202ethis\u001b[2J";
    const content = `${POLICY}\n${note}\n`;
    await mkdir(join(f.repository, scope));
    const draft = await f.generate({
      path: scope,
      run: async (stage) => ({
        ...stageResult(stage),
        ...(stage === "policy"
          ? { markdown: content, reviewNotes: [note] }
          : {}),
      }),
    });
    const deps = policyDependencies(f, { draft });
    const create = deps.createPolicySecurity;
    deps.createPolicySecurity = (config) => {
      const security = create(config);
      return {
        ...security,
        preflightPolicy: async (repository, options) => ({
          ...(await security.preflightPolicy(repository, options)),
          scope,
          targetPath: draft.targetPath,
        }),
      };
    };
    for (const args of [["--dry-run"], ["--format", "toon"]]) {
      const stdout = capture(true);
      expect(
        await main(["policy", ...args], stdout.stream, capture().stream, deps),
      ).toBe(0);
      expect(stdout.text()).not.toMatch(/[\u001b\p{Bidi_Control}]/u);
      expect(stdout.text()).toContain("\\u202e");
    }
    const json = capture();
    expect(
      await main(["policy", "--json"], json.stream, capture().stream, deps),
    ).toBe(0);
    expect(JSON.parse(json.text())).toMatchObject({
      scope,
      reviewNotes: expect.arrayContaining([note]),
    });
    const markdown = capture();
    expect(
      await main(
        ["policy", "--format", "md"],
        markdown.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(markdown.text()).toBe(content);
  });

  test("marks failed generation and cancellation envelopes as errors", async () => {
    const f = await fixture();
    for (const [signal, expectedExit] of [
      [undefined, 2],
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ] as const) {
      const signals = new FakeSignals();
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["policy", "--json", "--full-output"],
          stdout.stream,
          stderr.stream,
          policyDependencies(f, {
            signals,
            onGenerate: (_repository, options) => {
              if (signal !== undefined) {
                signals.emit(signal);
                options.signal!.throwIfAborted();
              }
              throw new Error("Synthetic generation failure");
            },
          }),
        ),
      ).toBe(expectedExit);
      const result = JSON.parse(stdout.text());
      expect(result).toMatchObject({
        ok: false,
        error: { code: "POLICY_FAILED" },
      });
      expect(result).not.toHaveProperty("data");
      expect(stderr.text()).toContain(result.error.message);
    }
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("keeps policy argument and schema errors in full-output stdout", async () => {
    const f = await fixture();
    let initialized = false;
    const deps = policyDependencies(f);
    deps.createPolicySecurity = () => {
      initialized = true;
      throw new Error("Validation must finish before initializing Codex");
    };
    for (const [args, message] of [
      [["policy", "--write"], "Unknown flag"],
      [["policy", "--path"], "Missing value"],
      [["policy", "--path", "--headless"], "Missing value"],
      [["policy", ".", "extra"], "Unexpected positional argument"],
      [["policy", "--unknown-policy-option"], "Unknown flag"],
      [["policy", "--max-cost", "0"], "Too small"],
    ] as const) {
      for (const leadingOutputFlags of [false, true]) {
        const flags = ["--json", "--full-output"];
        const stdout = capture();
        const stderr = capture();
        expect(
          await main(
            leadingOutputFlags ? [...flags, ...args] : [...args, ...flags],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
        const result = JSON.parse(stdout.text());
        expect(result.ok).toBe(false);
        expect(result.error.message).toContain(message);
        expect(stderr.text()).not.toContain('"ok": false');
      }
    }
    expect(initialized).toBe(false);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("returns a full-output error when policy setup fails", async () => {
    const f = await fixture();
    const deps = policyDependencies(f);
    deps.currentDirectory = () => {
      throw new Error("Working directory is unavailable");
    };
    const stdout = capture();
    expect(
      await main(
        ["policy", "--json", "--full-output"],
        stdout.stream,
        {
          write: () => {
            throw new Error("Diagnostic output failed");
          },
        },
        deps,
      ),
    ).toBe(2);
    expect(JSON.parse(stdout.text())).toMatchObject({
      ok: false,
      error: {
        code: "POLICY_FAILED",
        message: "Working directory is unavailable",
      },
    });
  });

  test("renders terminal controls visibly without changing reviewed bytes", async () => {
    const f = await fixture();
    const controls =
      "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069";
    const scope = `component${controls}name`;
    await mkdir(join(f.repository, scope));
    const draft = await f.generate({ path: scope });
    const controlled = `${POLICY}\nLiteral \u001b[2J text.${controls}\n`;
    await writeFile(draft.draftPath, controlled);
    const stderr = capture();
    expect(
      await main(
        ["policy", "--path", scope],
        capture().stream,
        stderr.stream,
        policyDependencies(f, { draft: { ...draft, content: controlled } }),
      ),
    ).toBe(0);
    expect(stderr.text()).not.toContain("\u001b");
    expect(stderr.text()).not.toMatch(/\p{Bidi_Control}/u);
    expect(stderr.text()).toContain("\\u001b[2J");
    for (const character of controls)
      expect(stderr.text()).toContain(
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
      );
    expect(await readFile(draft.draftPath, "utf8")).toBe(controlled);
    expect(await readdir(dirname(draft.targetPath))).toEqual([]);
  });

  test("returns the interrupt exit code and removes signal listeners", async () => {
    const f = await fixture();
    const signals = new FakeSignals();
    let closed = false;
    expect(
      await main(
        ["policy", "--headless"],
        capture().stream,
        capture().stream,
        policyDependencies(f, {
          signals,
          onClose: () => {
            closed = true;
          },
          onGenerate: (_repository, options) => {
            signals.emit("SIGINT");
            options.signal!.throwIfAborted();
          },
        }),
      ),
    ).toBe(130);
    expect(closed).toBe(true);
    expect(
      [...signals.listeners.values()].every(
        (listeners) => listeners.size === 0,
      ),
    ).toBe(true);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("treats Inquirer's Ctrl-C error as cancellation without a process signal", async () => {
    const f = await fixture();
    const stderr = capture(true);
    expect(
      await main(
        ["policy"],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            input: async () => {
              throw Object.assign(new Error("Prompt closed"), {
                name: "ExitPromptError",
              });
            },
          }),
        }),
      ),
    ).toBe(130);
    expect(stderr.text()).toContain("canceled by Ctrl-C");
    expect(await readdir(f.repository)).toEqual([]);
  });
});
