import {
  lstat,
  mkdir,
  readFile,
  readdir,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { delimiter, dirname, join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  SecurityPolicyRecoveryError,
  SecurityPolicyVerificationError,
} from "../src/errors.js";
import {
  securityPolicyDiff,
  type SecurityPolicyDraft,
  type SecurityPolicyOptions,
} from "../src/index.js";
import { formatSecurityPolicyText } from "../src/security-policy.js";
import type { PolicyPrompt } from "../src/security-policy-cli.js";
import { resolvePluginPython } from "../src/runtime.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import {
  POLICY,
  PYTHON,
  addPolicySubmodule,
  policyFixture,
  policyGit,
  policyPlugin,
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
    confirm: async () => {
      throw new Error("Unexpected confirmation");
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
      environment: { PYTHON },
    }),
    policyPrompt: options.prompt ?? prompt(),
    resolvePolicyPython: async () => PYTHON,
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
    expect(stdout.text()).toContain("--apply");
    expect(stdout.text()).toContain("--write");
    expect(stdout.text()).toContain("--headless");
    expect(stdout.text()).not.toContain("--outputDir");
    expect(stdout.text()).not.toContain("--write true");
    expect(stdout.text()).toContain(
      "--apply /path/outside/repository/policy --write",
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
          confirm: async () => false,
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

  test("does not choose credentials for automated, explicit, or saved policy requests", async () => {
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
      { args: ["--apply", f.outputDir] },
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
          confirm: async () => false,
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

  test("does not offer an interactive write if the diff preview fails", async () => {
    const f = await fixture();
    await f.generate();
    let asked = false;
    expect(
      await main(
        ["policy", "--apply", f.outputDir],
        capture(true).stream,
        {
          isTTY: true,
          write: () => {
            throw new Error("Preview output failed");
          },
        },
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            confirm: async () => {
              asked = true;
              return true;
            },
          }),
        }),
      ),
    ).toBe(2);
    expect(asked).toBe(false);
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

  test("offers source-backed questions and shows the exact diff before approval", async () => {
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
            confirm: async (_question, defaultValue) => {
              expect(defaultValue).toBe(false);
              expect(stderr.text()).toContain("--- /dev/null");
              expect(stderr.text()).toContain("+Requests must be authorized");
              expect(stderr.text()).toContain("Owner review:");
              expect(await readdir(f.repository)).toEqual([]);
              return true;
            },
          }),
        }),
      ),
    ).toBe(0);
    expect(asked).toBe(1);
    expect(await readFile(join(f.repository, "SECURITY.md"), "utf8")).toBe(
      POLICY,
    );
    expect(stderr.text()).toContain("Wrote and verified");
  });

  test("declining approval leaves the policy draft available", async () => {
    const f = await fixture();
    const draft = await f.generate();
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
            confirm: async () => false,
          }),
        }),
      ),
    ).toBe(0);
    expect(await readdir(f.repository)).toEqual([]);
    expect(stderr.text()).toContain("No repository files changed");
    expect(await readFile(draft.draftPath, "utf8")).toBe(POLICY);
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
            confirm: async () => false,
          }),
        }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain("+Last line  \n");
  });

  test("uses the selected plugin when approving a generated policy", async () => {
    const f = await fixture();
    const log = join(f.root, "resolver.log");
    const pluginPath = await policyPlugin(
      f.root,
      [
        "import os, pathlib",
        "with pathlib.Path(os.environ['POLICY_TEST_LOG']).open('a') as output: output.write('used\\n')",
        "print('custom guidance')",
      ].join("\n"),
    );
    const draft = await f.generate({ pluginPath });
    const deps = policyDependencies(f, {
      draft,
      prompt: prompt({ isInteractive: () => true, confirm: async () => true }),
    });
    deps.environment = { ...deps.environment, POLICY_TEST_LOG: log };
    expect(
      await main(
        ["policy", "--plugin-path", pluginPath],
        capture(true).stream,
        capture(true).stream,
        deps,
      ),
    ).toBe(0);
    expect((await readFile(log, "utf8")).trimEnd().split(/\r?\n/u)).toEqual([
      "used",
      "used",
    ]);
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
  });

  test("applies a reviewed, edited saved draft without initializing Codex", async () => {
    const f = await fixture();
    await mkdir(join(f.repository, "component"));
    const draft = await f.generate({ path: "component" });
    const edited = `${POLICY}\nReviewed by the component owner.\n`;
    await writeFile(draft.draftPath, edited);
    const stdout = capture();
    const deps = policyDependencies(f);
    deps.createPolicySecurity = () => {
      throw new Error("Must not initialize Codex for --apply");
    };
    expect(
      await main(
        [
          "policy",
          ".",
          "--path",
          "component",
          "--apply",
          f.outputDir,
          "--write",
          "--json",
        ],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).status).toBe("written");
    expect(await readFile(draft.targetPath, "utf8")).toBe(edited);
  });

  test("reports the retained previous file after updating a policy", async () => {
    const f = await fixture();
    const original = "# Original policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["policy", "--apply", f.outputDir, "--write", "--json"],
        stdout.stream,
        stderr.stream,
        policyDependencies(f),
      ),
    ).toBe(0);
    const result = JSON.parse(stdout.text());
    expect(result.status).toBe("written");
    expect(dirname(result.recoveryPath)).toBe(f.outputDir);
    expect(stderr.text()).toContain(result.recoveryPath);
    expect(await readFile(result.recoveryPath, "utf8")).toBe(original);
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    expect(await readdir(f.repository)).toEqual(["SECURITY.md"]);
  });

  test("reports a written policy when verification fails after cancellation", async () => {
    const name =
      "reports a written policy when verification fails after cancellation";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const pluginPath = await policyPlugin(
      f.root,
      [
        "import pathlib, sys",
        "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
        "if (root / 'SECURITY.md').exists(): raise SystemExit('synthetic verification failure')",
        "print('preflight passed')",
      ].join("\n"),
    );
    const draft = await f.generate({ pluginPath });
    const signals = new FakeSignals();
    const deps = policyDependencies(f, { signals });
    deps.createPolicySecurity = () => {
      throw new Error("Must not initialize Codex for --apply");
    };
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async (source: string, destination: string) => {
        await originalLink(source, destination);
        if (destination === draft.targetPath) signals.emit("SIGINT");
      },
    }));
    try {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          [
            "policy",
            "--apply",
            f.outputDir,
            "--plugin-path",
            pluginPath,
            "--write",
            "--json",
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(JSON.parse(stdout.text())).toMatchObject({
        status: "written_unverified",
        targetPath: draft.targetPath,
      });
      expect(stderr.text()).toContain("was written");
      expect(stderr.text()).not.toContain("canceled by Ctrl-C");
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
      for (const flags of [
        [],
        [
          "--plugin-path",
          pluginPath,
          "--python",
          join(f.root, "missing-python"),
        ],
      ]) {
        const failedRetry = capture();
        expect(
          await main(
            ["policy", "--apply", f.outputDir, "--write", "--json", ...flags],
            failedRetry.stream,
            capture().stream,
            {
              ...policyDependencies(f),
              resolvePolicyPython: resolvePluginPython,
            },
          ),
        ).toBe(2);
        expect(JSON.parse(failedRetry.text())).toMatchObject({
          status: "written_unverified",
          targetPath: draft.targetPath,
        });
      }
      await writeFile(
        join(pluginPath, "scripts", "resolve_security_md.py"),
        "print('resolver accepted the policy')\n",
      );
      const retry = capture();
      expect(
        await main(
          [
            "policy",
            "--apply",
            f.outputDir,
            "--plugin-path",
            pluginPath,
            "--write",
            "--json",
          ],
          retry.stream,
          capture().stream,
          policyDependencies(f),
        ),
      ).toBe(0);
      expect(JSON.parse(retry.text()).status).toBe("unchanged");
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
      }));
    }
  });

  test("rejects writing an unseen model-generated policy", async () => {
    const f = await fixture();
    const stderr = capture();
    let generated = false;
    expect(
      await main(
        ["policy", "--write"],
        capture().stream,
        stderr.stream,
        policyDependencies(f, {
          onGenerate: () => {
            generated = true;
          },
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("--write requires --apply");
    expect(generated).toBe(false);
  });

  test("does not silently ignore generation options when applying a saved draft", async () => {
    const f = await fixture();
    const deps = policyDependencies(f);
    deps.createPolicySecurity = () => {
      throw new Error("Must not initialize Codex for --apply");
    };
    for (const option of [
      ["--model", "gpt-5.6-terra"],
      ["--auth", "chatgpt"],
      ["--provider", "fireworks"],
      ["--output-dir", f.outputDir],
    ]) {
      const stderr = capture();
      expect(
        await main(
          ["policy", "--apply", f.outputDir, ...option],
          capture().stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toContain("generation options");
    }
  });

  test("preflights without generation or Python discovery", async () => {
    const f = await fixture();
    const stdout = capture();
    const deps = policyDependencies(f, {
      onGenerate: () => {
        throw new Error("Must not generate");
      },
    });
    deps.resolvePolicyPython = async () => {
      throw new Error("Must not resolve Python during preflight");
    };
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

  test("protects enclosing checkouts during CLI Python discovery", async () => {
    const f = await fixture();
    policyGit(f.repository, "init", "--quiet");
    const nested = await addPolicySubmodule(
      f.repository,
      join(f.root, "submodule-source"),
    );
    await f.generate({ path: "services/api" });
    const protectedRoots: (string | undefined)[] = [];
    const deps = {
      ...policyDependencies(f),
      resolvePolicyPython: async (
        options: Parameters<typeof resolvePluginPython>[0],
      ) => {
        protectedRoots.push(options?.protectedRoot);
        return PYTHON;
      },
    };
    for (const [repository, path] of [
      [f.repository, "services/api"],
      [nested, "."],
    ] as const) {
      expect(
        await main(
          [
            "policy",
            repository,
            "--path",
            path,
            "--apply",
            f.outputDir,
            "--json",
          ],
          capture().stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
    }
    expect(protectedRoots).toEqual([f.repository, f.repository]);
    await expect(lstat(join(nested, "SECURITY.md"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  test.skipIf(process.platform === "win32")(
    "does not run an enclosing checkout's Python shim during preview",
    async () => {
      const f = await fixture();
      policyGit(f.repository, "init", "--quiet");
      const nested = await addPolicySubmodule(
        f.repository,
        join(f.root, "submodule-source"),
      );
      await f.generate({ path: "services/api" });
      const unsafeBin = join(f.repository, ".venv", "bin");
      const trustedBin = join(f.root, "trusted-bin");
      const unsafePython = join(unsafeBin, "python3");
      await mkdir(unsafeBin, { recursive: true });
      await mkdir(trustedBin);
      await writeFile(
        unsafePython,
        '#!/bin/sh\nprintf executed > "$0.executed"\nprintf "codex-security-python-ok\\n"\n',
        { mode: 0o700 },
      );
      await symlink(PYTHON, join(trustedBin, "python3"), "file");
      for (const explicit of [false, true]) {
        const stdout = capture();
        const deps = {
          ...policyDependencies(f),
          environment: {
            PATH: [unsafeBin, trustedBin].join(delimiter),
            ...(explicit ? { PYTHON: unsafePython } : {}),
          },
          resolvePolicyPython: async (
            options: Parameters<typeof resolvePluginPython>[0],
          ) =>
            await resolvePluginPython({ ...options, managedRuntimeRoots: [] }),
        };
        const code = await main(
          ["policy", nested, "--apply", f.outputDir, "--json", "--full-output"],
          stdout.stream,
          capture().stream,
          deps,
        );
        expect(code).toBe(explicit ? 2 : 0);
        expect(JSON.parse(stdout.text()).ok).toBe(!explicit);
        await expect(lstat(`${unsafePython}.executed`)).rejects.toMatchObject({
          code: "ENOENT",
        });
      }
      await expect(lstat(join(nested, "SECURITY.md"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

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
      [["policy", "--write"], "--write requires --apply"],
      [
        ["policy", "--apply", f.outputDir, "--model", "synthetic-model"],
        "--apply cannot be combined",
      ],
      [["policy", "--path"], "Missing value"],
      [["policy", "--path", "--write"], "Missing value"],
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

  test("preserves recovery records and useful sanitized error causes", async () => {
    const f = await fixture();
    const targetPath = join(f.repository, "SECURITY.md");
    const recoveryPath = join(f.outputDir, "recovery-SECURITY.md");
    for (const [cause, diagnostic] of [
      [
        new Error("synthetic resolver unavailable"),
        "synthetic resolver unavailable",
      ],
      [new Error("api_key=synthetic-test-value"), "[redacted]"],
    ] as const) {
      for (const [error, status] of [
        [
          new SecurityPolicyVerificationError(targetPath, {
            recoveryPath,
            cause,
          }),
          "written_unverified",
        ],
        [
          new SecurityPolicyRecoveryError(targetPath, recoveryPath, { cause }),
          "recovery_required",
        ],
      ] as const) {
        const deps = policyDependencies(f, {
          onGenerate: () => {
            throw error;
          },
        });
        for (const fullOutput of [false, true]) {
          const stdout = capture();
          const stderr = capture();
          expect(
            await main(
              ["policy", "--json", ...(fullOutput ? ["--full-output"] : [])],
              stdout.stream,
              stderr.stream,
              deps,
            ),
          ).toBe(2);
          expect(stderr.text()).toContain(diagnostic);
          expect(stdout.text() + stderr.text()).not.toContain(
            "synthetic-test-value",
          );
          const result = JSON.parse(stdout.text());
          if (fullOutput) {
            expect(result).toMatchObject({
              ok: false,
              error: { code: "POLICY_FAILED", message: error.message },
            });
            expect(result.error.message).toContain(diagnostic);
            expect(result).not.toHaveProperty("data");
          } else {
            expect(result).toMatchObject({ status, targetPath, recoveryPath });
          }
        }
      }
    }
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

  test("keeps the written and previous files after a full-output verification error", async () => {
    const f = await fixture();
    const original = "# Original policy\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const pluginPath = await policyPlugin(
      f.root,
      [
        "import pathlib, sys",
        "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
        "if (root / 'SECURITY.md').read_text() != '# Original policy\\n': raise SystemExit('synthetic verification failure')",
        "print('preflight passed')",
      ].join("\n"),
    );
    const draft = await f.generate({ pluginPath });
    const stdout = capture();
    expect(
      await main(
        [
          "policy",
          "--apply",
          f.outputDir,
          "--plugin-path",
          pluginPath,
          "--write",
          "--json",
          "--full-output",
        ],
        stdout.stream,
        capture().stream,
        policyDependencies(f),
      ),
    ).toBe(2);
    const result = JSON.parse(stdout.text());
    expect(result).toMatchObject({
      ok: false,
      error: { code: "POLICY_FAILED" },
    });
    expect(result.error.message).toContain(draft.targetPath);
    const recovery = (await readdir(f.outputDir)).find((name) =>
      name.startsWith("recovery-SECURITY-"),
    );
    expect(recovery).toBeDefined();
    const recoveryPath = join(f.outputDir, recovery!);
    expect(result.error.message).toContain(recoveryPath);
    expect(await readFile(recoveryPath, "utf8")).toBe(original);
    expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
  });

  test("reports an unchanged saved policy without starting Codex or Python", async () => {
    for (const alreadyApplied of [false, true]) {
      const f = await fixture();
      const target = join(f.repository, "SECURITY.md");
      if (!alreadyApplied) await writeFile(target, POLICY);
      await f.generate();
      if (alreadyApplied) await writeFile(target, POLICY);
      const stdout = capture();
      const deps = policyDependencies(f);
      deps.createPolicySecurity = () => {
        throw new Error("Must not initialize Codex for --apply");
      };
      deps.resolvePolicyPython = async () => {
        throw new Error("Must not resolve Python for an unchanged preview");
      };
      expect(
        await main(
          [
            "policy",
            "--apply",
            f.outputDir,
            ...(alreadyApplied ? [] : ["--write"]),
            "--python",
            "missing-python",
            "--json",
          ],
          stdout.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text()).status).toBe("unchanged");
      expect(await readFile(target, "utf8")).toBe(POLICY);
    }
  });

  test("does not report an unchanged policy as verified when its scope changed", async () => {
    const f = await fixture();
    const component = join(f.repository, "component");
    const target = join(component, "SECURITY.md");
    await mkdir(component);
    await writeFile(target, POLICY);
    await f.generate({ path: "component" });
    const alias = join(f.repository, "sibling", "SECURITY.md");
    await mkdir(dirname(alias));
    await symlink(target, alias, "file");

    const stdout = capture();
    const stderr = capture();
    const deps = policyDependencies(f);
    deps.createPolicySecurity = () => {
      throw new Error("Must not initialize Codex for --apply");
    };
    deps.resolvePolicyPython = async () => {
      throw new Error("Must not resolve Python for an unchanged draft");
    };

    expect(
      await main(
        ["policy", "--path", "component", "--apply", f.outputDir, "--write"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("outside the selected component");
    expect(stdout.text()).not.toContain("Verified");
    expect(await readFile(target, "utf8")).toBe(POLICY);
  });

  test("does not overwrite source edited during the confirmation", async () => {
    const f = await fixture();
    const draft = await f.generate();
    const stderr = capture(true);
    expect(
      await main(
        ["policy", "--apply", f.outputDir],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            confirm: async () => {
              await writeFile(draft.targetPath, "# Concurrent change\n");
              return true;
            },
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("changed after");
    expect(await readFile(draft.targetPath, "utf8")).toBe(
      "# Concurrent change\n",
    );
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
        ["policy", "--path", scope, "--apply", f.outputDir, "--write"],
        capture().stream,
        stderr.stream,
        policyDependencies(f),
      ),
    ).toBe(0);
    expect(stderr.text()).not.toContain("\u001b");
    expect(stderr.text()).not.toMatch(/\p{Bidi_Control}/u);
    expect(stderr.text()).toContain("\\u001b[2J");
    for (const character of controls)
      expect(stderr.text()).toContain(
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
      );
    expect(await readFile(draft.targetPath, "utf8")).toBe(controlled);
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

  test("lets a later interrupt escape post-write verification", async () => {
    const name = "lets a later interrupt escape post-write verification";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const draft = await f.generate();
    const signals = new FakeSignals();
    const forced: string[] = [];
    let now = 0;
    const deps = policyDependencies(f, { signals });
    deps.now = () => now;
    deps.forceExit = (signal) => {
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
      forced.push(signal);
    };
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async (source: string, destination: string) => {
        await originalLink(source, destination);
        if (destination !== draft.targetPath) return;
        signals.emit("SIGINT");
        signals.emit("SIGINT");
        expect(forced).toEqual([]);
        now = 1_000;
        signals.emit("SIGINT");
      },
    }));
    try {
      const stderr = capture();
      expect(
        await main(
          ["policy", "--apply", f.outputDir, "--write", "--json"],
          capture().stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(forced).toEqual(["SIGINT"]);
      expect(stderr.text()).toContain("recovery files before retrying");
      expect(await readFile(draft.targetPath, "utf8")).toBe(POLICY);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
      }));
    }
  });

  test("reports recovery paths even when a conflict also receives cancellation", async () => {
    const name =
      "reports recovery paths even when a conflict also receives cancellation";
    if (runTestInSubprocess(import.meta.path, name)) return;
    const f = await fixture();
    const original = "# Original policy\n";
    const concurrent = "# Concurrent save\n";
    await writeFile(join(f.repository, "SECURITY.md"), original);
    const draft = await f.generate();
    const signals = new FakeSignals();
    const originalLink = fsPromises.link;
    mock.module("node:fs/promises", () => ({
      ...fsPromises,
      link: async (source: string, destination: string) => {
        if (destination === draft.targetPath && source.endsWith(".tmp")) {
          await writeFile(destination, concurrent);
          signals.emit("SIGINT");
        }
        await originalLink(source, destination);
      },
    }));
    try {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["policy", "--apply", f.outputDir, "--write", "--json"],
          stdout.stream,
          stderr.stream,
          policyDependencies(f, { signals }),
        ),
      ).toBe(2);
      const result = JSON.parse(stdout.text());
      expect(result.status).toBe("recovery_required");
      expect(result.targetPath).toBe(draft.targetPath);
      expect(stderr.text()).toContain(result.recoveryPath);
      expect(await readFile(result.recoveryPath, "utf8")).toBe(original);
      expect(await readFile(draft.targetPath, "utf8")).toBe(concurrent);
    } finally {
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        link: originalLink,
      }));
    }
  });

  test("cancels a pending review prompt on SIGTERM", async () => {
    const f = await fixture();
    await f.generate();
    const signals = new FakeSignals();
    expect(
      await main(
        ["policy", "--apply", f.outputDir],
        capture(true).stream,
        capture(true).stream,
        policyDependencies(f, {
          signals,
          prompt: prompt({
            isInteractive: () => true,
            confirm: async (_question, _defaultValue, signal) => {
              expect(signal).toBeDefined();
              signals.emit("SIGTERM");
              signal!.throwIfAborted();
              return true;
            },
          }),
        }),
      ),
    ).toBe(143);
    expect(await readdir(f.repository)).toEqual([]);
  });

  test("treats Inquirer's Ctrl-C error as cancellation without a process signal", async () => {
    const f = await fixture();
    await f.generate();
    const stderr = capture(true);
    expect(
      await main(
        ["policy", "--apply", f.outputDir],
        capture(true).stream,
        stderr.stream,
        policyDependencies(f, {
          prompt: prompt({
            isInteractive: () => true,
            confirm: async () => {
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
