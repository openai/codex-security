import { execFileSync } from "node:child_process";
import {
  link,
  mkdir,
  readFile,
  readdir,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type {
  CodexOptions,
  ThreadEvent,
  ThreadOptions,
  TurnOptions,
} from "@openai/codex-sdk";
import Ajv, { type AnySchema } from "ajv";
import { afterEach, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import {
  CodexSecurity,
  InvalidTargetError,
  OutputDirectoryNotEmptyError,
  securityPolicyDiff,
  writeCodexConfig,
  type SecurityPolicyStage,
} from "../src/index.js";
import { preparedRuntime } from "./support/api-events.js";
import type { PluginPythonOptions } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  POLICY,
  PYTHON,
  addPolicySubmodule,
  policyFixture,
  policyGit,
  policyPlugin,
  stageResult,
} from "./support/security-policy.js";

const InternalSecurity = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
  runtimeOptions?: { surface: "cli" | "sdk" },
) => CodexSecurity;
const fixtures: Awaited<ReturnType<typeof policyFixture>>[] = [];
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((f) => f.cleanup()));
});

async function setup(
  options: {
    stream?: (
      stage: SecurityPolicyStage,
      signal: AbortSignal,
    ) => AsyncGenerator<ThreadEvent>;
    onPrepare?: () => void;
    onRevision?: () => Promise<void>;
    secureOutput?: (path: string) => Promise<void>;
    surface?: "cli" | "sdk";
    config?: Record<string, unknown>;
  } = {},
) {
  const f = await policyFixture();
  fixtures.push(f);
  const codexHome = join(f.root, "codex-home");
  await mkdir(codexHome);
  const runtime = preparedRuntime(codexHome);
  let configuration: CodexOptions | undefined;
  const threads: ThreadOptions[] = [];
  const prompts: string[] = [];
  const turns: TurnOptions[] = [];
  const pythonSelections: PluginPythonOptions[] = [];
  const stages: SecurityPolicyStage[] = [
    "architecture",
    "threat_model",
    "policy",
  ];
  const security = new InternalSecurity(
    options.config ?? {},
    {
      environment: { CODEX_SECURITY_STATE_DIR: join(f.root, "state") },
      prepareRuntime: async () => {
        options.onPrepare?.();
        return runtime;
      },
      resolvePluginPython: async (selection: PluginPythonOptions) => {
        pythonSelections.push(selection);
        return PYTHON;
      },
      requirePrivatePolicyOutputDirectory: async (path: string) => {
        await options.secureOutput?.(path);
      },
      repositoryRevision: async () => {
        await options.onRevision?.();
        return "synthetic-revision";
      },
      runWorkbench: async () => {
        throw new Error("Policy generation must not register a scan.");
      },
      createCodex: (config: CodexOptions) => {
        configuration = config;
        return {
          startThread: (threadOptions: ThreadOptions) => {
            const stage = stages[threads.length]!;
            threads.push(threadOptions);
            return {
              id: null,
              async runStreamed(prompt: string, turn: TurnOptions) {
                prompts.push(prompt);
                turns.push(turn);
                return {
                  events:
                    options.stream?.(stage, turn.signal!) ?? events(stage),
                };
              },
            };
          },
        };
      },
    },
    { surface: options.surface ?? "sdk" },
  );
  return {
    ...f,
    security,
    runtime,
    threads,
    prompts,
    turns,
    pythonSelections,
    configuration: () => configuration,
  };
}

async function* events(
  stage: SecurityPolicyStage,
  result = stageResult(stage),
): AsyncGenerator<ThreadEvent> {
  yield { type: "thread.started", thread_id: `policy-${stage}` };
  yield { type: "turn.started" };
  yield {
    type: "item.completed",
    item: {
      id: "result",
      type: "agent_message",
      text: JSON.stringify(result),
    },
  };
  yield {
    type: "turn.completed",
    usage: {
      input_tokens: 100,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      output_tokens: 10,
      reasoning_output_tokens: 0,
    },
  };
}

describe("CodexSecurity policy API", () => {
  test("requires private output before starting a policy turn", async () => {
    let announced = false;
    const secured: string[] = [];
    const f = await setup({
      secureOutput: async (path) => {
        secured.push(path);
        throw new Error("Policy output could not be made private");
      },
    });
    await expect(
      f.security.generatePolicy(f.repository, {
        outputDir: f.outputDir,
        onOutputDirReady: () => {
          announced = true;
        },
      }),
    ).rejects.toThrow("Policy output could not be made private");
    expect(secured).toEqual([f.outputDir]);
    expect(announced).toBe(false);
    expect(f.threads).toHaveLength(0);
    expect(await readdir(f.outputDir)).toEqual([]);
    await f.security.close();
  });

  test("keeps prompt data on one encoded line", async () => {
    const marker = "source\u0085line\u2028separator\u2029end";
    const scope = `component-${marker}`;
    const f = await setup({
      stream: async function* (stage) {
        yield* events(stage, {
          ...stageResult(stage),
          questions: [marker],
          reviewNotes: [marker],
        });
      },
    });
    await mkdir(join(f.repository, scope));
    await writeFile(join(f.repository, "SECURITY.md"), `# Policy\n${marker}\n`);
    const draft = await f.security.generatePolicy(f.repository, {
      path: scope,
      outputDir: f.outputDir,
      answerQuestions: async () => marker,
    });
    for (const prompt of f.prompts) {
      expect(prompt).not.toMatch(/[\u0085\u2028\u2029]/u);
      expect(prompt).toContain("source\\u0085line\\u2028separator\\u2029end");
    }
    expect(draft.reviewNotes).toContain(marker);
    await f.security.close();
  });

  test("uses the client's Python and renders preview controls visibly", async () => {
    const content = `${POLICY}\n\u001b]52;c;c3ludGhldGlj\u0007\u202eOwner note\n`;
    const f = await setup({
      config: { pythonPath: "configured-policy-python" },
      stream: async function* (stage) {
        yield* events(stage, {
          ...stageResult(stage),
          ...(stage === "policy" ? { markdown: content } : {}),
        });
      },
    });
    const draft = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
    });
    const preview = await f.security.previewPolicy(draft);
    expect(f.pythonSelections).toHaveLength(2);
    for (const selection of f.pythonSelections)
      expect(selection).toMatchObject({
        configuredPath: "configured-policy-python",
        protectedRoot: f.repository,
      });
    expect(preview).not.toMatch(/[\u001b\u0007\p{Bidi_Control}]/u);
    expect(preview).toContain("\\u001b]52;c;c3ludGhldGlj\\u0007\\u202e");
    expect(await securityPolicyDiff(draft, PYTHON)).toContain(
      "\u001b]52;c;c3ludGhldGlj\u0007\u202eOwner note",
    );
    expect(await readFile(draft.draftPath, "utf8")).toBe(content);
    expect(draft).not.toHaveProperty("pythonPath");
    await f.security.close();
  });

  test("preflights without runtime initialization or output creation", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    await mkdir(join(f.repository, "component"));
    const preflight = await f.security.preflightPolicy(f.repository, {
      path: "component",
      outputDir: f.outputDir,
    });
    expect(preflight.scope).toBe("component");
    expect(preflight.targetPath).toBe(
      join(f.repository, "component", "SECURITY.md"),
    );
    expect(preflight.model).toBe("gpt-5.6-sol");
    expect(prepared).toBe(false);
    expect(await readdir(f.outputDir)).toEqual([]);
    await f.security.close();
  });

  test("gives a usable remedy for a nonempty policy output directory", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    const previous = join(f.outputDir, "previous.md");
    await writeFile(previous, "Keep this draft.\n");
    for (const operation of [
      () =>
        f.security.preflightPolicy(f.repository, { outputDir: f.outputDir }),
      () => f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
    ]) {
      const error = await operation().catch((value: unknown) => value);
      expect(error).toBeInstanceOf(OutputDirectoryNotEmptyError);
      expect(String(error)).toContain("Choose a new or empty directory");
      expect(String(error)).not.toContain("--archive-existing");
    }
    expect(prepared).toBe(false);
    expect(await readFile(previous, "utf8")).toBe("Keep this draft.\n");
    await f.security.close();
  });

  test("rejects redirected Git roots before inspecting policy or starting Codex", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    execFileSync("git", ["init", "--quiet", f.repository]);
    execFileSync("git", [
      "-C",
      f.repository,
      "config",
      "core.worktree",
      f.root,
    ]);
    for (const operation of [
      () => f.security.preflightPolicy(f.repository),
      () => f.security.generatePolicy(f.repository),
    ])
      await expect(operation()).rejects.toThrow(
        "does not match the selected checkout",
      );
    expect(prepared).toBe(false);
    expect(f.threads).toHaveLength(0);
    expect(await readdir(f.outputDir)).toEqual([]);
    await f.security.close();
  });

  test("rejects Git metadata borrowed from another checkout before starting Codex", async () => {
    for (const kind of [
      "ordinary",
      "separate",
      "linked",
      "submodule",
      "unregistered-directory",
      "unregistered-gitfile",
    ]) {
      let prepared = false;
      const f = await setup({ onPrepare: () => (prepared = true) });
      const owner = join(f.root, "other-repository");
      await mkdir(owner);
      policyGit(
        owner,
        "init",
        "--quiet",
        ...(kind === "separate"
          ? ["--separate-git-dir", join(f.root, "other-git-data")]
          : []),
      );
      policyGit(owner, "commit", "--allow-empty", "--quiet", "-m", "initial");
      let checkout = owner;
      if (kind === "linked") {
        checkout = join(f.root, "other-worktree");
        policyGit(owner, "worktree", "add", "--quiet", "--detach", checkout);
      } else if (kind === "submodule") {
        checkout = await addPolicySubmodule(
          owner,
          join(f.root, "submodule-source"),
        );
      }
      let metadata = execFileSync(
        "git",
        ["-C", checkout, "rev-parse", "--absolute-git-dir"],
        { encoding: "utf8" },
      ).trim();
      if (kind.startsWith("unregistered-")) {
        const common = metadata;
        metadata = join(
          f.repository,
          kind === "unregistered-directory" ? ".git" : "git-data",
        );
        await mkdir(metadata);
        await writeFile(
          join(metadata, "HEAD"),
          await readFile(join(common, "HEAD")),
        );
        await writeFile(join(metadata, "commondir"), `${common}\n`);
        await writeFile(
          join(metadata, "gitdir"),
          `${join(f.repository, ".git")}\n`,
        );
      }
      if (kind !== "unregistered-directory")
        await writeFile(join(f.repository, ".git"), `gitdir: ${metadata}\n`);
      for (const operation of [
        () => f.security.preflightPolicy(f.repository),
        () => f.security.generatePolicy(f.repository),
      ])
        await expect(operation()).rejects.toThrow(InvalidTargetError);
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      expect(await readdir(f.outputDir)).toEqual([]);
      await f.security.close();
    }
  });

  test("rejects Git metadata added after policy validation", async () => {
    const f = await setup({
      secureOutput: async () => {
        const metadata = join(f.root, "late-git-data");
        policyGit(
          f.repository,
          "init",
          "--quiet",
          "--separate-git-dir",
          metadata,
        );
        policyGit(f.repository, "config", "core.worktree", f.repository);
      },
    });

    await expect(
      f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
    ).rejects.toThrow(InvalidTargetError);
    expect(f.threads).toHaveLength(0);
    await f.security.close();
  });

  test("rejects Git metadata targets before starting Codex", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    execFileSync("git", ["init", "--quiet", f.repository]);
    const options = { path: ".git/refs/heads", outputDir: f.outputDir };
    await expect(
      f.security.preflightPolicy(f.repository, options),
    ).rejects.toThrow("inside Git metadata");
    await expect(
      f.security.generatePolicy(f.repository, options),
    ).rejects.toThrow("inside Git metadata");
    expect(prepared).toBe(false);
    expect(await readdir(f.outputDir)).toEqual([]);
    expect(await readdir(join(f.repository, ".git", "refs", "heads"))).toEqual(
      [],
    );
    await f.security.close();
  });

  test("keeps submodule artifacts outside every enclosing checkout", async () => {
    let prepared = false;
    const f = await setup({
      onPrepare: () => {
        prepared = true;
      },
    });
    policyGit(f.repository, "init", "--quiet");
    const nested = await addPolicySubmodule(
      f.repository,
      join(f.root, "submodule-source"),
    );
    const inside = join(f.repository, "policy-artifacts");
    for (const [repository, path] of [
      [f.repository, "services/api"],
      [nested, "."],
    ] as const) {
      const options = { path, outputDir: inside };
      await expect(
        f.security.preflightPolicy(repository, options),
      ).rejects.toThrow("outside the protected scan root");
      await expect(
        f.security.generatePolicy(repository, options),
      ).rejects.toThrow("outside the protected scan root");
    }
    const stateInside = new InternalSecurity(
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: join(f.repository, "state") },
      },
    );
    await expect(stateInside.preflightPolicy(nested)).rejects.toThrow(
      "outside the protected scan root",
    );
    await stateInside.close();
    expect(prepared).toBe(false);
    expect(f.threads).toHaveLength(0);
    expect(await readdir(f.outputDir)).toEqual([]);
    await expect(readdir(inside)).rejects.toMatchObject({ code: "ENOENT" });
    const preflight = await f.security.preflightPolicy(nested, {
      outputDir: f.outputDir,
    });
    expect(preflight.repository).toBe(nested);
    expect(preflight.scope).toBe(".");
    const draft = await f.security.generatePolicy(f.repository, {
      path: "services/api",
      outputDir: f.outputDir,
    });
    expect(draft.repository).toBe(nested);
    expect(draft.outputDir).toBe(f.outputDir);
    expect(
      f.threads.every((thread) => thread.workingDirectory === f.outputDir),
    ).toBe(true);
    expect(f.configuration()?.env?.["CODEX_SECURITY_REPOSITORY"]).toBe(nested);
    await f.security.close();
  });

  test("keeps policy output, state and model reads out of external Git metadata", async () => {
    for (const kind of ["separate", "linked"]) {
      let prepared = false;
      const f = await setup({ onPrepare: () => (prepared = true) });
      let repository = f.repository;
      let common: string;
      if (kind === "separate") {
        common = join(f.root, "git-data");
        policyGit(repository, "init", "--quiet", "--separate-git-dir", common);
        policyGit(repository, "config", "core.worktree", repository);
      } else {
        policyGit(repository, "init", "--quiet");
        policyGit(
          repository,
          "commit",
          "--allow-empty",
          "--quiet",
          "-m",
          "initial",
        );
        common = join(repository, ".git");
        const linked = join(f.root, "linked-worktree");
        policyGit(repository, "worktree", "add", "--quiet", "--detach", linked);
        repository = linked;
      }
      const gitDirectory = execFileSync(
        "git",
        ["-C", repository, "rev-parse", "--absolute-git-dir"],
        { encoding: "utf8" },
      ).trim();
      for (const metadata of new Set([common, gitDirectory])) {
        const outputDir = join(metadata, "policy-artifacts");
        for (const operation of [
          () => f.security.preflightPolicy(repository, { outputDir }),
          () => f.security.generatePolicy(repository, { outputDir }),
        ])
          await expect(operation()).rejects.toThrow(
            "outside the protected scan root",
          );
        const state = new InternalSecurity(
          {},
          { environment: { CODEX_SECURITY_STATE_DIR: outputDir } },
        );
        await expect(state.preflightPolicy(repository)).rejects.toThrow(
          "outside the protected scan root",
        );
        await expect(state.generatePolicy(repository)).rejects.toThrow(
          "outside the protected scan root",
        );
        await state.close();
        await expect(readdir(outputDir)).rejects.toMatchObject({
          code: "ENOENT",
        });
      }
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      await f.security.generatePolicy(repository, { outputDir: f.outputDir });
      for (const thread of f.threads) {
        expect(thread.additionalDirectories).toContain(repository);
        expect(thread.additionalDirectories).not.toContain(common);
        expect(thread.additionalDirectories).not.toContain(gitDirectory);
      }
      await f.security.close();
    }
  });

  test("checks descendant policy links before starting Codex", async () => {
    for (const kind of [
      "root",
      "component",
      "component_sibling",
      "git_metadata",
      "reporting_directory",
    ]) {
      let prepared = false;
      const f = await setup({ onPrepare: () => (prepared = true) });
      policyGit(f.repository, "init", "--quiet");
      const scope = kind.startsWith("component") ? "component" : ".";
      const child = join(f.repository, scope, "child");
      await mkdir(child, { recursive: true });
      const outside = join(
        kind === "component_sibling" ? f.repository : f.root,
        "outside-policy.md",
      );
      await writeFile(outside, "# Private synthetic policy\n");
      if (kind === "reporting_directory") {
        const directory = join(f.root, "reporting");
        await mkdir(directory);
        await writeFile(join(directory, "SECURITY.md"), "# Reporting policy\n");
        await symlink(
          directory,
          join(f.repository, ".github"),
          process.platform === "win32" ? "junction" : "dir",
        );
      } else {
        await symlink(
          kind === "git_metadata"
            ? join(f.repository, ".git", "config")
            : outside,
          join(child, "SECURITY.md"),
          "file",
        );
      }
      const options = { path: scope, outputDir: f.outputDir };
      const message =
        kind === "git_metadata"
          ? "Git metadata"
          : kind === "component_sibling"
            ? "outside the selected component"
            : "outside the repository";
      await expect(
        f.security.preflightPolicy(f.repository, options),
      ).rejects.toThrow(message);
      await expect(
        f.security.generatePolicy(f.repository, options),
      ).rejects.toThrow(message);
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      expect(await readdir(f.outputDir)).toEqual([]);
      await f.security.close();
    }
  });

  test("rejects hard-linked policy evidence before starting Codex", async () => {
    for (const [scope, policyPath] of [
      [".", "SECURITY.md"],
      ["component", "SECURITY.md"],
      [".", "child/SECURITY.md"],
      [".", ".github/SECURITY.md"],
    ] as const) {
      let prepared = false;
      const f = await setup({ onPrepare: () => (prepared = true) });
      policyGit(f.repository, "init", "--quiet");
      const target = join(f.repository, policyPath);
      await mkdir(join(f.repository, scope), { recursive: true });
      await mkdir(dirname(target), { recursive: true });
      await link(join(f.repository, ".git", "config"), target);
      const options = { path: scope, outputDir: f.outputDir };
      await expect(
        f.security.preflightPolicy(f.repository, options),
      ).rejects.toThrow("hard-linked");
      await expect(
        f.security.generatePolicy(f.repository, options),
      ).rejects.toThrow("hard-linked");
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      expect(await readdir(f.outputDir)).toEqual([]);
      await f.security.close();
    }
  });

  test("validates descendant policy contents before starting Codex", async () => {
    for (const [content, message] of [
      [Buffer.alloc(1024 * 1024 + 1, "x"), "1 MiB"],
      [Buffer.from([0xff]), "UTF-8"],
    ] as const) {
      let prepared = false;
      const f = await setup({ onPrepare: () => (prepared = true) });
      const child = join(f.repository, "child");
      await mkdir(child);
      await writeFile(join(child, "SECURITY.md"), content);
      const options = { outputDir: f.outputDir };
      await expect(
        f.security.preflightPolicy(f.repository, options),
      ).rejects.toThrow(message);
      await expect(
        f.security.generatePolicy(f.repository, options),
      ).rejects.toThrow(message);
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      expect(await readdir(f.outputDir)).toEqual([]);
      await f.security.close();
    }
  });

  test.each(["path", "directory"])(
    "limits model reads to the selected component via %s",
    async (selection) => {
      const f = await setup();
      policyGit(f.repository, "init", "--quiet");
      const component = join(f.repository, "component");
      await mkdir(component);
      await writeFile(
        join(f.repository, "SECURITY.md"),
        "# Inherited guidance\n",
      );
      await writeFile(join(f.repository, "unrelated.txt"), "SYNTHETIC_SIBLING");
      await f.security.generatePolicy(
        selection === "path" ? f.repository : component,
        {
          ...(selection === "path" ? { path: "component" } : {}),
          outputDir: f.outputDir,
        },
      );
      for (const thread of f.threads) {
        expect(thread.additionalDirectories).toContain(component);
        expect(thread.additionalDirectories).not.toContain(f.repository);
      }
      expect(
        f.prompts.every((prompt) => prompt.includes("# Inherited guidance")),
      ).toBe(true);
      expect(f.prompts.join("\n")).not.toContain("SYNTHETIC_SIBLING");
      await f.security.close();
    },
  );

  test("gives Codex only the checked, host-resolved policy inventory", async () => {
    const f = await setup();
    policyGit(f.repository, "init", "--quiet");
    const component = join(f.repository, "component");
    await mkdir(join(component, "child"), { recursive: true });
    policyGit(join(component, "child"), "init", "--quiet");
    const ownerPolicy = join(component, "owner-policy.md");
    await writeFile(ownerPolicy, "# Owner policy\n");
    await symlink(ownerPolicy, join(component, "child", "SECURITY.md"), "file");
    const outside = join(f.root, "outside");
    await mkdir(outside);
    await writeFile(
      join(outside, "SECURITY.md"),
      "# Unlisted synthetic policy\n",
    );
    await symlink(
      outside,
      join(component, "linked-directory"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await f.security.generatePolicy(f.repository, {
      path: "component",
      outputDir: f.outputDir,
    });
    expect(f.prompts[0]).toContain('["component/child/SECURITY.md"]');
    const policyScope = join(component, "child");
    expect(f.prompts[0]).toContain("# Owner policy");
    expect(f.threads[0]!.additionalDirectories).not.toContain(f.repository);
    expect(
      execFileSync(
        PYTHON,
        [
          join(PLUGIN_ROOT, "scripts", "resolve_security_md.py"),
          "--repo",
          f.repository,
          "--scope",
          policyScope,
        ],
        { encoding: "utf8" },
      ),
    ).toContain("# Owner policy");
    expect(f.prompts[0]).not.toContain("linked-directory/SECURITY.md");
    expect(f.prompts[0]).not.toContain("Unlisted synthetic policy");
    await f.security.close();
  });

  test.each([".", "component"])(
    "denies Git metadata in the policy permission profile for %s",
    async (scope) => {
      const f = await setup();
      policyGit(f.repository, "init", "--quiet");
      const component = join(f.repository, "component");
      const metadata = join(f.repository, "git-data");
      await mkdir(component);
      policyGit(component, "init", "--quiet", "--separate-git-dir", metadata);
      policyGit(component, "config", "core.worktree", component);
      await f.security.generatePolicy(f.repository, {
        path: scope,
        outputDir: f.outputDir,
      });
      const overrides = f
        .configuration()!
        .configOverrides!.map((override) => parseToml(override));
      for (const path of [
        join(f.repository, ".git"),
        join(component, ".git"),
        metadata,
      ]) {
        expect(overrides).toContainEqual({
          permissions: {
            codex_security_policy: { filesystem: { [path]: "deny" } },
          },
        });
      }
      expect(f.threads).toHaveLength(3);
      await f.security.close();
    },
  );

  test("includes inherited and descendant guidance once per policy path", async () => {
    const f = await setup();
    const policies = [
      [".", "ROOT_GUIDANCE"],
      ["component", "COMPONENT_GUIDANCE"],
      ["component/child", "CHILD_GUIDANCE"],
      ["component/child/nested", "NESTED_GUIDANCE"],
      ["component/sibling", "SIBLING_GUIDANCE"],
      [".github", "REPORTING_GUIDANCE"],
    ] as const;
    for (const [scope, marker] of policies) {
      const directory = join(f.repository, scope);
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, "SECURITY.md"), `# ${marker}\n`);
    }
    await f.security.generatePolicy(f.repository, {
      path: "component",
      outputDir: f.outputDir,
    });
    for (const prompt of f.prompts)
      for (const [, marker] of policies)
        expect(prompt.split(marker)).toHaveLength(2);
    await f.security.close();
  });

  test.each(["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"])(
    "checks %s links against the component's policy guidance before runtime setup",
    async (policyPath) => {
      let prepared = false;
      const f = await setup({
        onPrepare: () => {
          prepared = true;
        },
      });
      await mkdir(join(f.repository, "component"));
      const source = join(f.repository, "notes.md");
      await writeFile(source, "# Unrelated project notes\n");
      const policy = join(f.repository, policyPath);
      await mkdir(dirname(policy), { recursive: true });
      await symlink(source, policy, "file");
      const options = { path: "component", outputDir: f.outputDir };
      await expect(
        f.security.preflightPolicy(f.repository, options),
      ).rejects.toThrow("outside the selected component");
      await expect(
        f.security.generatePolicy(f.repository, options),
      ).rejects.toThrow("outside the selected component");
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      expect(await readdir(f.outputDir)).toEqual([]);
      await f.security.close();
    },
  );

  test("accepts shared inherited and reporting policy guidance for a component", async () => {
    const f = await setup();
    policyGit(f.repository, "init", "--quiet");
    await mkdir(join(f.repository, "component"));
    await mkdir(join(f.repository, ".github"));
    await mkdir(join(f.repository, "docs"));
    const reporting = join(f.repository, ".github", "SECURITY.md");
    await writeFile(reporting, "# Shared reporting policy\n");
    await symlink(reporting, join(f.repository, "SECURITY.md"), "file");
    await symlink(reporting, join(f.repository, "docs", "SECURITY.md"), "file");
    await f.security.generatePolicy(f.repository, {
      path: "component",
      outputDir: f.outputDir,
    });
    expect(f.prompts).toHaveLength(3);
    for (const prompt of f.prompts)
      expect(prompt).toContain("Shared reporting policy");
    await f.security.close();
  });

  test("keeps literal component names intact through generation and preview", async () => {
    for (const scope of ["-component", "~component", "~", "~/child"]) {
      let prepared = false;
      const f = await setup({
        onPrepare: () => {
          prepared = true;
        },
      });
      const component = join(f.repository, scope);
      await mkdir(component, { recursive: true });
      await writeFile(
        join(f.repository, "SECURITY.md"),
        "# Root policy\nInherited guidance.\n",
      );
      const options = { path: `./${scope}`, outputDir: f.outputDir };
      const preflight = await f.security.preflightPolicy(f.repository, options);
      expect(preflight.scope).toBe(scope);
      expect(preflight.targetPath).toBe(join(component, "SECURITY.md"));
      expect(prepared).toBe(false);
      const generated = await f.security.generatePolicy(f.repository, options);
      expect(generated.scope).toBe(scope);
      expect(f.prompts[0]).toContain("Inherited guidance.");
      expect(await securityPolicyDiff(generated, PYTHON)).toContain(
        `b/${scope}/SECURITY.md`,
      );
      expect(await readdir(component)).toEqual([]);
      await f.security.close();
    }
  });

  test("validates inherited policies before preflight or runtime setup", async () => {
    for (const invalid of [
      "utf8",
      "outside",
      "git_config",
      "git_file",
      "separate_git",
    ] as const) {
      let prepared = false;
      const f = await setup({
        onPrepare: () => {
          prepared = true;
        },
      });
      await mkdir(join(f.repository, "component"));
      const policy = join(f.repository, "SECURITY.md");
      let message: string;
      if (invalid === "utf8") {
        await writeFile(policy, Buffer.from([0xff]));
        message = "valid UTF-8";
      } else if (invalid === "outside") {
        const outside = join(f.root, "outside-policy.md");
        await writeFile(outside, "# Outside policy\n");
        await symlink(outside, policy, "file");
        message = "outside the repository";
      } else {
        const metadata = join(
          f.repository,
          invalid === "git_config" ? ".git" : "git-data",
        );
        policyGit(
          f.repository,
          "init",
          "--quiet",
          ...(invalid === "git_config" ? [] : ["--separate-git-dir", metadata]),
        );
        policyGit(
          f.repository,
          "config",
          "http.extraHeader",
          "synthetic-value",
        );
        await symlink(
          invalid === "git_file"
            ? join(f.repository, ".git")
            : join(metadata, "config"),
          policy,
          "file",
        );
        message = "Git metadata";
      }
      const options = { path: "component", outputDir: f.outputDir };
      await expect(
        f.security.preflightPolicy(f.repository, options),
      ).rejects.toThrow(message);
      await expect(
        f.security.generatePolicy(f.repository, options),
      ).rejects.toThrow(message);
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      expect(await readdir(f.outputDir)).toEqual([]);
      await f.security.close();
    }
  });

  test("rejects a closed policy client before resolving its target", async () => {
    const f = await setup();
    await f.security.close();
    await expect(
      f.security.preflightPolicy(join(f.root, "missing-repository")),
    ).rejects.toThrow("CodexSecurity is closed");
    expect(f.threads).toHaveLength(0);
  });

  test("does not load instructions from the artifact checkout", async () => {
    const f = await setup({
      config: {
        codexOverrides: {
          project_doc_max_bytes: 8192,
          project_root_markers: [".git"],
        },
      },
    });
    const unrelated = join(f.root, "unrelated");
    const outputDir = join(unrelated, "artifacts");
    const codexHome = join(f.root, "prompt-home");
    await mkdir(outputDir, { recursive: true, mode: 0o700 });
    await mkdir(codexHome);
    policyGit(unrelated, "init", "--quiet");
    await writeFile(join(unrelated, "AGENTS.md"), "SYNTHETIC_PROJECT_MARKER\n");
    await writeFile(join(codexHome, "AGENTS.md"), "SYNTHETIC_USER_MARKER\n");
    await writeCodexConfig(join(codexHome, "config.toml"), {
      model: "gpt-5.6-sol",
      features: { plugins: false, apps: false },
    });
    await f.security.generatePolicy(f.repository, { outputDir });
    const config = f.configuration()!.config!;
    const environment: NodeJS.ProcessEnv = {
      ...process.env,
      CODEX_HOME: codexHome,
    };
    delete environment["OPENAI_API_KEY"];
    delete environment["CODEX_API_KEY"];
    const node = Bun.which("node");
    if (node === null)
      throw new Error("The pinned Codex CLI requires Node.js.");
    const result = Bun.spawnSync(
      [
        node,
        join(
          import.meta.dir,
          "..",
          "node_modules",
          "@openai",
          "codex",
          "bin",
          "codex.js",
        ),
        "debug",
        "prompt-input",
        "-c",
        `project_doc_max_bytes=${JSON.stringify(config["project_doc_max_bytes"])}`,
        "-c",
        `project_root_markers=${JSON.stringify(config["project_root_markers"])}`,
        "Synthetic policy request",
      ],
      { cwd: outputDir, env: environment, stdout: "pipe", stderr: "pipe" },
    );
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    const visible = new TextDecoder().decode(result.stdout);
    expect(visible.includes("SYNTHETIC_PROJECT_MARKER")).toBe(false);
    expect(visible.includes("SYNTHETIC_USER_MARKER")).toBe(true);
    expect(config["project_root_markers"]).toEqual([]);
    await f.security.close();
  });

  test("uses the shared runtime for three fresh, scoped, structured turns", async () => {
    const f = await setup({ surface: "cli" });
    await writeFile(
      join(f.repository, "SECURITY.md"),
      "# Existing policy\nKeep the reporting channel.\n",
    );
    const observed: SecurityPolicyStage[] = [];
    const costs: number[] = [];
    const result = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      onStage: (stage) => observed.push(stage),
      onCost: (cost) => costs.push(cost.estimatedUsd),
      answerQuestions: async () => "Authenticated clients only.",
    });
    expect(observed).toEqual(["architecture", "threat_model", "policy"]);
    expect(f.threads).toHaveLength(3);
    const readRoots = f.threads[0]!.additionalDirectories;
    expect(readRoots).toContain(f.repository);
    expect(readRoots).toContain(PLUGIN_ROOT);
    expect(readRoots).toEqual([f.repository, PLUGIN_ROOT]);
    expect(readRoots).not.toContain(f.runtime.codexHome);
    expect(readRoots).not.toContain(join(f.root, "state"));
    for (const thread of f.threads) {
      expect(thread.workingDirectory).toBe(f.outputDir);
      expect(thread.additionalDirectories).toEqual(readRoots);
      expect(thread.approvalPolicy).toBe("never");
      expect(thread.networkAccessEnabled).toBe(false);
      expect(thread.webSearchMode).toBe("disabled");
    }
    expect(f.turns.every((turn) => turn.outputSchema !== undefined)).toBe(true);
    const outputSchema = f.turns[0]!.outputSchema as AnySchema;
    expect(JSON.stringify(outputSchema)).not.toContain('"nullable"');
    expect(JSON.stringify(outputSchema)).not.toContain('"minLength"');
    const validate = new Ajv().compile(outputSchema);
    expect(validate(stageResult("architecture"))).toBe(true);
    expect(
      validate({ ...stageResult("architecture"), blockedReason: 42 }),
    ).toBe(false);
    expect(f.prompts[0]).toContain("Keep the reporting channel.");
    expect(f.prompts[1]).toContain("Authenticated clients only.");
    expect(f.configuration()?.config?.["features"]).toMatchObject({
      plugins: false,
      apps: false,
    });
    expect(f.configuration()?.config).toMatchObject({
      default_permissions: "codex_security_policy",
      mcp_servers: {},
      web_search: "disabled",
      sandbox_workspace_write: { network_access: false },
    });
    expect(f.configuration()?.config?.["responses_api_metadata"]).toMatchObject(
      { codex_security_surface: "cli" },
    );
    expect(f.configuration()?.env?.["CODEX_SECURITY_REPOSITORY"]).toBe(
      f.repository,
    );
    expect(f.configuration()?.env?.["CODEX_SECURITY_SCAN_ID"]).toBeUndefined();
    expect(result.cost?.inputTokens).toBe(300);
    expect(result.cost?.outputTokens).toBe(30);
    expect(costs).toHaveLength(3);
    expect(costs.at(-1)).toBe(result.cost?.estimatedUsd);
    expect(await readFile(result.draftPath, "utf8")).toBe(POLICY);
    expect(await readFile(result.targetPath, "utf8")).toContain(
      "Keep the reporting channel.",
    );
    await f.security.close();
  });

  test("rejects policy changes made while resolving generation guidance", async () => {
    for (const scope of [".", "component"]) {
      const f = await setup();
      await mkdir(join(f.repository, "component"));
      await writeFile(join(f.repository, "SECURITY.md"), "# Original policy\n");
      const pluginRoot = await policyPlugin(
        f.root,
        [
          "import pathlib, sys",
          "root = pathlib.Path(sys.argv[sys.argv.index('--repo') + 1])",
          "policy = root / 'SECURITY.md'",
          "previous = policy.read_text()",
          "policy.write_bytes(b'# Concurrent policy\\n')",
          "print(previous)",
        ].join("\n"),
      );
      for (const name of [
        "references/threat-model.md",
        "references/security-guidance.md",
        "skills/define-security-policy/SKILL.md",
      ]) {
        const path = join(pluginRoot, name);
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, "Synthetic policy guidance.\n");
      }
      f.runtime.plugin = {
        ...f.runtime.plugin,
        pluginRoot,
      };
      await expect(
        f.security.generatePolicy(f.repository, {
          path: scope,
          outputDir: f.outputDir,
        }),
      ).rejects.toThrow("changed after");
      expect(f.threads).toHaveLength(0);
      expect(await readFile(join(f.repository, "SECURITY.md"), "utf8")).toBe(
        "# Concurrent policy\n",
      );
      expect(await readdir(f.outputDir)).not.toContain("policy-draft.json");
      await f.security.close();
    }
  });

  test("keeps the original checkpoint when a policy changes after guidance resolution", async () => {
    let targetPath = "";
    const f = await setup({
      onRevision: async () => {
        await writeFile(targetPath, "# Concurrent policy\n");
      },
    });
    targetPath = join(f.repository, "SECURITY.md");
    const original = "# Original policy\n";
    await writeFile(targetPath, original);
    await expect(
      f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
    ).rejects.toThrow("changed after");
    expect(f.prompts[0]).toContain(original.trim());
    expect(
      await readFile(join(f.outputDir, "previous-SECURITY.md"), "utf8"),
    ).toBe(original);
    expect(await readdir(f.outputDir)).not.toContain("policy-draft.json");
    await f.security.close();
  });

  test.each([".", "component"])(
    "rejects governing policy changes during generation for %s and preserves documents",
    async (scope) => {
      let policyPath = "";
      const f = await setup({
        stream: async function* (stage) {
          if (stage === "policy")
            await writeFile(policyPath, "# Concurrent policy\n");
          yield* events(stage);
        },
      });
      await mkdir(join(f.repository, "component"));
      policyPath = join(f.repository, "SECURITY.md");
      await writeFile(policyPath, "# Original policy\n");
      await expect(
        f.security.generatePolicy(f.repository, {
          path: scope,
          outputDir: f.outputDir,
        }),
      ).rejects.toThrow("changed after");
      expect(f.threads).toHaveLength(3);
      expect((await readdir(f.outputDir)).sort()).toEqual([
        "SECURITY.md",
        "THREAT_MODEL.md",
        "previous-SECURITY.md",
        "project-spec.md",
      ]);
      expect(await readFile(join(f.outputDir, "SECURITY.md"), "utf8")).toBe(
        POLICY,
      );
      await f.security.close();
    },
  );

  test("rejects an incomplete policy plugin before starting model work", async () => {
    const f = await setup();
    const pluginRoot = join(f.root, "incomplete-plugin");
    for (const path of [
      "references/threat-model.md",
      "skills/define-security-policy/SKILL.md",
      "scripts/resolve_security_md.py",
    ]) {
      const destination = join(pluginRoot, path);
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, "synthetic plugin fixture\n");
    }
    f.runtime.plugin = {
      ...f.runtime.plugin,
      pluginRoot,
    };
    await expect(
      f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
    ).rejects.toThrow("references/security-guidance.md");
    expect(f.threads).toHaveLength(0);
    expect(await readdir(f.outputDir)).toEqual([]);
    await f.security.close();
  });

  test("resolves quoted profiles before applying policy settings", async () => {
    const f = await setup({
      config: {
        codexOverrides: {
          profile: "team.prod",
          features: { apps: true, goals: false, shell_snapshot: true },
          allow_login_shell: true,
          shell_environment_policy: {
            inherit: "all",
            ignore_default_excludes: true,
            set: { SYNTHETIC_SETTING: "root-setting" },
            include_only: ["SYNTHETIC_*"],
          },
          mcp_servers: { synthetic: { command: "synthetic-tool" } },
          sandbox_workspace_write: {
            network_access: true,
            writable_roots: ["/synthetic"],
          },
          profiles: {
            unused: { "features.apps": true },
            "team.prod": {
              model: "gpt-5.6-terra",
              model_reasoning_effort: "high",
              features: { apps: true, goals: true },
              mcp_servers: { synthetic: { command: "synthetic-profile-tool" } },
              web_search: "live",
              shell_environment_policy: {
                set: { SYNTHETIC_PROFILE_SETTING: "profile-setting" },
                experimental_use_profile: true,
              },
              sandbox_workspace_write: { network_access: true },
            },
          },
        },
      },
    });
    await f.security.preflightPolicy(f.repository);
    await f.security.generatePolicy(f.repository, { outputDir: f.outputDir });
    expect(f.configuration()?.config).toMatchObject({
      model: "gpt-5.6-terra",
      model_reasoning_effort: "high",
      default_permissions: "codex_security_policy",
      features: {
        plugins: false,
        apps: false,
        goals: true,
        shell_snapshot: false,
      },
      allow_login_shell: false,
      mcp_servers: {},
      web_search: "disabled",
      sandbox_workspace_write: { network_access: false },
    });
    expect(f.configuration()?.config?.["shell_environment_policy"]).toEqual({
      inherit: "core",
      ignore_default_excludes: false,
    });
    expect(f.configuration()?.config).not.toHaveProperty("profile");
    expect(f.configuration()?.config).not.toHaveProperty("profiles");
    const serialized = JSON.stringify(f.configuration()?.config);
    expect(serialized).not.toContain("synthetic-tool");
    expect(serialized).not.toContain("synthetic-profile-tool");
    expect(serialized).not.toContain("writable_roots");
    expect(serialized).not.toContain('"plugins":true');
    expect(serialized).not.toContain('"apps":true');
    await f.security.close();
  });

  test("rejects Codex override aliases before policy runtime setup", async () => {
    for (const codexOverrides of [
      { "features.plugins": true },
      { "mcp_servers.synthetic.command": "synthetic-tool" },
      { features: { '"apps"': true } },
      {
        profile: "selected",
        profiles: { selected: { "features.apps": true } },
      },
    ]) {
      let prepared = false;
      const f = await setup({
        config: { codexOverrides },
        onPrepare: () => {
          prepared = true;
        },
      });
      await expect(f.security.preflightPolicy(f.repository)).rejects.toThrow(
        "dotted or quoted Codex override keys",
      );
      await expect(f.security.generatePolicy(f.repository)).rejects.toThrow(
        "dotted or quoted Codex override keys",
      );
      expect(prepared).toBe(false);
      expect(f.threads).toHaveLength(0);
      await f.security.close();
    }
  });

  test("leaves quoted model-provider names in the native configuration", async () => {
    const provider = "synthetic.provider";
    const f = await setup({
      config: {
        codexOverrides: {
          model_provider: provider,
          model_providers: {
            [provider]: {
              name: "Synthetic provider",
              base_url: "https://example.invalid/v1",
              wire_api: "responses",
            },
          },
        },
      },
    });
    await f.security.generatePolicy(f.repository, { outputDir: f.outputDir });
    expect(f.configuration()?.config?.["model_provider"]).toBe(provider);
    expect(f.configuration()?.config).not.toHaveProperty("model_providers");
    await f.security.close();
  });

  test("retains an explicit plugin selection without persisting its location", async () => {
    const f = await setup({ config: { pluginPath: PLUGIN_ROOT } });
    const draft = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
    });
    expect(draft.customPlugin).toBe(true);
    expect(draft.pluginPath).toBe(resolve(PLUGIN_ROOT));
    const manifest = JSON.parse(
      await readFile(join(f.outputDir, "policy-draft.json"), "utf8"),
    );
    expect(manifest.customPlugin).toBe(true);
    expect(manifest).not.toHaveProperty("pluginPath");
    await f.security.close();
  });

  test("keeps knowledge-base context with private review artifacts and removes it afterward", async () => {
    const f = await setup();
    const context = join(f.root, "architecture.md");
    await writeFile(context, "The synthetic service is private.\n");
    await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      knowledgeBasePaths: [context],
    });
    const extracted = f.configuration()?.env?.["CODEX_SECURITY_KNOWLEDGE_BASE"];
    expect(extracted).toBeDefined();
    expect(dirname(extracted!)).toBe(f.outputDir);
    expect(f.threads[0]!.additionalDirectories).toContain(extracted);
    expect(
      f.prompts.every((prompt) => prompt.includes(JSON.stringify(extracted))),
    ).toBe(true);
    await expect(readFile(extracted!)).rejects.toThrow();
    expect(await readdir(f.repository)).toEqual([]);
    await f.security.close();
  });

  test("enforces one cost budget across stages and preserves completed evidence", async () => {
    const f = await setup();
    await expect(
      f.security.generatePolicy(f.repository, {
        outputDir: f.outputDir,
        maxCostUsd: 0.001,
      }),
    ).rejects.toThrow("cost limit");
    expect(f.threads).toHaveLength(2);
    expect(
      await readFile(join(f.outputDir, "project-spec.md"), "utf8"),
    ).toContain("src/service.ts:1");
    expect(await readdir(f.repository)).toEqual([]);
    await f.security.close();
  });

  test("optional observer failures do not stop policy generation", async () => {
    const f = await setup();
    const errors: string[] = [];
    const fail = () => {
      throw new Error("optional observer");
    };
    const result = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      onStage: fail,
      onCost: fail,
      onOutputDirReady: fail,
      onObserverError: (observer) => errors.push(observer),
    });
    expect(result.content).toBe(POLICY);
    expect(errors).toContain("onStage");
    expect(errors).toContain("onCost");
    expect(errors).toContain("onOutputDirReady");
    await f.security.close();
  });

  test("optional cost-tracking failures preserve the generated policy", async () => {
    const f = await setup();
    await writeFile(join(f.root, "codex-home", "sessions"), "not a directory");
    const warnings: string[] = [];
    const result = await f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      onWarning: (warning) => warnings.push(warning),
    });
    expect(result.content).toBe(POLICY);
    expect(result.cost?.inputTokens).toBe(300);
    expect(warnings.some((warning) => warning.includes("track"))).toBe(true);
    await f.security.close();
  });

  test("allows unavailable usage unless an explicit cost limit needs verification", async () => {
    for (const limited of [false, true]) {
      const f = await setup({
        stream: async function* (stage) {
          for await (const event of events(stage)) {
            if (event.type === "turn.completed") {
              throw new TypeError(
                "Cannot read properties of null (reading 'cache_write_input_tokens')",
              );
            }
            yield event;
          }
        },
      });
      const result = f.security.generatePolicy(f.repository, {
        outputDir: f.outputDir,
        ...(limited ? { maxCostUsd: 1 } : {}),
      });
      if (limited) await expect(result).rejects.toThrow("cost limit");
      else expect((await result).cost).toBeNull();
      await f.security.close();
    }
  });

  test("uses scan reconnect handling and rejects definitive access failures", async () => {
    const warnings: string[] = [];
    const f = await setup({
      stream: async function* (stage) {
        yield {
          type: "error",
          message: "Reconnecting... 1/5 (connection reset)",
        };
        yield* events(stage);
      },
    });
    expect(
      (
        await f.security.generatePolicy(f.repository, {
          outputDir: f.outputDir,
          onWarning: (warning) => warnings.push(warning),
        })
      ).content,
    ).toBe(POLICY);
    expect(warnings).toHaveLength(3);
    await f.security.close();

    const denied = await setup({
      stream: async function* () {
        yield {
          type: "error",
          message: "Reconnecting... 1/5 (HTTP 403 Forbidden)",
        };
        throw new Error("Must fail before retrying");
      },
    });
    await expect(
      denied.security.generatePolicy(denied.repository, {
        outputDir: denied.outputDir,
      }),
    ).rejects.toThrow("403 Forbidden");
    await denied.security.close();
  });

  test("rejects incomplete and invalid model responses", async () => {
    for (const [response, message] of [
      ["incomplete", "before the turn completed"],
      ["invalid", "invalid document"],
      ["empty", "returned an empty document"],
    ] as const) {
      const f = await setup({
        stream: async function* (stage) {
          if (response === "empty") {
            yield* events(stage, { ...stageResult(stage), markdown: " \n" });
            return;
          }
          yield { type: "thread.started", thread_id: "policy-failed" };
          if (response === "invalid") {
            yield {
              type: "item.completed",
              item: { id: "result", type: "agent_message", text: "not JSON" },
            };
            yield {
              type: "turn.completed",
              usage: {
                input_tokens: 0,
                cached_input_tokens: 0,
                cache_write_input_tokens: 0,
                output_tokens: 0,
                reasoning_output_tokens: 0,
              },
            };
          }
        },
      });
      await expect(
        f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
      ).rejects.toThrow(message);
      expect(await readdir(f.repository)).toEqual([]);
      await f.security.close();
    }
  });

  test("stops when source inspection is blocked instead of synthesizing a policy", async () => {
    const f = await setup({
      stream: (stage) =>
        events(stage, {
          ...stageResult(stage),
          blockedReason: "The source-inspection sandbox could not start.",
        }),
    });
    await expect(
      f.security.generatePolicy(f.repository, { outputDir: f.outputDir }),
    ).rejects.toThrow("source-inspection sandbox could not start");
    expect(f.threads).toHaveLength(1);
    expect(await readdir(f.outputDir)).toContain("project-spec.md");
    expect(await readdir(f.outputDir)).not.toContain("policy-draft.json");
    expect(await readdir(f.repository)).toEqual([]);
    await f.security.close();
  });

  test("cancels through AbortSignal without writing source", async () => {
    const controller = new AbortController();
    const f = await setup({
      stream: async function* (stage) {
        yield { type: "thread.started", thread_id: `policy-${stage}` };
        controller.abort(new Error("cancel"));
        yield* events(stage);
      },
    });
    await expect(
      f.security.generatePolicy(f.repository, {
        outputDir: f.outputDir,
        signal: controller.signal,
      }),
    ).rejects.toThrow("interrupted");
    expect(await readdir(f.repository)).toEqual([]);
    await f.security.close();
  });

  test("close cancels an owner-question callback even if it never settles", async () => {
    const f = await setup();
    let entered!: () => void;
    const waiting = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let promptSignal: AbortSignal | undefined;
    const generation = f.security.generatePolicy(f.repository, {
      outputDir: f.outputDir,
      answerQuestions: (_questions, signal) => {
        promptSignal = signal;
        entered();
        return new Promise(() => {});
      },
    });
    const interrupted = generation.catch((error: unknown) => error);
    await waiting;
    await f.security.close();
    expect(await interrupted).toMatchObject({
      message: expect.stringContaining("interrupted"),
    });
    expect(promptSignal?.aborted).toBe(true);
    expect(f.threads).toHaveLength(1);
    expect(await readdir(f.repository)).toEqual([]);
    expect(await readdir(f.outputDir)).not.toContain("policy-draft.json");
  });
});
