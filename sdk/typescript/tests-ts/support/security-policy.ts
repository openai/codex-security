import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  inspectSecurityPolicyPaths,
  readSecurityPolicySnapshot,
  resolveSecurityPolicyTarget,
  runSecurityPolicyStages,
  type SecurityPolicyDraft,
  type SecurityPolicyOptions,
  type SecurityPolicyStage,
  type SecurityPolicyStageResult,
} from "../../src/security-policy.js";
import { PLUGIN_ROOT } from "../plugin-root.js";

export const POLICY =
  "# Security Policy\n\n## Security Invariants\n\nRequests must be authorized before reading another account's records.\n";
export const PYTHON = execFileSync(
  process.env["PYTHON"] ??
    (process.platform === "win32" ? "python" : "python3"),
  ["-c", "import sys; print(sys.executable)"],
  { encoding: "utf8" },
).trim();

export function policyGit(repository: string, ...args: string[]): void {
  execFileSync("git", [
    "-C",
    repository,
    "-c",
    "user.name=Synthetic Test",
    "-c",
    "user.email=test@example.invalid",
    "-c",
    "commit.gpgsign=false",
    ...args,
  ]);
}

export async function addPolicySubmodule(
  repository: string,
  source: string,
  path = "services/api",
): Promise<string> {
  await mkdir(source);
  policyGit(source, "init", "--quiet");
  policyGit(source, "commit", "--allow-empty", "--quiet", "-m", "initial");
  policyGit(
    repository,
    "-c",
    "protocol.file.allow=always",
    "submodule",
    "add",
    "--quiet",
    source,
    path,
  );
  return join(repository, path);
}

export function stageResult(
  stage: SecurityPolicyStage,
): SecurityPolicyStageResult {
  return {
    markdown:
      stage === "policy" ? POLICY : `# ${stage}\n\nSource: src/service.ts:1\n`,
    questions:
      stage === "architecture" ? ["Is this service internet-facing?"] : [],
    reviewNotes:
      stage === "policy" ? ["Confirm the deployment's exposure."] : [],
    blockedReason: null,
  };
}

export async function policyFixture(): Promise<{
  root: string;
  repository: string;
  outputDir: string;
  generate(options?: {
    path?: string;
    pluginPath?: string;
    run?: (
      stage: SecurityPolicyStage,
      prompt: string,
    ) => Promise<SecurityPolicyStageResult>;
    answerQuestions?: SecurityPolicyOptions["answerQuestions"];
    signal?: AbortSignal;
  }): Promise<SecurityPolicyDraft>;
  cleanup(): Promise<void>;
}> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-policy-")),
  );
  const repository = join(root, "repository");
  const outputDir = join(root, "policy");
  await mkdir(repository);
  await mkdir(outputDir, { mode: 0o700 });
  return {
    root,
    repository,
    outputDir,
    generate: async (options = {}) => {
      const target = await resolveSecurityPolicyTarget(
        repository,
        options.path,
      );
      return await runSecurityPolicyStages({
        target,
        snapshot: await readSecurityPolicySnapshot(target, options.signal),
        policyPaths: await inspectSecurityPolicyPaths(target, options.signal),
        outputDir,
        pluginRoot: PLUGIN_ROOT,
        pluginPath: options.pluginPath,
        guidance: "Synthetic inherited guidance",
        revision: null,
        model: "gpt-5.6-sol",
        reasoningEffort: "high",
        pluginVersion: "0.1.0",
        signal: options.signal ?? new AbortController().signal,
        run: options.run ?? (async (stage) => stageResult(stage)),
        answerQuestions: options.answerQuestions,
        cost: () => null,
      });
    },
    cleanup: async () => rm(root, { recursive: true, force: true }),
  };
}

export async function policyPlugin(
  root: string,
  script: string,
): Promise<string> {
  const plugin = await mkdtemp(join(root, "custom-plugin-"));
  await mkdir(join(plugin, ".codex-plugin"));
  await mkdir(join(plugin, "scripts"));
  await writeFile(
    join(plugin, ".codex-plugin", "plugin.json"),
    JSON.stringify({ name: "codex-security", version: "test-policy-plugin" }),
  );
  await writeFile(join(plugin, "scripts", "resolve_security_md.py"), script);
  return plugin;
}
