import { gitText } from "./support/shell.js";
import { expect, beforeEach, afterEach } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { Finding, JsonObject, SeverityLevel } from "../src/index.js";
import { main } from "../src/cli.js";
import { dependencies, fakeResult } from "./cli-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { createCliTest } from "./support/cli-run.js";

const workflowDirectories = createTemporaryDirectories(true);
export let CURRENT_REPOSITORY: string;
export let SAVED_REPOSITORY: string;
beforeEach(async () => {
  const root = await workflowDirectories.create("patch-workflow-");
  CURRENT_REPOSITORY = join(root, "current", "repository");
  SAVED_REPOSITORY = join(root, "saved", "repository");
  await Promise.all(
    [
      CURRENT_REPOSITORY,
      SAVED_REPOSITORY,
      resolve(CURRENT_REPOSITORY, "../other/repository"),
    ].map((directory) => mkdir(directory, { recursive: true })),
  );
});
afterEach(workflowDirectories.cleanup);
export const STATE_DIRECTORY = resolve("/tmp/codex-security-state");

export async function readAppliedText(path: string) {
  return (await readFile(path, "utf8")).replaceAll("\r\n", "\n");
}

export function resultWithFindings(severities: readonly SeverityLevel[]) {
  const result = fakeResult(severities);
  result.findings.findings.forEach((finding, index) => {
    Object.assign(finding, {
      findingId: `csf_${index + 1}`,
      occurrenceId: `occ_${index + 1}`,
      title: `Finding ${index + 1}`,
      summary: `Summary ${index + 1}`,
      locations: [
        { path: `src/finding-${index + 1}.ts`, startLine: index + 1 },
      ],
    });
  });
  return result;
}

export function savedScan(
  result: ReturnType<typeof resultWithFindings>,
  scanId = "scan-1",
  targetPath = SAVED_REPOSITORY,
): JsonObject {
  return {
    scan: {
      scanId,
      targetPath,
      findings: result.findings.findings as unknown as JsonObject[],
    },
  };
}

export function completePatches(
  args: readonly string[],
  output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
  status: "verified" | "blocked" = "verified",
): Finding[] {
  const prompt = output?.appServer?.prompt ?? args.at(-1)!;
  const findings = JSON.parse(prompt.split("\n").at(-1)!) as Finding[];
  output?.stdout.write(
    JSON.stringify({
      patches: findings.map((finding) => ({
        occurrenceId: finding.occurrenceId,
        status,
        files: status === "verified" ? [finding.locations[0]!.path] : [],
        ...(status === "verified"
          ? { verification: "The exploit fails and focused tests pass." }
          : { reason: "The required service is unavailable." }),
      })),
    }),
  );
  return findings;
}

export function patchRiskSummary() {
  return [
    "### Recommendation: human review required",
    "",
    "The patch has moderate impact and low regression likelihood.",
    "",
    "- Protection: focused tests passed",
    "- Recovery: revert the patch commit",
  ].join("\n");
}

export function patchRiskAssessment() {
  const summary = patchRiskSummary();
  return {
    report: [
      "<!-- codex-security:patch-risk-summary:start -->",
      summary,
      "<!-- codex-security:patch-risk-summary:end -->",
      "",
      "```json",
      '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
      "```",
    ].join("\n"),
  };
}

export function patchRiskReport() {
  return [
    patchRiskSummary(),
    "",
    "```json",
    '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
    "```",
  ].join("\n");
}

export async function runWorkflow(
  arguments_: string[],
  fixtures: Parameters<typeof dependencies>[0] = {},
  options: {
    interactive?: boolean;
    review?: boolean;
    configure?: (value: ReturnType<typeof dependencies>) => void;
  } = {},
) {
  const { stdout, stderr, runCli } = createCliTest(main, {
    stderr: options.interactive,
  });

  const current = dependencies({
    currentDirectory: CURRENT_REPOSITORY,
    onCodex: (args, output) => {
      completePatches(args, output);
      return 0;
    },
    ...fixtures,
  });
  if (options.interactive) {
    current.confirmPatchReview = async (question) => {
      stderr.stream.write(`\n${question} (y/N)\n`);
      return options.review ?? true;
    };
  }
  options.configure?.(current);
  return {
    exitCode: await runCli(arguments_, current),
    stdout: stdout.text(),
    stderr: stderr.text(),
  };
}

export function repositoryGit(repository: string) {
  return (...args: string[]) =>
    execFileSync("git", args, {
      cwd: repository,
      encoding: "utf8",
      maxBuffer: Infinity,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
}

export const runGitRepositoryCommand: NonNullable<
  NonNullable<Parameters<typeof dependencies>[0]>["onRepositoryCommand"]
> = (command, args, workingDirectory, options) => {
  expect(command).toBe("git");
  const result = gitText(args, {
    cwd: options?.directory ?? workingDirectory,
    env: { ...process.env, ...options?.environment },
    maxBuffer: options?.maxBuffer,
    input: options?.input,
    stdio: [options?.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  });
  return options?.trim === false ? result : result.trim();
};

export async function publicationRepository(
  fixtures: ReturnType<typeof createTemporaryDirectories>,
) {
  const directory = await fixtures.create("patch-destination-");
  const git = repositoryGit(directory);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  await mkdir(join(directory, "src"));
  await writeFile(join(directory, "src/finding-1.ts"), "original\n");
  git("add", ".");
  git("commit", "-m", "Synthetic baseline");
  const remote = await fixtures.create("patch-destination-origin-");
  git("init", "--bare", remote);
  git("remote", "add", "origin", remote);
  return { directory, git, remote };
}
