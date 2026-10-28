import { expect, beforeEach, afterEach } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve, win32 } from "node:path";
import type { Finding, JsonObject, SeverityLevel } from "../src/index.js";
import { main } from "../src/cli.js";
import { dependencies, fakeResult } from "./cli-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { createCliTest } from "./support/cli-run.js";

export let CURRENT_REPOSITORY: string;
export let SAVED_REPOSITORY: string;

export function setupPatchWorkflowFixtures() {
  const workflowDirectories = createTemporaryDirectories(true);
  beforeEach(async () => {
    const root = await workflowDirectories.create("patch-workflow-");
    CURRENT_REPOSITORY = join(root, "current", "repository");
    SAVED_REPOSITORY = join(root, "saved", "repository");
    await Promise.all(
      [
        CURRENT_REPOSITORY,
        SAVED_REPOSITORY,
        resolve(CURRENT_REPOSITORY, "../other/repository"),
      ].map(async (directory) => {
        await mkdir(directory, { recursive: true });
        repositoryGit(directory)("init", "--initial-branch=main");
      }),
    );
  });
  afterEach(workflowDirectories.cleanup);
}

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

export function patchDependencies(
  options: Parameters<typeof dependencies>[0] = {},
) {
  return dependencies({
    ...options,
    onRepositoryCommand: async (command, args, repository, commandOptions) => {
      const output = await options.onRepositoryCommand?.(
        command,
        args,
        repository,
        commandOptions,
      );
      if (
        output !== undefined ||
        command !== "git" ||
        !args.includes("rev-parse") ||
        !args.some((argument) =>
          [
            "--show-toplevel",
            "--absolute-git-dir",
            "--git-common-dir",
            "--git-dir",
            "--git-path",
            "--resolve-git-dir",
          ].includes(argument),
        )
      )
        return output;
      return runGitRepositoryCommand(command, args, repository, commandOptions);
    },
  });
}

export async function runWorkflow(
  arguments_: string[],
  fixtures: Parameters<typeof dependencies>[0] = {},
  options: {
    interactive?: boolean;
    review?: boolean;
    localHosting?: boolean;
    configure?: (value: ReturnType<typeof dependencies>) => void;
  } = {},
) {
  const { stdout, stderr, runCli } = createCliTest(main, {
    stderr: options.interactive,
  });

  const savedFindings = new Map<string, readonly Finding[]>();
  const current = patchDependencies({
    currentDirectory: CURRENT_REPOSITORY,
    onCodex: (args, output) => {
      completePatches(args, output);
      return 0;
    },
    ...fixtures,
    onWorkbench: async (...args) => {
      const response = await fixtures.onWorkbench?.(...args);
      const scan = response?.["scan"] as JsonObject | undefined;
      if (
        typeof scan?.["scanId"] === "string" &&
        Array.isArray(scan["findings"])
      ) {
        savedFindings.set(
          scan["scanId"],
          scan["findings"] as unknown as Finding[],
        );
      }
      return response ?? { scans: [] };
    },
    readSavedFindings:
      fixtures.readSavedFindings ??
      (async (scanId) =>
        fixtures.result?.findings.findings ?? savedFindings.get(scanId) ?? []),
  });
  // Publication fixtures use real local bare repositories behind a synthetic
  // hosting transport. Hosting tests disable this adapter to inspect real URLs.
  if (options.localHosting !== false) {
    const run = current.runRepositoryCommand;
    const localRemotes = new Map<string, string>();
    let hostedRemote = "https://github.example.test/example/repository.git";
    let creatingRequest = false;
    current.runRepositoryCommand = async (
      command,
      args,
      cwd,
      commandOptions,
    ) => {
      if (command === "gh" && args[0] === "repo" && args[1] === "view") {
        if (args.at(-1) === ".url") {
          creatingRequest = true;
          return hostedRemote.replace(/\.git$/u, "");
        }
        if (
          (localRemotes.size || creatingRequest) &&
          args.at(-1) === "tojson" &&
          args.includes("id,url")
        )
          return JSON.stringify({
            id: "synthetic-origin-id",
            url: hostedRemote.replace(/\.git$/u, ""),
          });
      }
      if (
        (localRemotes.size || creatingRequest) &&
        command === "gh" &&
        args[0] === "repo" &&
        args[1] === "set-default"
      )
        return new URL(hostedRemote).pathname.slice(1).replace(/\.git$/u, "");
      const environment = { ...commandOptions?.environment };
      for (const key of Object.keys(environment)) {
        if (!key.startsWith("GIT_CONFIG_KEY_")) continue;
        for (const [hosted, local] of localRemotes)
          if (environment[key] === `url.${hosted}.insteadOf`)
            environment[key] = `url.${local}.insteadOf`;
      }
      const output = await run(command, args, cwd, {
        ...commandOptions,
        environment,
      });
      if (command !== "git" || args[args.indexOf("remote") + 1] !== "get-url")
        return output;
      if (!output.trim()) return hostedRemote;
      const remotes = output.split("\n").map((remote) => {
        if (
          !isAbsolute(remote) &&
          !win32.isAbsolute(remote) &&
          !remote.startsWith("file://")
        )
          return remote;
        let hosted = [...localRemotes].find(
          ([, local]) => local === remote,
        )?.[0];
        if (!hosted) {
          hosted = `https://github.example.test/example/repository-${localRemotes.size}.git`;
          localRemotes.set(hosted, remote);
        }
        return hosted;
      });
      if (args.includes("--push") && remotes[0]?.includes("://"))
        hostedRemote = remotes[0];
      return remotes.join("\n");
    };
  }
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

export const runGitRepositoryCommand: (
  ...args: Parameters<ReturnType<typeof dependencies>["runRepositoryCommand"]>
) => string | Promise<string> = (command, args, workingDirectory, options) => {
  expect(command).toBe("git");
  const result = execFileSync("git", args, {
    encoding:
      options?.encoding === "base64" || options?.onStdout !== undefined
        ? "buffer"
        : "utf8",
    cwd: options?.directory ?? workingDirectory,
    env: { ...process.env, ...options?.environment },
    maxBuffer: options?.maxBuffer,
    input: options?.input,
    stdio: [options?.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  });
  if (options?.onStdout !== undefined) {
    options.onStdout(Buffer.isBuffer(result) ? result : Buffer.from(result));
    return "";
  }
  const output = Buffer.isBuffer(result)
    ? result.toString(options?.encoding ?? "utf8")
    : result;
  return options?.trim === false ? output : output.trim();
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
