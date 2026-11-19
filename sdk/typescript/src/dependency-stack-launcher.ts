import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CodexSecurityError } from "./errors.js";
import type { DependencyProgressSink } from "./dependency-check-output.js";
import { analyzeStackAdvisory } from "./dependency-stack-advisory.js";
import type { DependencyCliContext } from "./dependency-stack-cli.js";
import { prepareStackCheckPacket } from "./dependency-stack-packet.js";
import {
  executeStackRun,
  readFinalStackReport,
} from "./dependency-stack-run.js";
import { gitOutput, repositoryRevision } from "./targets.js";
import { requireOutputOutsideRepository } from "./runtime.js";
import { VERSION } from "./version.js";

const packageRoot = dirname(
  fileURLToPath(new URL("../package.json", import.meta.url)),
);
const instructionsPath = join(
  packageRoot,
  "resources",
  "dependency-stack-investigation.md",
);

interface StackInvestigationSession {
  directory: string;
  inputs: string;
  repo: string;
  state: string;
}

/** A development build can share its package version with a different checkout. */
async function toolRevision(signal?: AbortSignal): Promise<string> {
  const packageDirectory = packageRoot;
  if (
    basename(packageDirectory) !== "typescript" ||
    basename(dirname(packageDirectory)) !== "sdk"
  )
    return `@openai/codex-security@${VERSION}`;
  const root = dirname(dirname(packageDirectory));
  const revision = await repositoryRevision(root, signal);
  if (!revision) return `@openai/codex-security@${VERSION}`;
  const changes = await gitOutput(
    root,
    [
      "status",
      "--porcelain",
      "--untracked-files=all",
      "--",
      "sdk/typescript/src",
      "sdk/typescript/resources/dependency-stack-investigation.md",
    ],
    signal,
  );
  if (!changes) return revision;
  const hash = createHash("sha256");
  const loadedModule = fileURLToPath(import.meta.url);
  const implementation = dirname(loadedModule);
  const extension = extname(loadedModule);
  const files = (await readdir(implementation, { recursive: true }))
    .filter((file) => file.endsWith(extension) && !file.endsWith(".d.ts"))
    .sort();
  for (const file of files) {
    hash
      .update(file)
      .update("\0")
      .update(await readFile(join(implementation, file)))
      .update("\0");
  }
  hash.update(await readFile(instructionsPath));
  return `${revision}+build.${hash.digest("hex")}`;
}

export async function runLocalStackInvestigation(options: {
  cve: string;
  sourcesPath: string;
  sinksPath: string;
  stacksPath: string;
  repository: string;
  signal: AbortSignal;
  runAgent: DependencyCliContext["runAgent"];
  emit: DependencyProgressSink;
}) {
  const temporaryRoot = await realpath(tmpdir());
  requireOutputOutsideRepository(options.repository, temporaryRoot, "runtime");
  const scratch = await mkdtemp(join(temporaryRoot, "codex-security-stacks-"));
  try {
    const directory = join(scratch, "work");
    await mkdir(directory, { mode: 0o700 });
    const inputs = join(scratch, "inputs");
    const state = join(directory, "run.sqlite");
    const agent = { stackTarget: options.repository, signal: options.signal };
    const packet = await prepareStackCheckPacket(
      {
        cve: options.cve,
        sourcesPath: options.sourcesPath,
        sinksPath: options.sinksPath,
        stacksPath: options.stacksPath,
        inputsDir: inputs,
        repository: options.repository,
        toolRevision: await toolRevision(options.signal),
        signal: options.signal,
      },
      {
        emit: options.emit,
        async analyze({ cve, sinks }, advisoryDetails) {
          options.emit("stage", cve, { stage: "advisory_analysis" });
          const analysisDirectory = join(scratch, "advisory");
          await mkdir(analysisDirectory, { mode: 0o700 });
          return analyzeStackAdvisory(
            { cve, sinks, advisoryDetails },
            (prompt) =>
              options.runAgent({
                ...agent,
                directory: analysisDirectory,
                readOnly: true,
                prompt,
              }),
          );
        },
      },
    );
    await executeStackRun("init", {
      state,
      inputs,
      repo: options.repository,
      signal: options.signal,
    });
    options.emit("investigation");
    await options.runAgent({
      ...agent,
      directory,
      prompt: await stackInvestigationPrompt({
        directory,
        inputs,
        repo: options.repository,
        state,
      }),
    });
    options.signal.throwIfAborted();
    const result = await readFinalStackReport(state, {
      packet,
      repository: options.repository,
      signal: options.signal,
    });
    const expected = packet.manifest;
    if (
      result.runId !== expected.runId ||
      result.attemptId !== expected.attemptId ||
      result.inputDigest !== expected.inputDigest ||
      result.toolRevision !== expected.toolRevision ||
      result.cve !== expected.cve ||
      result.target.repository !== expected.target.repository ||
      result.target.sha !== expected.target.sha
    )
      throw new CodexSecurityError(
        "Finalized report does not belong to the requested stack investigation.",
      );
    return result;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

async function stackInvestigationPrompt(session: StackInvestigationSession) {
  const instructions = await readFile(instructionsPath, "utf8");
  return [
    instructions,
    "Investigate the initialized attempt described below and use the supplied command prefix for every invocation. Each directory, file and executable path is an argument, including paths containing spaces. The packet and checkout are read-only. Store temporary data in the working directory.",
    JSON.stringify({
      command: [
        process.execPath,
        join(packageRoot, "bin", "codex-security.mjs"),
        "exploitability",
        "run",
      ],
      ...session,
    }),
    "Call finalize before returning. The host reads the completed report from the investigation database.",
  ].join("\n\n");
}
