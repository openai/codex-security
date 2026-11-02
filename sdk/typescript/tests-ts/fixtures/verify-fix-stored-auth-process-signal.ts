import { writeSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { main, runCodexSkillCommand } from "../../src/cli.js";
import type { Finding } from "../../src/index.js";
import {
  acquireCodexSecurityCredentialHomeLock,
  prepareCodexSecurityCredentialHome,
  resolveCodexCommand,
} from "../../src/runtime.js";

const mode = process.argv[2] as
  "git" | "helper-unresponsive" | "helper-responsive";
const signal = process.argv[3] === "SIGINT" ? "SIGINT" : "SIGTERM";
const root = await mkdtemp(join(tmpdir(), "verify-fix-stored-auth-signal-"));
const repository = join(root, "repository");
const ambientHome = join(root, "ambient");
const stateDirectory = join(root, "state");
const gitMarker = join(root, "git.json");
const helperMarker = join(root, "helper.txt");
const invocationMarker = join(root, "invocations.jsonl");
const workerMarker = join(root, "worker-started");
const git = join(root, "git");
const codex = join(root, "codex");
const value = (input: string): string => JSON.stringify(input);

await mkdir(join(repository, ".git"), { recursive: true });
await mkdir(ambientHome, { recursive: true, mode: 0o700 });
await writeFile(
  git,
  `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
const mode = ${value(mode)};
const marker = ${value(gitMarker)};
const repository = ${value(repository)};
if (mode === "git" && !fs.existsSync(marker)) {
  fs.writeFileSync(marker, JSON.stringify({ gitPid: process.pid, cliPid: process.ppid, signal: ${value(signal)} }));
  setTimeout(() => process.kill(process.ppid, ${value(signal)}), 100);
  setInterval(() => {}, 1000);
} else {
  const joined = args.join(" ");
  const output = joined.includes("--show-toplevel")
    ? repository
    : joined.includes("--git-common-dir") || joined.includes("--absolute-git-dir")
      ? repository + "/.git"
      : "false";
  process.stdout.write(output + "\\n");
}
`,
  { mode: 0o755 },
);
await writeFile(
  codex,
  `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
fs.appendFileSync(${value(invocationMarker)}, JSON.stringify(args) + "\\n");
if (args.includes("login") && args.includes("status")) {
  fs.writeFileSync(${value(helperMarker)}, JSON.stringify({ helperPid: process.pid, cliPid: process.ppid, signal: ${value(signal)} }) + "\\n");
  process.on("SIGTERM", () => {
    fs.appendFileSync(${value(helperMarker)}, "SIGTERM_RECEIVED\\n");
    if (${value(mode)} === "helper-responsive") {
      setTimeout(() => {
        fs.appendFileSync(${value(helperMarker)}, "GRACEFUL_EXIT\\n");
        process.exit(0);
      }, 50);
    }
  });
  setTimeout(() => {
    fs.appendFileSync(${value(helperMarker)}, "SIGNAL_SENT\\n");
    process.kill(process.ppid, ${value(signal)});
  }, 100);
  setInterval(() => {}, 1000);
} else {
  fs.writeFileSync(${value(workerMarker)}, JSON.stringify(args));
  process.exit(1);
}
`,
  { mode: 0o755 },
);
await chmod(git, 0o755);
await chmod(codex, 0o755);

const environment: NodeJS.ProcessEnv = {
  ...process.env,
  TERM: "xterm-256color",
  PATH: `${dirname(process.execPath)}:${root}:/usr/bin:/bin`,
  CODEX_CLI_PATH: codex,
  CODEX_HOME: ambientHome,
  CODEX_SECURITY_STATE_DIR: stateDirectory,
};
delete environment["CI"];
delete process.env["CI"];
Object.assign(process.env, environment);
if (process.stderr.isTTY !== true) {
  throw new Error("Stored-auth process-signal fixture requires a real TTY");
}
process.stderr.write("PTY_CAPABLE_true\n");
const finding = {
  findingId: "csf_1",
  occurrenceId: "occ_1",
  title: "Synthetic stored-auth finding",
  severity: "high",
  description: "Synthetic verification evidence",
  codeEvidence: [{ path: "src/finding.ts", code: "unsafe();" }],
} as unknown as Finding;
const initialInterruptListeners = process.listenerCount("SIGINT");
const initialTerminateListeners = process.listenerCount("SIGTERM");
const dependencies = {
  environment,
  currentDirectory: () => repository,
  now: Date.now,
  setInterval,
  clearInterval,
  addSignalListener: (name: NodeJS.Signals, listener: () => void) =>
    process.on(name, listener),
  removeSignalListener: (name: NodeJS.Signals, listener: () => void) =>
    process.off(name, listener),
  writeSynchronously: (
    stream: NodeJS.WritableStream & { fd?: number },
    contents: string,
  ) => {
    if (stream.fd === undefined) throw new Error("Missing terminal descriptor");
    writeSync(stream.fd, contents);
  },
  forceExit: (name: NodeJS.Signals) => process.kill(process.pid, name),
  checkForUpdate: async () => undefined,
  runWorkbench: async () => ({
    scan: {
      scanId: "scan-stored-auth-signal",
      targetPath: repository,
      findings: [finding],
    },
  }),
  readSavedFindings: async () => [finding],
  runCodex: (
    args: readonly string[],
    output: Parameters<typeof runCodexSkillCommand>[1],
    selected: NodeJS.ProcessEnv,
    input?: string,
  ) =>
    runCodexSkillCommand(
      args,
      output,
      resolveCodexCommand(selected),
      selected,
      input,
    ),
  matchFindings: async () => ({ matches: [], uncertain: [] }),
  exportFindings: async () => undefined,
} as unknown as NonNullable<Parameters<typeof main>[3]>;

try {
  const exitCode = await main(
    [
      "verify-fix",
      "--scan",
      "scan-stored-auth-signal",
      "--json",
      "--auth",
      "chatgpt",
    ],
    process.stdout,
    process.stderr,
    dependencies,
  );
  const targeted = JSON.parse(
    await readFile(mode === "git" ? gitMarker : helperMarker, "utf8").then(
      (contents) => contents.split("\n", 1)[0]!,
    ),
  ) as { cliPid: number; helperPid?: number; gitPid?: number };
  const helperState =
    mode === "git" ? "" : await readFile(helperMarker, "utf8");
  const invocations = await readFile(invocationMarker, "utf8").catch(() => "");
  const helperPid = targeted.helperPid;
  let helperAlive = false;
  if (helperPid !== undefined) {
    try {
      process.kill(helperPid, 0);
      helperAlive = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
  }
  if (mode !== "git") {
    const credentialHome =
      await prepareCodexSecurityCredentialHome(environment);
    const release = await acquireCodexSecurityCredentialHomeLock(
      credentialHome,
      AbortSignal.timeout(2_000),
    );
    await release();
    process.stderr.write("LOCK_REACQUIRED\n");
  }
  process.stderr.write(`PID_TARGET_ONLY_${targeted.cliPid === process.pid}\n`);
  process.stderr.write(
    `SIGNAL_SENT_COUNT_${mode === "git" ? 1 : (helperState.match(/SIGNAL_SENT/gu)?.length ?? 0)}\n`,
  );
  process.stderr.write(`HELPER_ALIVE_${helperAlive}\n`);
  process.stderr.write(
    `WORKER_STARTED_${
      invocations.includes("app-server") ||
      (await readFile(workerMarker).then(
        () => true,
        () => false,
      ))
    }\n`,
  );
  if (helperState !== "") process.stderr.write(helperState);
  process.stderr.write(
    `SIGNAL_LISTENERS_${process.listenerCount("SIGINT") - initialInterruptListeners}_${process.listenerCount("SIGTERM") - initialTerminateListeners}\n`,
  );
  process.stderr.write(`STORED_AUTH_EXIT_${exitCode}\n`);
  process.exitCode = exitCode;
} finally {
  await rm(root, { recursive: true, force: true });
}
