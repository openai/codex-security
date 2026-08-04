import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { authStatus, describeAuth } from "./auth.mjs";
import { preflightScan, runScan } from "./scan.mjs";
import { DEFAULT_EFFORT, DEFAULT_MODEL, EFFORT_LEVELS } from "./runner.mjs";
import { SCAN_MODES, targetDescription } from "./targets.mjs";
import {
  PACKAGE_ROOT,
  SEVERITY_LEVELS,
  SecurityError,
  formatDuration,
  redactMessage,
} from "./util.mjs";
import { resolvePython, runWorkbench, workbenchEnvironment } from "./workbench.mjs";

const USAGE = `claude-security — security scanning driven by Claude Code

Usage:
  claude-security scan <repository> [options]
  claude-security scans list [repository] [--json]
  claude-security scans show <scan-id> [--json]
  claude-security scans compare <before-scan-id> <after-scan-id> [--json]
  claude-security auth status
  claude-security --version

Scan options:
  --path <path>              Limit the scan to a path (repeatable)
  --diff <base>[..<head>]    Scan a commit, branch, or revision range
  --working-tree[=<base>]    Scan uncommitted changes against a base (default HEAD)
  --mode <standard|deep>     Scan depth (default: standard)
  --model <model>            Claude model (default: ${DEFAULT_MODEL})
  --effort <level>           ${EFFORT_LEVELS.join(" | ")} (default: ${DEFAULT_EFFORT})
  --knowledge-base <path>    Architecture/threat-model documents (repeatable)
  --output-dir <dir>         Where scan bundles are written (must be outside the repo)
  --archive-existing         Move earlier scan bundles into an archive directory first
  --fail-on-severity <level> Exit non-zero when a finding is at or above this level
  --workers <n>              Deep mode: parallel discovery workers per pass
  --subagents <n>            Deep mode: subagents each worker may use
  --stop-after-no-new <n>    Deep mode: stop after this many passes find nothing new
  --max-discovery-runs <n>   Deep mode: hard ceiling on discovery passes
  --python <path>            Python 3.10+ interpreter for the plugin helpers
  --dry-run                  Print what would be scanned and exit
  --json                     Emit machine-readable JSON
  --quiet                    Suppress live progress
  -h, --help                 Show this help

Scans are billed against the Claude Code subscription that the local \`claude\`
CLI is signed in to. Run \`claude-security auth status\` to check.`;

export async function main(argv) {
  const [command, ...rest] = argv;
  if (command === undefined || command === "-h" || command === "--help" || command === "help") {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (command === "--version" || command === "-v" || command === "version") {
    process.stdout.write(`${await packageVersion()}\n`);
    return 0;
  }
  switch (command) {
    case "scan":
      return await scanCommand(rest);
    case "scans":
      return await scansCommand(rest);
    case "auth":
      return await authCommand(rest);
    default:
      throw new SecurityError(`Unknown command: ${command}\n\n${USAGE}`);
  }
}

async function packageVersion() {
  const manifest = JSON.parse(await readFile(join(PACKAGE_ROOT, "package.json"), "utf8"));
  return manifest.version;
}

/* ------------------------------------------------------------------ parsing */

const SCAN_FLAGS = {
  "--path": { key: "paths", type: "list" },
  "--diff": { key: "diff", type: "value" },
  "--working-tree": { key: "workingTree", type: "optional" },
  "--mode": { key: "mode", type: "value" },
  "--model": { key: "model", type: "value" },
  "--effort": { key: "effort", type: "value" },
  "--knowledge-base": { key: "knowledgeBasePaths", type: "list" },
  "--output-dir": { key: "outputDir", type: "value" },
  "--archive-existing": { key: "archiveExisting", type: "flag" },
  "--fail-on-severity": { key: "failOnSeverity", type: "value" },
  "--workers": { key: "workers", type: "integer" },
  "--subagents": { key: "subagents", type: "integer" },
  "--stop-after-no-new": { key: "stopAfterNoNew", type: "integer" },
  "--max-discovery-runs": { key: "maxDiscoveryRuns", type: "integer" },
  "--python": { key: "python", type: "value" },
  "--dry-run": { key: "dryRun", type: "flag" },
  "--json": { key: "json", type: "flag" },
  "--quiet": { key: "quiet", type: "flag" },
};

function parseFlags(argv, specification) {
  const options = {};
  const positional = [];
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") {
      positional.push(...argv.slice(index + 1));
      break;
    }
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }
    const [name, inlineValue] = token.includes("=")
      ? [token.slice(0, token.indexOf("=")), token.slice(token.indexOf("=") + 1)]
      : [token, undefined];
    const spec = specification[name];
    if (spec === undefined) throw new SecurityError(`Unknown option: ${name}`);
    const readValue = () => {
      if (inlineValue !== undefined) return inlineValue;
      const next = argv[index + 1];
      if (next === undefined || next.startsWith("--")) {
        throw new SecurityError(`${name} requires a value.`);
      }
      index += 1;
      return next;
    };
    switch (spec.type) {
      case "flag":
        options[spec.key] = true;
        break;
      case "value":
        options[spec.key] = readValue();
        break;
      case "list":
        options[spec.key] = [...(options[spec.key] ?? []), readValue()];
        break;
      case "integer": {
        const parsed = Number.parseInt(readValue(), 10);
        if (!Number.isInteger(parsed) || parsed < 0) {
          throw new SecurityError(`${name} requires a non-negative integer.`);
        }
        options[spec.key] = parsed;
        break;
      }
      // Only `--flag=value` supplies a value here. A space-separated form would
      // happily swallow the repository positional in `scan --working-tree .`.
      case "optional":
        options[spec.key] = inlineValue ?? true;
        break;
      default:
        throw new SecurityError(`Unsupported option kind for ${name}`);
    }
  }
  return { options, positional };
}

function validateScanOptions(options) {
  if (options.mode !== undefined && !SCAN_MODES.includes(options.mode)) {
    throw new SecurityError(`--mode must be one of: ${SCAN_MODES.join(", ")}`);
  }
  if (options.effort !== undefined && !EFFORT_LEVELS.includes(options.effort)) {
    throw new SecurityError(`--effort must be one of: ${EFFORT_LEVELS.join(", ")}`);
  }
  if (
    options.failOnSeverity !== undefined &&
    !SEVERITY_LEVELS.includes(options.failOnSeverity)
  ) {
    throw new SecurityError(`--fail-on-severity must be one of: ${SEVERITY_LEVELS.join(", ")}`);
  }
}

/* --------------------------------------------------------------- scan command */

async function scanCommand(argv) {
  const { options, positional } = parseFlags(argv, SCAN_FLAGS);
  validateScanOptions(options);
  const repository = positional[0] ?? ".";
  if (positional.length > 1) {
    throw new SecurityError(`scan accepts one repository; got: ${positional.join(", ")}`);
  }

  const auth = await authStatus();
  if (!auth.authenticated) {
    throw new SecurityError(
      `${describeAuth(auth)}\nRun \`claude\` and sign in, then retry the scan.`,
    );
  }

  if (options.dryRun) {
    const preflight = await preflightScan(repository, options);
    const payload = {
      repository: preflight.repository,
      target: targetDescription(preflight.target),
      mode: preflight.mode,
      skill: preflight.skill,
      model: preflight.model,
      effort: preflight.effort,
      outputRoot: preflight.outputRoot,
      revision: preflight.revision,
      changedFiles: preflight.changedFiles,
      authentication: auth.source,
    };
    if (options.json) process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    else {
      process.stdout.write(
        [
          `Repository   ${payload.repository}`,
          `Target       ${payload.target}`,
          `Mode         ${payload.mode} (${payload.skill})`,
          `Model        ${payload.model}, effort ${payload.effort}`,
          `Output       ${payload.outputRoot}`,
          `Revision     ${payload.revision ?? "unversioned"}`,
          `Auth         ${payload.authentication}`,
          "",
          "Dry run: nothing was scanned.",
        ].join("\n") + "\n",
      );
    }
    return 0;
  }

  const controller = new AbortController();
  const interrupt = () => controller.abort(new SecurityError("Interrupted.", { exitCode: 130 }));
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", interrupt);

  const startedAt = Date.now();
  const progress = createProgressReporter({
    quiet: options.quiet === true || options.json === true,
  });

  try {
    const summary = await runScan(repository, {
      ...options,
      signal: controller.signal,
      observer: progress.observer,
    });
    progress.done();
    const elapsed = formatDuration(Date.now() - startedAt);
    if (options.json) {
      process.stdout.write(`${JSON.stringify({ ...summary, elapsed }, null, 2)}\n`);
    } else {
      process.stdout.write(renderSummary(summary, elapsed));
    }
    return summary.failedSeverityGate ? 3 : 0;
  } catch (error) {
    progress.done();
    throw error;
  } finally {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
  }
}

/* -------------------------------------------------------------- scans command */

async function scansCommand(argv) {
  const [subcommand, ...rest] = argv;
  const { options, positional } = parseFlags(rest, {
    "--json": { key: "json", type: "flag" },
    "--limit": { key: "limit", type: "integer" },
    "--python": { key: "python", type: "value" },
  });
  const python = await resolvePython(options.python);
  const workbenchOptions = { python, environment: workbenchEnvironment(python) };

  switch (subcommand) {
    case "list": {
      const result = await runWorkbench(workbenchOptions, [
        "list-scans",
        "--limit",
        String(options.limit ?? 20),
        ...(positional[0] === undefined ? [] : ["--target-path", positional[0]]),
      ]);
      if (options.json) {
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        return 0;
      }
      process.stdout.write(renderScanList(result["scans"] ?? []));
      return 0;
    }
    case "show": {
      if (positional[0] === undefined) throw new SecurityError("scans show requires a scan ID.");
      const result = await runWorkbench(workbenchOptions, ["get-scan", "--scan-id", positional[0]]);
      process.stdout.write(
        options.json ? `${JSON.stringify(result, null, 2)}\n` : renderScanDetail(result),
      );
      return 0;
    }
    case "compare": {
      if (positional[0] === undefined || positional[1] === undefined) {
        throw new SecurityError("scans compare requires a before and an after scan ID.");
      }
      const result = await runWorkbench(workbenchOptions, [
        "compare-scans",
        "--before-scan-id",
        positional[0],
        "--after-scan-id",
        positional[1],
      ]);
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    }
    default:
      throw new SecurityError(`Unknown scans subcommand: ${subcommand ?? "(none)"}`);
  }
}

async function authCommand(argv) {
  const [subcommand] = argv;
  if (subcommand !== undefined && subcommand !== "status") {
    throw new SecurityError(
      `Unknown auth subcommand: ${subcommand}. Sign in with \`claude\` itself; ` +
        `claude-security only reports the status.`,
    );
  }
  const status = await authStatus();
  process.stdout.write(`${describeAuth(status)}\n`);
  return status.authenticated ? 0 : 1;
}

/* ------------------------------------------------------------------ rendering */

/**
 * Live progress for a scan.
 *
 * A scan is long and mostly silent, so the reporter surfaces which phase the
 * session is in rather than streaming raw model output: the useful signal is
 * "still reviewing files", not the prose.
 */
function createProgressReporter({ quiet }) {
  const stream = process.stderr;
  const interactive = quiet !== true && stream.isTTY === true;
  let lastLine = "";
  let toolCount = 0;

  const write = (text) => {
    if (quiet) return;
    if (!interactive) {
      if (text !== lastLine) stream.write(`${text}\n`);
      lastLine = text;
      return;
    }
    stream.write(`\r\u001B[2K${text.slice(0, (stream.columns ?? 80) - 1)}`);
    lastLine = text;
  };

  return {
    observer: {
      onScanDirReady: (scanDir) => write(`Scan directory: ${scanDir}`),
      onScanStarted: ({ skill }) => write(`Starting ${skill}…`),
      onToolUse: ({ name, input }) => {
        toolCount += 1;
        write(`[${toolCount}] ${name}${describeToolInput(name, input)}`);
      },
      onDeepScanStarted: ({ config }) =>
        write(
          `Deep scan: ${config.workers} worker(s)/pass, stop after ${config.stopAfterNoNew} quiet passes, max ${config.maxDiscoveryRuns} passes`,
        ),
      onDeepRoundStarted: ({ round, workers }) =>
        write(`Discovery pass ${round}: ${workers} worker(s)…`),
      onDeepRoundFinished: ({ round, newFindings, canonicalCandidates }) =>
        write(
          `Discovery pass ${round}: +${newFindings} new, ${canonicalCandidates} candidate(s) total`,
        ),
      onDeepScanFinished: ({ terminalReason, discoveryPasses }) =>
        write(`Discovery ${terminalReason} after ${discoveryPasses} pass(es)`),
      onDeepTailStarted: () => write("Validating, analyzing attack paths, and reporting…"),
      onWarning: (warning) => {
        if (interactive) stream.write("\r\u001B[2K");
        if (!quiet) stream.write(`warning: ${redactMessage(warning)}\n`);
      },
    },
    done() {
      if (interactive && !quiet) stream.write("\r\u001B[2K");
    },
  };
}

function describeToolInput(name, input) {
  if (name === "Read" && typeof input?.file_path === "string") {
    return ` ${shorten(input.file_path)}`;
  }
  if ((name === "Grep" || name === "Glob") && typeof input?.pattern === "string") {
    return ` ${shorten(input.pattern)}`;
  }
  if (name === "Bash" && typeof input?.description === "string") {
    return ` ${shorten(input.description)}`;
  }
  if (name === "Task" && typeof input?.description === "string") {
    return ` ${shorten(input.description)}`;
  }
  if (name === "Skill" && typeof input?.skill === "string") return ` ${input.skill}`;
  return "";
}

function shorten(value, width = 60) {
  return value.length <= width ? value : `…${value.slice(value.length - width + 1)}`;
}

function renderSummary(summary, elapsed) {
  const lines = [""];
  const bySeverity = new Map();
  for (const finding of summary.findings) {
    bySeverity.set(finding.severity, (bySeverity.get(finding.severity) ?? 0) + 1);
  }
  const counts = SEVERITY_LEVELS.filter((level) => bySeverity.has(level))
    .map((level) => `${bySeverity.get(level)} ${level}`)
    .join(", ");

  lines.push(
    summary.findings.length === 0
      ? `No findings reported (coverage: ${summary.completeness}) in ${elapsed}.`
      : `${summary.findings.length} finding(s) — ${counts} — coverage: ${summary.completeness} — ${elapsed}`,
  );

  if (summary.findings.length > 0) {
    lines.push("");
    const ordered = [...summary.findings].sort(
      (left, right) =>
        SEVERITY_LEVELS.indexOf(left.severity) - SEVERITY_LEVELS.indexOf(right.severity),
    );
    for (const finding of ordered) {
      const location = finding.path
        ? ` (${finding.path}${finding.line === null ? "" : `:${finding.line}`})`
        : "";
      lines.push(`  ${finding.severity.padEnd(13)} ${finding.title}${location}`);
    }
  }

  lines.push("");
  if (summary.reportPath !== null) lines.push(`Report   ${summary.reportPath}`);
  if (summary.sarifPath !== null) lines.push(`SARIF    ${summary.sarifPath}`);
  lines.push(`Bundle   ${summary.scanDir}`);
  lines.push(`Scan ID  ${summary.scanId}`);
  if (typeof summary.costUsd === "number") {
    lines.push(
      `Usage    ~$${summary.costUsd.toFixed(2)} equivalent (billed against your Claude subscription, not per-token)`,
    );
  }
  for (const warning of summary.warnings ?? []) lines.push(`warning: ${redactMessage(warning)}`);
  if (summary.failedSeverityGate) {
    lines.push("");
    lines.push("Severity gate failed: exiting 3.");
  }
  return `${lines.join("\n")}\n`;
}

function renderScanList(scans) {
  if (scans.length === 0) return "No scans recorded yet.\n";
  const lines = [];
  for (const scan of scans) {
    const status = scan["progress"]?.["status"] ?? "unknown";
    const findings = scan["findingCount"];
    lines.push(
      [
        String(scan["scanId"] ?? "").slice(0, 8),
        String(scan["startedAt"] ?? "").slice(0, 19).replace("T", " "),
        String(status).padEnd(9),
        String(scan["mode"] ?? "").padEnd(8),
        findings === undefined || findings === null
          ? "".padEnd(11)
          : `${findings} finding${findings === 1 ? "" : "s"}`.padEnd(11),
        scan["targetPath"] ?? "",
      ].join("  "),
    );
  }
  return `${lines.join("\n")}\n`;
}

function renderScanDetail(result) {
  const scan = result["scan"] ?? {};
  const severities = scan["severityCounts"] ?? {};
  const counts = SEVERITY_LEVELS.filter((level) => severities[level])
    .map((level) => `${severities[level]} ${level}`)
    .join(", ");
  const lines = [
    `Scan ID    ${scan["scanId"] ?? "(unknown)"}`,
    `Status     ${scan["progress"]?.["status"] ?? "unknown"} (phase: ${scan["progress"]?.["phase"] ?? "unknown"})`,
    `Mode       ${scan["mode"] ?? "unknown"}`,
    `Target     ${scan["targetPath"] ?? "(unknown)"}`,
    ...(scan["targetRevision"] ? [`Revision   ${scan["targetRevision"]}`] : []),
    `Findings   ${scan["findingCount"] ?? 0}${counts === "" ? "" : ` — ${counts}`}`,
    `Bundle     ${scan["scanDir"] ?? "(unknown)"}`,
  ];
  if (scan["failureMessage"]) lines.push(`Failure    ${redactMessage(scan["failureMessage"])}`);
  for (const warning of scan["warnings"] ?? []) lines.push(`warning: ${redactMessage(warning)}`);
  return `${lines.join("\n")}\n`;
}
