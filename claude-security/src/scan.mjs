import { mkdir, readdir, rename, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { runDeepScan } from "./deep.mjs";
import { scanPrompt } from "./prompt.mjs";
import { DEFAULT_EFFORT, DEFAULT_MODEL, runClaudeSession, scanSettings } from "./runner.mjs";
import {
  changedFileCount,
  normalizeTarget,
  repositoryRevision,
  resolveRepositoryPath,
  skillNameFor,
} from "./targets.mjs";
import {
  IncompleteScanError,
  PLUGIN_ROOT,
  SecurityError,
  canonicalPath,
  ensureDirectory,
  isFile,
  pathExists,
  readJson,
  requireOutsideRepository,
  safeSegment,
  scanRootDirectory,
  severityAtLeast,
  stateDirectory,
} from "./util.mjs";
import { resolvePython, runWorkbench, workbenchEnvironment } from "./workbench.mjs";

const CANONICAL_FILES = ["scan-manifest.json", "findings.json", "coverage.json"];

export async function preflightScan(repositoryArgument, options) {
  const python = await resolvePython(options.python);
  const repository = await resolveRepositoryPath(repositoryArgument);
  const target = await normalizeTarget(repository, options);
  const mode = options.mode ?? "standard";
  if (mode === "deep" && (target.kind === "refs" || target.kind === "working_tree")) {
    throw new SecurityError("Deep mode does not support diff targets. Use --mode standard.");
  }
  const outputRoot = options.outputDir
    ? resolve(options.outputDir)
    : scanRootDirectory(basename(repository));
  await requireOutsideRepository(outputRoot, repository, "output");
  return {
    python,
    repository,
    target,
    mode,
    outputRoot,
    skill: skillNameFor(target, mode),
    model: options.model ?? DEFAULT_MODEL,
    effort: options.effort ?? DEFAULT_EFFORT,
    revision: await repositoryRevision(repository),
    changedFiles: await changedFileCount(repository, target).catch(() => null),
    knowledgeBasePaths: options.knowledgeBasePaths ?? [],
  };
}

export async function runScan(repositoryArgument, options) {
  const preflight = await preflightScan(repositoryArgument, options);
  const { python, repository, target, mode } = preflight;
  const observer = options.observer ?? {};
  const signal = options.signal;
  const environmentForWorkbench = workbenchEnvironment(python);

  const scanDir = await prepareScanDirectory(preflight);
  observer.onScanDirReady?.(scanDir);

  const archivedScanDir = options.archiveExisting
    ? await archiveSiblingScans(preflight.outputRoot, scanDir)
    : null;
  if (archivedScanDir !== null) observer.onOutputArchived?.(archivedScanDir);

  const recipe = {
    repository,
    target: {
      kind: target.kind,
      paths: [...target.paths],
      ...(target.base === undefined ? {} : { base: target.base }),
      ...(target.head === undefined ? {} : { head: target.head }),
      ...(target.baseRef === undefined ? {} : { baseRef: target.baseRef }),
      ...(target.headRef === undefined ? {} : { headRef: target.headRef }),
    },
    mode,
    ...(preflight.revision === null ? {} : { repositoryRevision: preflight.revision }),
    config: {
      runtime: "claude-code",
      model: preflight.model,
      effort: preflight.effort,
      ...(mode === "deep" ? { deepScan: deepScanOptions(options) } : {}),
    },
    ...(options.failOnSeverity === undefined ? {} : { failOnSeverity: options.failOnSeverity }),
    ...(preflight.knowledgeBasePaths.length === 0
      ? {}
      : { knowledgeBasePaths: preflight.knowledgeBasePaths }),
  };

  const workbenchOptions = { python, environment: environmentForWorkbench, signal };
  const registration = await runWorkbench(
    { ...workbenchOptions, failureMessage: "Could not register the scan" },
    [
      "register-cli-scan",
      "--scan-dir",
      scanDir,
      "--repository",
      repository,
      "--recipe-json",
      JSON.stringify(recipe),
      ...(options.archiveExisting ? ["--archive-existing"] : []),
      ...(archivedScanDir === null ? [] : ["--archived-scan-dir", archivedScanDir]),
    ],
  );

  const scanId = registration["scanId"];
  const targetId = registration["targetId"];
  const contract = registration["contract"];
  if (typeof scanId !== "string" || typeof targetId !== "string") {
    throw new SecurityError("The workbench returned an invalid scan registration.");
  }
  const { targetKind, snapshotDigest } = readContractTarget(contract);
  const targetRevision =
    registration["targetRevision"] === "unversioned" ? null : registration["targetRevision"];

  try {
    const falsePositivePath = await writeFalsePositiveFeedback(
      workbenchOptions,
      scanId,
      targetId,
      scanDir,
    );
    const knowledgeBasePath = await writeKnowledgeBaseManifest(
      scanDir,
      preflight.knowledgeBasePaths,
    );
    const targetPathsFile =
      target.kind === "paths" ? await writeTargetPaths(scanDir, target.paths) : null;

    const sessionEnvironment = {
      ...environmentForWorkbench,
      CLAUDE_SECURITY_STARTED_AT: new Date().toISOString(),
      CLAUDE_SECURITY_REPOSITORY: repository,
      CLAUDE_SECURITY_SCAN_DIR: scanDir,
      CLAUDE_SECURITY_PLUGIN_ROOT: PLUGIN_ROOT,
      CLAUDE_SECURITY_STATE_DIR: stateDirectory(),
      CLAUDE_SECURITY_SCAN_ID: scanId,
      CLAUDE_SECURITY_TARGET_ID: targetId,
      CLAUDE_SECURITY_TARGET_DISPLAY_NAME: basename(repository),
      CLAUDE_SECURITY_TARGET_KIND: targetKind,
      ...(targetRevision === null ? {} : { CLAUDE_SECURITY_TARGET_REVISION: targetRevision }),
      ...(snapshotDigest === null
        ? {}
        : { CLAUDE_SECURITY_TARGET_SNAPSHOT_DIGEST: snapshotDigest }),
      ...(knowledgeBasePath === null
        ? {}
        : { CLAUDE_SECURITY_KNOWLEDGE_BASE: knowledgeBasePath }),
      ...(targetPathsFile === null
        ? {}
        : { CLAUDE_SECURITY_TARGET_PATHS_FILE: targetPathsFile }),
    };

    const sessionOptions = {
      cwd: scanDir,
      environment: sessionEnvironment,
      model: preflight.model,
      effort: preflight.effort,
      settings: scanSettings(repository),
      addDirs: [
        repository,
        ...preflight.knowledgeBasePaths.map((path) => resolve(path)),
      ],
      signal,
      observer,
    };

    observer.onScanStarted?.({ scanId, scanDir, skill: preflight.skill });

    const session =
      mode === "deep"
        ? await runDeepScan({
            ...sessionOptions,
            python,
            scanId,
            scanDir,
            repository,
            target,
            workbenchOptions,
            deep: deepScanOptions(options),
            hasKnowledgeBase: knowledgeBasePath !== null,
            falsePositiveFeedbackPath: falsePositivePath ?? undefined,
            sessionName: `claude-security deep ${basename(repository)}`,
          })
        : await runClaudeSession({
            ...sessionOptions,
            sessionName: `claude-security ${basename(repository)}`,
            prompt: scanPrompt({
              target,
              mode,
              hasKnowledgeBase: knowledgeBasePath !== null,
              falsePositiveFeedbackPath: falsePositivePath ?? undefined,
            }),
          });

    if (session.isError) {
      throw new IncompleteScanError(
        `The scan session ended without completing (${session.subtype ?? "error"}).` +
          (session.text ? `\n${session.text.slice(0, 2000)}` : ""),
      );
    }

    await requireCanonicalArtifacts(scanDir, session);

    await runWorkbench(workbenchOptions, ["prepare-scan-completion", "--scan-id", scanId]);
    const completion = await runWorkbench(
      { ...workbenchOptions, failureMessage: "Could not seal the scan contract" },
      ["complete-scan", "--scan-id", scanId],
    );

    const warnings = collectWarnings(completion);
    for (const warning of warnings) observer.onWarning?.(warning);

    const summary = await summarizeScan(scanDir, {
      scanId,
      repository,
      target,
      mode,
      model: session.model ?? preflight.model,
      costUsd: session.costUsd,
      usage: session.usage,
      warnings,
    });

    if (
      options.failOnSeverity !== undefined &&
      summary.findings.some((finding) => severityAtLeast(finding.severity, options.failOnSeverity))
    ) {
      summary.failedSeverityGate = true;
    }
    return summary;
  } catch (error) {
    await runWorkbench({ ...workbenchOptions, signal: undefined }, [
      "fail-scan",
      "--scan-id",
      scanId,
      "--message",
      String(error?.message ?? error).slice(0, 2400),
    ]).catch(() => {});
    throw error;
  }
}

function deepScanOptions(options) {
  return {
    ...(options.workers === undefined ? {} : { workers: options.workers }),
    ...(options.subagents === undefined ? {} : { subagents: options.subagents }),
    ...(options.stopAfterNoNew === undefined ? {} : { stopAfterNoNew: options.stopAfterNoNew }),
    ...(options.maxDiscoveryRuns === undefined
      ? {}
      : { maxDiscoveryRuns: options.maxDiscoveryRuns }),
  };
}

function pluginRootForSession() {
  return new URL("../plugin", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
}

function readContractTarget(contract) {
  const contractTarget =
    contract && typeof contract === "object" ? contract["target"] : undefined;
  const allowedKinds =
    contractTarget && typeof contractTarget === "object"
      ? contractTarget["allowedKinds"]
      : undefined;
  const targetKind =
    Array.isArray(allowedKinds) && allowedKinds.length === 1 ? allowedKinds[0] : undefined;
  if (typeof targetKind !== "string") {
    throw new SecurityError("The workbench returned an ambiguous scan target kind.");
  }
  const diffTarget = contract && typeof contract === "object" ? contract["diffTarget"] : undefined;
  const digest =
    targetKind === "git_diff" && diffTarget && typeof diffTarget === "object"
      ? diffTarget["contentDigest"]
      : contractTarget && typeof contractTarget === "object"
        ? contractTarget["requiredSnapshotDigest"]
        : undefined;
  return { targetKind, snapshotDigest: typeof digest === "string" ? digest : null };
}

async function prepareScanDirectory(preflight) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const revision = preflight.revision === null ? "unversioned" : preflight.revision.slice(0, 12);
  const scanDir = join(preflight.outputRoot, `${safeSegment(revision)}_${safeSegment(stamp)}`);
  await ensureDirectory(scanDir);
  const entries = await readdir(scanDir);
  if (entries.length > 0) {
    throw new SecurityError(`The scan directory must be empty before the scan starts: ${scanDir}`);
  }
  return await canonicalPath(scanDir);
}

/**
 * Moves previously completed scans of the same repository out of the way.
 *
 * Only sibling scan directories are touched, and they are moved rather than
 * deleted: an operator who passes --archive-existing wants a clean latest-scan
 * view, not the loss of the evidence behind an earlier report.
 */
async function archiveSiblingScans(outputRoot, currentScanDir) {
  const entries = await readdir(outputRoot, { withFileTypes: true }).catch(() => []);
  const stale = entries.filter(
    (entry) => entry.isDirectory() && join(outputRoot, entry.name) !== currentScanDir,
  );
  if (stale.length === 0) return null;
  const archiveDir = join(
    outputRoot,
    `archive-${new Date().toISOString().replace(/[:.]/g, "-")}`,
  );
  await ensureDirectory(archiveDir);
  for (const entry of stale) {
    if (entry.name.startsWith("archive-")) continue;
    await rename(join(outputRoot, entry.name), join(archiveDir, entry.name));
  }
  return archiveDir;
}

async function writeFalsePositiveFeedback(workbenchOptions, scanId, targetId, scanDir) {
  const feedback = await runWorkbench(
    { ...workbenchOptions, failureMessage: "Could not load false-positive feedback" },
    ["get-scan-feedback", "--scan-id", scanId],
  );
  const examples = feedback["falsePositives"];
  if (feedback["scanId"] !== scanId || feedback["targetId"] !== targetId) {
    throw new SecurityError("The workbench returned feedback for a different scan.");
  }
  if (!Array.isArray(examples) || examples.length === 0) return null;
  const path = join(scanDir, "artifacts", "01_context", "false_positive_feedback.json");
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(examples, null, 2)}\n`, { mode: 0o600 });
  return path;
}

async function writeKnowledgeBaseManifest(scanDir, paths) {
  if (paths.length === 0) return null;
  const documents = [];
  for (const entry of paths) {
    const absolute = resolve(entry);
    if (!(await pathExists(absolute))) {
      throw new SecurityError(`--knowledge-base path does not exist: ${entry}`);
    }
    documents.push(absolute);
  }
  const path = join(scanDir, "artifacts", "01_context", "knowledge_base.json");
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify({ documents }, null, 2)}\n`, { mode: 0o600 });
  return path;
}

async function writeTargetPaths(scanDir, paths) {
  const path = join(scanDir, "artifacts", "01_context", "target_paths.json");
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(paths)}\n`, { mode: 0o400 });
  return path;
}

async function requireCanonicalArtifacts(scanDir, session) {
  const missing = [];
  for (const name of CANONICAL_FILES) {
    if (!(await isFile(join(scanDir, name)))) missing.push(name);
  }
  if (missing.length === 0) return;
  throw new IncompleteScanError(
    `The scan finished without writing ${missing.join(", ")} to ${scanDir}. ` +
      `The session's final message was:\n${(session.text || "(empty)").slice(0, 2000)}`,
  );
}

function collectWarnings(completion) {
  const scan = completion["scan"];
  if (!scan || typeof scan !== "object" || !Array.isArray(scan["warnings"])) return [];
  return scan["warnings"].filter((warning) => typeof warning === "string");
}

async function summarizeScan(scanDir, context) {
  const findingsDocument = await readJson(join(scanDir, "findings.json"));
  const coverage = await readJson(join(scanDir, "coverage.json")).catch(() => null);
  const findings = (findingsDocument["findings"] ?? []).map((finding) => ({
    id: finding["findingId"],
    title: finding["title"],
    severity: finding["severity"]?.["level"] ?? "informational",
    confidence: finding["confidence"]?.["level"] ?? "medium",
    path: finding["locations"]?.[0]?.["path"] ?? "",
    line: finding["locations"]?.[0]?.["startLine"] ?? null,
  }));
  const reportPath = join(scanDir, "report.md");
  return {
    ...context,
    scanDir,
    reportPath: (await isFile(reportPath)) ? reportPath : null,
    sarifPath: (await isFile(join(scanDir, "exports", "results.sarif")))
      ? join(scanDir, "exports", "results.sarif")
      : null,
    findings,
    completeness: coverage?.["completeness"] ?? "unknown",
    failedSeverityGate: false,
  };
}
