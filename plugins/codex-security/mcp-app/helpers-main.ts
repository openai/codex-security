import { closeSync, readFileSync } from "node:fs";
import { resolveSecurityMdCommand } from "./src/helpers/resolve-security-md";
import { decodePosixBytes } from "./src/helpers/posix-path";
import { windowsBinding } from "./src/native";
import { normalizeCandidatesCommand } from "./src/helpers/normalize-candidates";
import { validatePatchRiskAssessmentCommand } from "./src/helpers/validate-patch-risk-assessment";
import { deepReviewInputCommand } from "./src/helpers/deep-review-input";
import { rankShardsCommand } from "./src/helpers/rank-shards";
import { rankPoolCommand } from "./src/helpers/rank-pool";
import { bindRepoScopesCommand } from "./src/helpers/bind-repo-scopes";
import { snapshotSqliteCommand } from "./src/helpers/snapshot-sqlite";
import { generateInScopeFilesCommand } from "./src/helpers/generate-in-scope-files";
import { workbenchCommand } from "./src/helpers/workbench-command";
import { workbenchDataCommand } from "./src/helpers/workbench-data-command";
import { workbenchFindingCommand } from "./src/helpers/workbench-finding-command";
import { workbenchCompletionCommand } from "./src/helpers/workbench-completion-command";
import { workbenchProgressCommand } from "./src/helpers/workbench-progress-command";
import { workbenchDeepCommand } from "./src/helpers/workbench-deep-command";
import { workbenchLifecycleCommand } from "./src/helpers/workbench-lifecycle-command";
import { workbenchResultsCommand } from "./src/helpers/workbench-results-command";
import { generateRankInputCommand } from "./src/helpers/generate-rank-input";
import { configPreflightCommand } from "./src/helpers/config-preflight-command";
import { scanArtifactRestorerCommand } from "./src/helpers/scan-artifact-restorer";
import { finalizeScanContractCommand } from "./src/helpers/finalize-scan-contract";
import { scanValidationCommand } from "./src/helpers/validate-scan-contract";
import { deepScanConfigCommand } from "./src/helpers/deep-scan-config";

let commandLine = process.argv.slice(2);
if (process.platform === "win32") {
  const original = windowsBinding().windowsArguments();
  commandLine = original
    .slice(original.length - commandLine.length)
    .map((argument) => argument.toString("utf16le"));
}
let posixHome = process.env.HOME;
if (commandLine[0] === "--helper") {
  if (process.platform === "win32") {
    commandLine = commandLine.slice(1);
  } else {
    const encoded = readFileSync(3, "ascii");
    closeSync(3);
    const [homeSet, home, ...args] = decodePosixBytes(
      Buffer.from(encoded.trim(), "hex"),
    )
      .split("\0")
      .slice(0, -1);
    posixHome = homeSet ? home : undefined;
    commandLine = args;
  }
}
const [command, ...args] = commandLine;
if (command === "resolve-security-md") {
  process.exitCode = resolveSecurityMdCommand(args, posixHome);
} else if (command === "normalize-candidates") {
  process.exitCode = normalizeCandidatesCommand(args, posixHome);
} else if (command === "validate-patch-risk-assessment") {
  process.exitCode = validatePatchRiskAssessmentCommand(args);
} else if (
  command === "validate-scan-contract" ||
  command === "validate-tracking-source"
) {
  process.exitCode = scanValidationCommand(command, args, posixHome);
} else if (
  command === "copy-deep-review-input" ||
  command === "select-deep-review-input"
) {
  process.exitCode = deepReviewInputCommand(command, args, posixHome);
} else if (
  command === "make-rank-shards" ||
  command === "validate-rank-shard" ||
  command === "merge-rank-outputs"
) {
  process.exitCode = rankShardsCommand(command, args, posixHome);
} else if (
  command === "make-rank-pool-plan" ||
  command === "validate-rank-worker" ||
  command === "validate-rank-pool"
) {
  process.exitCode = rankPoolCommand(command, args, posixHome);
} else if (command === "bind-repo-scopes") {
  process.exitCode = bindRepoScopesCommand(args, posixHome);
} else if (command === "snapshot-sqlite") {
  void snapshotSqliteCommand(args, posixHome).then((status) => {
    process.exitCode = status;
  });
} else if (command === "generate-in-scope-files") {
  process.exitCode = generateInScopeFilesCommand(args, posixHome);
} else if (
  command === "compare-scans" ||
  command === "list-unmatched-scan-pairs" ||
  command === "save-scan-comparison" ||
  command === "export-findings" ||
  command === "inspect-linear-publication" ||
  command === "prepare-linear-publication" ||
  command === "record-linear-publications" ||
  command === "set-scan-cost-limit" ||
  command === "finding-workflow" ||
  command === "severity-classification" ||
  command === "read-severity-classification"
) {
  void workbenchDataCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "set-finding-triage" ||
  command === "request-finding-remediation" ||
  command === "request-finding-remediation-action" ||
  command === "claim-finding-remediation-resend" ||
  command === "mark-finding-remediation-delivered" ||
  command === "release-finding-remediation-claim" ||
  command === "cancel-finding-remediation-request" ||
  command === "set-finding-remediation"
) {
  void workbenchFindingCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "prepare-scan-completion" ||
  command === "complete-scan" ||
  command === "complete-budget-exhausted-scan" ||
  command === "cancel-scan" ||
  command === "fail-scan" ||
  command === "preserve-scan-results" ||
  command === "recover-scan-results" ||
  command === "write-scan-draft"
) {
  void workbenchCompletionCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "update-progress" ||
  command === "update-scan-context" ||
  command === "claim-handoff-delivery" ||
  command === "release-handoff-delivery" ||
  command === "attach-scan-continuation-thread" ||
  command === "mark-handoff-delivered"
) {
  void workbenchProgressCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "begin-deep-scan" ||
  command === "get-deep-scan" ||
  command === "claim-deep-scan-coordinator" ||
  command === "upsert-deep-scan-worker" ||
  command === "claim-deep-scan-dedup" ||
  command === "commit-deep-scan-dedup" ||
  command === "finish-deep-scan" ||
  command === "fail-deep-scan" ||
  command === "record-deep-scan-publication-failure"
) {
  void workbenchDeepCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "create-workspace" ||
  command === "save-workspace" ||
  command === "start-scan" ||
  command === "start-prompt-only-scan" ||
  command === "start-headless-standard-scan" ||
  command === "register-cli-scan" ||
  command === "set-scan-thread" ||
  command === "get-scan-recipe" ||
  command === "get-cli-scan-resume"
) {
  void workbenchLifecycleCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "inspect-target" ||
  command === "inspect-setup" ||
  command === "get-workspace" ||
  command === "get-scan" ||
  command === "list-findings"
) {
  void workbenchResultsCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "dashboard" ||
  command === "database-info" ||
  command === "store-findings" ||
  command === "list-stored-findings" ||
  command === "find-potential-duplicates" ||
  command === "store-dedupe-groups" ||
  command === "list-dedupe-groups" ||
  command === "list-global-findings" ||
  command === "list-repositories" ||
  command === "list-scans" ||
  command === "get-scan-feedback"
) {
  void workbenchCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "make-repo-rank-input" ||
  command === "make-repo-scope-input" ||
  command === "make-diff-rank-input"
) {
  process.exitCode = generateRankInputCommand(command, args, posixHome);
} else if (command === "config-preflight") {
  process.exitCode = configPreflightCommand(args);
} else if (command === "deep-scan-config") {
  process.exitCode = deepScanConfigCommand(args);
} else if (command === "scan-artifact-restorer") {
  process.exitCode = scanArtifactRestorerCommand(args);
} else if (command === "finalize-scan-contract") {
  process.exitCode = finalizeScanContractCommand(args);
} else {
  console.error(
    "Usage: launch_codex_security_mcp[.cmd] --helper <resolve-security-md | normalize-candidates | validate-patch-risk-assessment | validate-scan-contract | validate-tracking-source | copy-deep-review-input | select-deep-review-input | make-rank-shards | validate-rank-shard | merge-rank-outputs | make-rank-pool-plan | validate-rank-worker | validate-rank-pool | bind-repo-scopes | snapshot-sqlite | generate-in-scope-files | dashboard | create-workspace | save-workspace | start-scan | start-prompt-only-scan | start-headless-standard-scan | register-cli-scan | set-scan-thread | get-scan-recipe | get-cli-scan-resume | compare-scans | list-unmatched-scan-pairs | save-scan-comparison | export-findings | inspect-linear-publication | prepare-linear-publication | record-linear-publications | set-scan-cost-limit | finding-workflow | severity-classification | read-severity-classification | set-finding-triage | request-finding-remediation | request-finding-remediation-action | claim-finding-remediation-resend | mark-finding-remediation-delivered | release-finding-remediation-claim | cancel-finding-remediation-request | set-finding-remediation | prepare-scan-completion | complete-scan | complete-budget-exhausted-scan | cancel-scan | fail-scan | preserve-scan-results | recover-scan-results | write-scan-draft | update-progress | update-scan-context | claim-handoff-delivery | release-handoff-delivery | attach-scan-continuation-thread | mark-handoff-delivered | begin-deep-scan | get-deep-scan | claim-deep-scan-coordinator | upsert-deep-scan-worker | claim-deep-scan-dedup | commit-deep-scan-dedup | finish-deep-scan | fail-deep-scan | record-deep-scan-publication-failure | database-info | store-findings | list-stored-findings | find-potential-duplicates | store-dedupe-groups | list-dedupe-groups | list-global-findings | list-repositories | list-scans | make-repo-rank-input | make-repo-scope-input | make-diff-rank-input | config-preflight | deep-scan-config | finalize-scan-contract> [options]",
  );
  process.exitCode = 2;
}
