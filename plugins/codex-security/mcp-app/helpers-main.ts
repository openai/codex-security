import { closeSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { resolveSecurityMdCommand } from "./src/helpers/resolve-security-md";
import { decodePosixBytes } from "./src/helpers/posix-path";
import { windowsBinding } from "./src/native";
import { normalizeCandidatesCommand } from "./src/helpers/normalize-candidates";
import { validatePatchRiskAssessmentCommand } from "./src/helpers/validate-patch-risk-assessment";
import { deepReviewInputCommand } from "./src/helpers/deep-review-input";
import { rankShardsCommand } from "./src/helpers/rank-shards";
import { rankPoolCommand } from "./src/helpers/rank-pool";
import { bindRepoScopesCommand } from "./src/helpers/bind-repo-scopes";
import { escapeControls, stringifyJson } from "./src/helpers/json";
import { decodeUtf8 } from "./src/helpers/utf8";

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
const workbenchUsage: Record<string, string> = {
  "database-info":
    "Usage: database-info (reads a JSON absolute state-directory string from stdin)",
  "store-findings":
    "Usage: store-findings\nReads a JSON object from stdin with an absolute stateDirectory and payload.entries containing finding and embedding records; payload.repositoryId is optional.",
  "list-stored-findings":
    "Usage: list-stored-findings\nReads a JSON object from stdin with an absolute stateDirectory, positive payload.limit and non-negative payload.offset.",
  "find-potential-duplicates":
    "Usage: find-potential-duplicates\nReads a JSON object from stdin with an absolute stateDirectory, payload.findingId and payload.scope containing either repositoryId or allRepositories: true.",
  "store-dedupe-groups":
    "Usage: store-dedupe-groups\nReads a JSON object from stdin with an absolute stateDirectory and payload.groups containing arrays of finding IDs.",
  "list-dedupe-groups":
    "Usage: list-dedupe-groups\nReads a JSON object from stdin with an absolute stateDirectory and payload.findingId.",
  dashboard:
    "Usage: dashboard\nReads a JSON object from stdin with an absolute stateDirectory and payload containing view (findings or groups), sort, limit and offset; direction, query, repository and id are optional.",
};
if (command === "resolve-security-md") {
  process.exitCode = resolveSecurityMdCommand(args, posixHome);
} else if (command === "normalize-candidates") {
  process.exitCode = normalizeCandidatesCommand(args, posixHome);
} else if (command === "validate-patch-risk-assessment") {
  process.exitCode = validatePatchRiskAssessmentCommand(args);
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
} else if (Object.hasOwn(workbenchUsage, command)) {
  void (async () => {
    const { values } = parseArgs({
      args,
      options: { help: { type: "boolean", short: "h" } },
    });
    if (values.help) {
      console.log(workbenchUsage[command]);
      return;
    }
    let result: unknown;
    if (command === "database-info") {
      const { databaseInfo } = await import("./src/workbench/database");
      result = await databaseInfo(JSON.parse(decodeUtf8(readFileSync(0))));
    } else {
      const { findingsCommand } = await import("./src/workbench/commands");
      result = await findingsCommand(command, decodeUtf8(readFileSync(0)));
    }
    console.log(
      stringifyJson(result, 0).replace(/[\p{Cc}\p{Cf}]/gu, (character) =>
        character
          .split("")
          .map(
            (unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`,
          )
          .join(""),
      ),
    );
  })().catch((error: unknown) => {
    console.error(
      escapeControls(error instanceof Error ? error.message : String(error)),
    );
    process.exitCode = 1;
  });
} else {
  console.error(
    `Usage: launch_codex_security_mcp[.cmd] --helper <resolve-security-md | normalize-candidates | validate-patch-risk-assessment | copy-deep-review-input | select-deep-review-input | make-rank-shards | validate-rank-shard | merge-rank-outputs | make-rank-pool-plan | validate-rank-worker | validate-rank-pool | bind-repo-scopes | ${Object.keys(workbenchUsage).join(" | ")}> [options]`,
  );
  process.exitCode = 2;
}
