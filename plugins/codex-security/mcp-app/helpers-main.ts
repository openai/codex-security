import { closeSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
export {
  parseCanonicalScanDraft,
  parseCurrentFindings,
} from "./src/artifact-scan-draft.js";
import { parseArgs } from "node:util";
import { isMainThread, parentPort, workerData } from "node:worker_threads";
import { resolveSecurityMdCommand } from "./src/helpers/resolve-security-md";
import { decodePosixBytes } from "./src/helpers/posix-path";
import { windowsBinding } from "./src/native";
import {
  normalizeCandidateBatch,
  normalizeCandidatesCommand,
} from "./src/helpers/normalize-candidates";
import { deepReviewInputCommand } from "./src/helpers/deep-review-input";
import { inventoryCommand } from "./src/helpers/generate-inventory";
import { bindRepoScopesCommand } from "./src/helpers/bind-repo-scopes";
import {
  escapeControls,
  requireFiniteNumbers,
  stringifyJson,
} from "./src/helpers/json";
import { decodeUtf8 } from "./src/helpers/utf8";

// Importing the bundled parser does not invoke its CLI adapter.
const entryPath = import.meta.url.startsWith("file:")
  ? fileURLToPath(import.meta.url)
  : import.meta.url;
const invokedPath = process.argv[1];
if (
  invokedPath &&
  existsSync(invokedPath) &&
  realpathSync(invokedPath) === realpathSync(entryPath)
) {
  if (isMainThread) runHelper();
  else parentPort!.postMessage(normalizeCandidateBatch(workerData));
}

function runHelper(): void {
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
    "local-dedupe":
      "Usage: local-dedupe\nReads a JSON object from stdin with an absolute stateDirectory and a prepare or embed payload.",
    "store-findings":
      "Usage: store-findings\nReads a JSON object from stdin with an absolute stateDirectory and payload.entries containing finding and embedding records; payload.repositoryId is optional.",
    "list-stored-findings":
      "Usage: list-stored-findings\nReads a JSON object from stdin with an absolute stateDirectory, positive payload.limit and non-negative payload.offset.",
    ...(process.env.CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS === "1"
      ? {
          "store-external-findings":
            "Usage: store-external-findings\nReads a JSON object from stdin with an absolute stateDirectory and payload containing repository, provider, sourceKey and findings with source_finding_id and evidence.",
          "list-external-findings":
            "Usage: list-external-findings\nReads a JSON object from stdin with an absolute stateDirectory and payload.repository; payload.id optionally selects one external finding.",
        }
      : {}),
    "find-potential-duplicates":
      "Usage: find-potential-duplicates\nReads a JSON object from stdin with an absolute stateDirectory, payload.findingId and payload.scope containing either repositoryId or allRepositories: true.",
    "store-dedupe-groups":
      "Usage: store-dedupe-groups\nReads a JSON object from stdin with an absolute stateDirectory and payload.groups containing arrays of finding IDs.",
    "list-dedupe-groups":
      "Usage: list-dedupe-groups\nReads a JSON object from stdin with an absolute stateDirectory and payload.findingId.",
    "severity-classification":
      "Usage: severity-classification\nReads a JSON object from stdin with an absolute stateDirectory and payload describing the begin or save action.",
    "read-severity-classification":
      "Usage: read-severity-classification --scan-id <id>\nReads a JSON object from stdin with an absolute stateDirectory. Reads saved assessments without updating the database.",
  };
  if (
    command === "generate-in-scope-files" ||
    command === "make-repo-scope-input" ||
    command === "make-hosted-repo-scope-input" ||
    command === "make-diff-rank-input"
  ) {
    void inventoryCommand(command, args).then((code) => {
      process.exitCode = code;
    });
  } else if (command === "resolve-security-md") {
    process.exitCode = resolveSecurityMdCommand(args, posixHome);
  } else if (command === "normalize-candidates") {
    process.exitCode = normalizeCandidatesCommand(args, posixHome);
  } else if (command === "validate-patch-risk-assessment") {
    void import("./src/helpers/validate-patch-risk-assessment").then(
      ({ validatePatchRiskAssessmentCommand }) => {
        process.exitCode = validatePatchRiskAssessmentCommand(args);
      },
    );
  } else if (command === "copy-deep-review-input") {
    process.exitCode = deepReviewInputCommand(args, posixHome);
  } else if (command === "bind-repo-scopes") {
    process.exitCode = bindRepoScopesCommand(args, posixHome);
  } else if (Object.hasOwn(workbenchUsage, command)) {
    void (async () => {
      const { values } = parseArgs({
        args,
        options: {
          help: { type: "boolean", short: "h" },
          ...(command === "read-severity-classification"
            ? { "scan-id": { type: "string" as const } }
            : {}),
        },
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
        const { workbenchCommand } = await import("./src/workbench/commands");
        result = await workbenchCommand(
          command,
          decodeUtf8(readFileSync(0)),
          values["scan-id"] as string | undefined,
        );
      }
      // Preparation commits before response serialization, as other workbench writes do.
      if (command === "local-dedupe") requireFiniteNumbers(result);
      console.log(
        stringifyJson(result, 0).replace(/[\p{Cc}\p{Cf}]/gu, (character) =>
          character
            .split("")
            .map(
              (unit) =>
                `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`,
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
      `Usage: launch_codex_security_mcp[.cmd] --helper <generate-in-scope-files | make-repo-scope-input | make-diff-rank-input | resolve-security-md | normalize-candidates | validate-patch-risk-assessment | copy-deep-review-input | bind-repo-scopes | ${Object.keys(workbenchUsage).join(" | ")}> [options]`,
    );
    process.exitCode = 2;
  }
}
