import { isDeepStrictEqual } from "node:util";
import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { asRecord, isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  scannerSeverity,
  text,
} from "./scanner-import.js";

export const promptfooReportFormat = "promptfoo-redteam/v3";

function hasGraderError(grade: Record<string, unknown>) {
  const metadata = asRecord(grade["metadata"]);
  return (
    metadata?.["graderError"] === true || Boolean(metadata?.["gradingError"])
  );
}

/** Each result ID identifies one observed probe in the native evaluation export. */
export async function readPromptfooFindings(
  path: string,
): Promise<ExternalFindings> {
  const input = record(await readScannerJson(path), "Promptfoo export");
  const evalId = text(input["evalId"]);
  const summary = asRecord(input["results"]);
  const config = asRecord(input["config"]);
  if (!evalId || summary?.["version"] !== 3 || !isRecord(config?.["redteam"]))
    throw new Error(
      "Expected a Promptfoo red-team JSON export with evalId and version 3 results.",
    );
  const rows = array(summary["results"], "Promptfoo results.results");
  const defaults = asRecord(config["defaultTest"])?.["assert"];
  return normalizeRecords(
    rows,
    (value) => {
      const row = record(value, "Promptfoo result");
      const response = asRecord(row["response"]);
      const grade = asRecord(row["gradingResult"]);
      // Promptfoo also writes assertion explanations to row.error. The failure reason distinguishes them.
      if (row["failureReason"] === 2 || response?.["error"])
        throw new Error(
          `Promptfoo execution error: ${text(response?.["error"]) ?? text(row["error"]) ?? "no diagnostic supplied"}`,
        );
      const components = Array.isArray(grade?.["componentResults"])
        ? grade["componentResults"].filter(isRecord)
        : grade
          ? [grade]
          : [];
      const aggregateError = grade && hasGraderError(grade);
      const errorGrade = aggregateError
        ? grade
        : components.find(hasGraderError);
      const graderDiagnostic = errorGrade
        ? `Promptfoo grader error: ${text(asRecord(errorGrade["metadata"])?.["gradingError"]) ?? text(errorGrade["reason"]) ?? "no diagnostic supplied"}`
        : null;
      if (aggregateError && graderDiagnostic) throw new Error(graderDiagnostic);
      if (
        row["success"] === true &&
        row["failureReason"] === 0 &&
        grade?.["pass"] !== false
      )
        throw new Error(
          graderDiagnostic ??
            "Promptfoo reports that the target passed this probe.",
        );
      if (
        row["success"] !== false ||
        row["failureReason"] !== 1 ||
        grade?.["pass"] !== false
      )
        throw new Error("Missing or inconsistent Promptfoo assertion verdict.");
      const testCase = asRecord(row["testCase"]);
      const meta = asRecord(testCase?.["metadata"]);
      const plugin = text(meta?.["pluginId"]);
      if (!plugin) throw new Error("Result has no red-team plugin ID.");
      // Promptfoo prepends default assertions before merging defaultTest.options.
      // The exported disableDefaultAsserts can therefore be true even with the prefix.
      const declared = testCase?.["assert"];
      const skipDefaults =
        Array.isArray(defaults) &&
        Array.isArray(declared) &&
        (asRecord(testCase?.["options"])?.["disableDefaultAsserts"] !== true ||
          (declared.length > defaults.length &&
            defaults.every((item, index) =>
              isDeepStrictEqual(item, declared[index]),
            )));
      const generatedIndex = skipDefaults ? defaults.length : 0;
      const generated = Array.isArray(declared)
        ? asRecord(declared[generatedIndex])
        : null;
      const failed = components.filter((component) => {
        const assertion = asRecord(component["assertion"]);
        if (
          component["pass"] !== false ||
          hasGraderError(component) ||
          !assertion
        )
          return false;
        if (text(assertion["type"])?.startsWith("promptfoo:redteam:"))
          return true;
        const metric = text(assertion["metric"]);
        if (!metric || generated?.["metric"] !== metric) return false;
        // Later transforms can change strategyId and append metric segments
        // while keeping the Best-of-N provider and its basic refusal check.
        if (assertion["type"] === "is-refusal")
          return (
            (meta?.["strategyId"] === "best-of-n" ||
              asRecord(testCase?.["provider"])?.["id"] ===
                "promptfoo:redteam:best-of-n") &&
            /\/BestOfN(?:\/|$)/.test(metric) &&
            generated["type"] === "is-refusal"
          );
        // Promptfoo can append a moderation grader to its native attack assertion.
        if (assertion["type"] === "moderation")
          return (
            plugin.startsWith("harmful:") &&
            generated["type"] === `promptfoo:redteam:${plugin}` &&
            Array.isArray(declared) &&
            isDeepStrictEqual(declared[generatedIndex + 1], assertion)
          );
        return (
          (plugin.startsWith("file://") ||
            (["cyberseceval", "donotanswer", "xstest"].includes(plugin) &&
              metric.split("/", 1)[0]?.toLowerCase() === plugin)) &&
          assertion["type"] === "llm-rubric" &&
          text(assertion["value"]) &&
          generated["type"] === assertion["type"] &&
          generated["value"] === assertion["value"]
        );
      });
      if (!failed.length)
        throw new Error(
          graderDiagnostic ??
            "No failed Promptfoo red-team assertion in this result.",
        );
      const provider = asRecord(row["provider"]);
      const target = text(provider?.["label"]) ?? text(provider?.["id"]);
      if (!target) throw new Error("Promptfoo result has no target provider.");
      const reasons = failed.flatMap(
        (component) => text(component["reason"]) ?? [],
      );
      return validateExternalEvidence(
        {
          title: `${plugin} on ${target}`,
          description:
            reasons.join("\n") ||
            (graderDiagnostic ? null : text(grade["reason"])),
          severity: scannerSeverity(text(meta?.["severity"])?.toLowerCase()),
          source_scan_id: evalId,
          source_data: { format: promptfooReportFormat, result: row },
        },
        "local",
      );
    },
    (value) => {
      const id = text(asRecord(value)?.["id"]);
      if (!id) throw new Error("Promptfoo result has no native result ID.");
      return id;
    },
    "local",
    {
      report: {
        format: promptfooReportFormat,
        evalId,
        promptfooVersion: text(
          asRecord(input["metadata"])?.["promptfooVersion"],
        ),
      },
    },
  );
}
