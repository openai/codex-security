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

function matchesProviderReference(reference: unknown, value: unknown) {
  const provider = asRecord(value);
  if (typeof reference !== "string" || !provider) return false;
  // Older exports retain provider objects but omit their id() method.
  return (
    typeof provider["id"] !== "string" ||
    reference === provider["id"] ||
    reference === provider["label"]
  );
}

function matchesDefaultProvider(original: unknown, evaluated: unknown) {
  if (
    isDeepStrictEqual(original, evaluated) ||
    matchesProviderReference(original, evaluated)
  )
    return true;
  const declared = asRecord(original);
  const actual = asRecord(evaluated);
  if (!declared || !actual || Object.hasOwn(declared, "id")) return false;
  const expected = { ...declared };
  for (const type of ["text", "embedding", "classification", "moderation"]) {
    const entry = declared[type];
    const options = asRecord(entry);
    const reference =
      options && Object.keys(options).length === 1 ? options["id"] : entry;
    if (matchesProviderReference(reference, actual[type]))
      expected[type] = actual[type];
  }
  return isDeepStrictEqual(expected, actual);
}

function matchesDefaultAssertion(
  value: unknown,
  declared: unknown,
  rubricPrompt: unknown,
) {
  if (isDeepStrictEqual(value, declared)) return true;
  const original = asRecord(value);
  const evaluated = asRecord(declared);
  if (
    !original ||
    !evaluated ||
    !matchesDefaultProvider(original["provider"], evaluated["provider"])
  )
    return false;
  const expected: Record<string, unknown> = {
    ...original,
    provider: evaluated["provider"],
  };
  const actual: Record<string, unknown> = {
    ...evaluated,
    provider: evaluated["provider"],
  };
  if (
    original["type"] === "llm-rubric" ||
    original["type"] === "not-llm-rubric"
  ) {
    // Grading also fills rubric values while retaining the other fields.
    const prompt = original["rubricPrompt"] || rubricPrompt;
    expected["value"] =
      original["value"] ||
      (prompt && typeof prompt === "object" ? JSON.stringify(prompt) : prompt);
    actual["value"] = evaluated["value"];
  }
  return isDeepStrictEqual(expected, actual);
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
      const rubricPrompt = asRecord(testCase?.["options"])?.["rubricPrompt"];
      const skipDefaults =
        Array.isArray(defaults) &&
        Array.isArray(declared) &&
        (asRecord(testCase?.["options"])?.["disableDefaultAsserts"] !== true ||
          (declared.length > defaults.length &&
            defaults.every((item, index) => {
              if (matchesDefaultAssertion(item, declared[index], rubricPrompt))
                return true;
              const original = asRecord(item);
              const evaluated = asRecord(declared[index]);
              const children = original?.["assert"];
              const evaluatedChildren = evaluated?.["assert"];
              return (
                original?.["type"] === "assert-set" &&
                Array.isArray(children) &&
                Array.isArray(evaluatedChildren) &&
                isDeepStrictEqual(
                  { ...original, assert: undefined },
                  { ...evaluated, assert: undefined },
                ) &&
                children.length === evaluatedChildren.length &&
                children.every((child, childIndex) =>
                  matchesDefaultAssertion(
                    child,
                    evaluatedChildren[childIndex],
                    rubricPrompt,
                  ),
                )
              );
            })));
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
        // Promptfoo can append a moderation grader to its native attack assertion.
        if (assertion["type"] === "moderation")
          return (
            plugin.startsWith("harmful:") &&
            generated?.["type"] === `promptfoo:redteam:${plugin}` &&
            Array.isArray(declared) &&
            isDeepStrictEqual(declared[generatedIndex + 1], assertion)
          );
        const metric = text(assertion["metric"]);
        if (!metric || generated?.["metric"] !== metric) return false;
        // Later transforms can replace strategyId, provider, and metric names.
        // Layer metadata retains the original strategy steps.
        if (assertion["type"] === "is-refusal") {
          const steps = asRecord(meta?.["strategyConfig"])?.["steps"];
          return (
            (meta?.["strategyId"] === "best-of-n" ||
              asRecord(testCase?.["provider"])?.["id"] ===
                "promptfoo:redteam:best-of-n" ||
              (Array.isArray(steps) &&
                steps.some((step) => {
                  const id =
                    typeof step === "string" ? step : asRecord(step)?.["id"];
                  return (
                    typeof id === "string" &&
                    id.split(":", 1)[0] === "best-of-n"
                  );
                }))) &&
            generated["type"] === "is-refusal"
          );
        }
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
