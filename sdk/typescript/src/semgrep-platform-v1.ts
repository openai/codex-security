import { hostedNumberToken } from "./hosted-scanner-http.js";
import { hostedRepositoryUrl } from "./hosted-scanner-http.js";
import {
  legacyDecimalInteger,
  restoreLegacyHostedNumbers,
} from "./hosted-scanner-v1.js";
import { array, record, requiredText, text } from "./scanner-import.js";
import {
  projectAliases,
  semgrepNativeProjectUrl,
  semgrepProjectUrlEvidence,
  type SemgrepRepositoryReference,
  semgrepPlatformId,
  semgrepRepositoryUrlKey,
} from "./semgrep-platform-findings.js";

/** Early v1 exports also admitted positive integral decimal spellings stored as text. */
export function semgrepV1Id(value: unknown): string {
  const token = hostedNumberToken(value);
  if (token !== undefined && !/^[1-9][0-9]*$/u.test(token))
    return semgrepPlatformId(legacyDecimalInteger(token));
  return semgrepPlatformId(
    typeof value === "string" ? legacyDecimalInteger(value) : value,
  );
}

function isLossyNumber(value: unknown): boolean {
  return (
    typeof value === "number" &&
    (!Number.isFinite(value) ||
      (Number.isInteger(value) && !Number.isSafeInteger(value)))
  );
}

/** Translate a saved object-row export into lossless per-finding JSON for the current reader. */
export function upgradeSemgrepPlatformReport(
  input: Record<string, unknown>,
  declaredUrl?: string,
  repositoryKey = semgrepRepositoryUrlKey,
  references: SemgrepRepositoryReference = [],
): Record<string, unknown> {
  const report = restoreLegacyHostedNumbers(input);
  const project = record(report["project"], "Semgrep project");
  const name = requiredText(project["name"], "Semgrep project name");
  const mapping = report["sourceRepositoryUrl"] ?? declaredUrl;
  const bound =
    mapping === undefined
      ? undefined
      : hostedRepositoryUrl(mapping, "Semgrep source repository");
  const native = semgrepNativeProjectUrl(project["url"], references);
  const url = hostedRepositoryUrl(
    native ?? bound,
    "Semgrep project repository",
  );
  for (const other of [bound, declaredUrl]) {
    if (
      other !== undefined &&
      repositoryKey(hostedRepositoryUrl(other, "Semgrep repository")) !==
        repositoryKey(url)
    )
      throw new Error(
        "Semgrep project does not match the declared source repository URL.",
      );
  }
  const entries = array(report["findings"], "Semgrep findings");
  let aliases = report["repositoryAliases"];
  if (aliases === undefined) {
    const derived = projectAliases(name, url, references, true);
    const observed = new Set<string>();
    for (const entry of entries) {
      const row = record(entry, "Semgrep finding");
      const repo = record(
        row["repository"] ?? {},
        "Semgrep finding repository",
      );
      const label = text(repo["name"]);
      if (!label) continue;
      // Without the later alias list, each row must independently identify the project.
      if (
        repo["id"] == null &&
        (repo["url"] == null || repo["url"] === "") &&
        !derived.has(label)
      )
        throw new Error(
          "Semgrep finding repository does not match the selected project.",
        );
      observed.add(label);
    }
    aliases = Array.from(observed);
  }
  return {
    format: "semgrep-platform-findings/v2",
    deployment: report["deployment"],
    project: { id: semgrepV1Id(project["id"]), name, url },
    ...semgrepProjectUrlEvidence(project["url"], native, bound),
    product: report["product"],
    ref: report["ref"],
    findingCount: report["findingCount"],
    repositoryAliases: aliases,
    findings: entries.map((entry) => {
      const row = record(entry, "Semgrep finding");
      const repository = record(
        row["repository"] ?? {},
        "Semgrep finding repository",
      );
      if ([row["id"], repository["id"]].some(isLossyNumber))
        throw new Error("Expected an exact, positive Semgrep Platform ID.");
      return JSON.stringify(row, (_key, value: unknown) => {
        if (isLossyNumber(value))
          throw new Error(
            "Cannot retain an unsafe Semgrep finding number. Read the original Semgrep export to preserve its JSON numbers.",
          );
        return value;
      });
    }),
  };
}
