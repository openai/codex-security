import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, posix, relative, resolve, sep, win32 } from "node:path";
import { isRecord } from "../../sdk/typescript/src/record.ts";
import { windowsUnsafePathComponent } from "../../sdk/typescript/src/windows-path.ts";

const verdicts = ["exploitable", "ruled_out", "unknown"] as const;
export type Verdict = (typeof verdicts)[number];
export type EvidenceGroup = readonly { path: string; contains?: string }[];

interface Citation {
  path: string;
  startLine: number;
  endLine: number;
  code: string;
}

export interface ReachabilityAnswer {
  verdict: Verdict;
  dependency_version: string;
  evidence: Citation[];
  reason: string;
}

const text = { type: "string" };
const lineNumber = { type: "integer" };
export const answerSchema = {
  type: "object",
  additionalProperties: false,
  required: ["verdict", "dependency_version", "reason", "evidence"],
  properties: {
    verdict: { type: "string", enum: [...verdicts] },
    dependency_version: text,
    reason: text,
    evidence: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["path", "startLine", "endLine", "code"],
        properties: {
          path: text,
          startLine: lineNumber,
          endLine: lineNumber,
          code: text,
        },
      },
    },
  },
};

function isCitationRange(
  value: unknown,
): value is Omit<Citation, "code"> & { code?: unknown } {
  return (
    isRecord(value) &&
    typeof value.path === "string" &&
    typeof value.startLine === "number" &&
    Number.isSafeInteger(value.startLine) &&
    typeof value.endLine === "number" &&
    Number.isSafeInteger(value.endLine) &&
    value.startLine > 0 &&
    value.endLine >= value.startLine
  );
}

// Model-supplied paths are read by the grader outside the model's sandbox.
async function sourceLines(root: string, path: string): Promise<string[]> {
  if (
    !path ||
    win32.parse(path).root ||
    path.includes("\\") ||
    path.split("/").includes("..") ||
    windowsUnsafePathComponent(path)
  ) {
    throw new Error("expected a repository-relative source file");
  }
  const file = resolve(root, path);
  const canonical = await realpath(file);
  const within = relative(root, canonical);
  if (isAbsolute(within) || within === ".." || within.startsWith(`..${sep}`)) {
    throw new Error("file resolves outside the snapshot");
  }
  if (!(await lstat(file)).isFile()) throw new Error("expected a regular file");
  const contents = await readFile(canonical, "utf8");
  return contents.replaceAll("\r\n", "\n").replace(/\n$/u, "").split("\n");
}

export async function gradeEvidence(
  evidence: unknown,
  groups: readonly EvidenceGroup[],
  repoRoot: string,
  format: "quotes" | "ranges",
) {
  const root = await realpath(repoRoot);
  const sources = new Map<string, string[]>();
  const verified: Citation[] = [];
  const errors: string[] = [];
  if (!Array.isArray(evidence) || !evidence.length) {
    errors.push("Expected a nonempty evidence array");
  } else {
    for (const [index, entry] of evidence.entries()) {
      if (!isCitationRange(entry)) {
        errors.push(
          `Evidence ${index + 1} needs a path and positive line range`,
        );
        continue;
      }
      const quote =
        typeof entry.code === "string"
          ? entry.code.replaceAll("\r\n", "\n").replace(/\n$/u, "")
          : undefined;
      if (format === "quotes" && !quote?.trim()) {
        errors.push(`Evidence ${index + 1} needs a source quote`);
        continue;
      }
      try {
        let source = sources.get(entry.path);
        if (!source) {
          source = await sourceLines(root, entry.path);
          sources.set(entry.path, source);
        }
        const code = source
          .slice(entry.startLine - 1, entry.endLine)
          .join("\n");
        if (
          entry.endLine > source.length ||
          !code.trim() ||
          (format === "quotes" && code !== quote)
        ) {
          errors.push(
            `Source mismatch at ${entry.path}:${entry.startLine}-${entry.endLine}`,
          );
        } else {
          verified.push({ ...entry, path: posix.normalize(entry.path), code });
        }
      } catch (error) {
        errors.push(
          `Cannot cite ${entry.path}: ${error instanceof Error ? error.message : error}`,
        );
      }
    }
  }
  for (const group of groups) {
    const supported = group.some((anchor) =>
      verified.some(
        (citation) =>
          citation.path === anchor.path &&
          (!anchor.contains || citation.code.includes(anchor.contains)),
      ),
    );
    if (!supported) {
      const choices = group.map((anchor) =>
        anchor.contains ? `${anchor.path} (${anchor.contains})` : anchor.path,
      );
      errors.push(`Missing source evidence: ${choices.join(" or ")}`);
    }
  }
  return errors;
}

export async function gradeAnswer(
  answer: unknown,
  expected: {
    verdict: Verdict;
    version: string;
    evidenceGroups: readonly EvidenceGroup[];
  },
  repoRoot: string,
) {
  const result = isRecord(answer) ? answer : {};
  const verdictCorrect = result.verdict === expected.verdict;
  const versionCorrect = result.dependency_version === expected.version;
  const errors = await gradeEvidence(
    result.evidence,
    expected.evidenceGroups,
    repoRoot,
    "quotes",
  );
  const evidenceCorrect = errors.length === 0;
  if (!verdictCorrect) errors.push(`Expected verdict ${expected.verdict}`);
  if (!versionCorrect)
    errors.push(`Expected dependency version ${expected.version}`);
  if (typeof result.reason !== "string" || !result.reason.trim())
    errors.push("Missing reason");
  return {
    pass: errors.length === 0,
    verdictCorrect,
    versionCorrect,
    evidenceCorrect,
    errors,
  };
}
