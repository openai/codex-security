import { createHash } from "node:crypto";
import { sourceReader } from "../grade.mjs";
import { supported } from "./grade.mjs";
import { questions } from "./skill-questions.mjs";

const text = { type: "string" };
const integer = { type: "integer" };
const schema = {
  type: "object",
  additionalProperties: false,
  required: ["verdict", "dependency_version", "reason", "evidence"],
  properties: {
    verdict: { type: "string", enum: ["exploitable", "ruled_out", "unknown"] },
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
          startLine: integer,
          endLine: integer,
          code: text,
        },
      },
    },
  },
};

export async function runBaseline(runSkill, scenario, repo, sha) {
  const question = questions.get(scenario.id);
  if (!question) throw Error("Missing baseline question for " + scenario.id);
  const prompt = [
    question,
    "Inspect the supplied source snapshot offline and read-only. Return a JSON object with " +
      "verdict (exploitable, ruled_out, or unknown), dependency_version, reason, and evidence. " +
      "For dependency_version, give only the bare version of the component named in the advisory as a string. Put package names and build details in reason. " +
      "Support the version and each decisive step with a short citation: {path, startLine, endLine, code}. " +
      "Use a repository-relative path and 1-based inclusive line numbers. Copy the complete cited lines " +
      "exactly, including indentation, without line numbers or ellipses.",
  ].join("\n\n");
  const { answer, usage } = await runSkill(repo, prompt, schema);
  const errors = [];
  const citations = [];
  const read = sourceReader(repo, sha);
  for (const citation of Array.isArray(answer?.evidence)
    ? answer.evidence
    : []) {
    try {
      if (typeof citation?.code !== "string" || !citation.code.trim())
        throw Error("Missing exact source quote");
      citations.push(
        read({
          ...citation,
          commit: sha,
          text: citation.code.replaceAll("\r\n", "\n").replace(/\n$/u, ""),
        }),
      );
    } catch (error) {
      errors.push(error.message);
    }
  }
  if (!citations.length) errors.push("Missing verified source citation");
  for (const group of scenario.skillEvidenceGroups ?? scenario.evidenceGroups) {
    if (!group.some((anchor) => supported(anchor, citations)))
      errors.push(
        "Missing source evidence at " + group.map((a) => a.path).join(" or "),
      );
  }
  const evidenceCorrect = errors.length === 0;
  // The historical skill questions explicitly supply caller/deployment assumptions.
  const expected =
    scenario.verdict === "potentially_exploitable"
      ? "exploitable"
      : scenario.verdict;
  const verdictCorrect = answer?.verdict === expected;
  const versionCorrect = answer?.dependency_version === scenario.version;
  if (!verdictCorrect) errors.push("Expected " + expected);
  if (!versionCorrect) errors.push("Expected version " + scenario.version);
  if (typeof answer?.reason !== "string" || !answer.reason.trim())
    errors.push("Missing reason");
  return {
    answer,
    usage,
    promptSha256: createHash("sha256").update(prompt).digest("hex"),
    grade: {
      pass: errors.length === 0,
      verdictCorrect,
      versionCorrect,
      evidenceCorrect,
      errors,
    },
  };
}
