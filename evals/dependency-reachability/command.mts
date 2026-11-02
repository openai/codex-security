import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { isRecord } from "../../sdk/typescript/src/record.ts";

export const cve = "CVE-2026-48801";
export const fixture = join(import.meta.dirname, "fixtures", "command");
export const commandArgs = ["exploitability", "check", cve, "--json"];

// Read the original fixture once. A path returned by the CLI can only select
// a file in this map, never a file elsewhere on the grading host.
export async function readFixture(directory = fixture) {
  const files = new Map<string, string>();
  const hash = createHash("sha256");
  const entries = await readdir(directory, {
    withFileTypes: true,
    recursive: true,
  });
  const paths = entries
    .filter((entry) => entry.isFile())
    .map((entry) =>
      relative(directory, join(entry.parentPath, entry.name))
        .split(sep)
        .join("/"),
    )
    .sort();
  for (const path of paths) {
    const bytes = await readFile(join(directory, path));
    hash.update(path).update("\0").update(bytes).update("\0");
    files.set(path, bytes.toString("utf8"));
  }
  return { files, sha256: hash.digest("hex") };
}

const expectedUses = [
  { service: "notes", version: "5.0.0", verdict: "exploitable" },
  { service: "reviews", version: "5.0.1", verdict: "ruled_out" },
] as const;

function citedText(entry: unknown, files: ReadonlyMap<string, string>) {
  if (!isRecord(entry) || typeof entry.path !== "string") return;
  const path = entry.path.replace(/^\.\//u, "");
  const source = files.get(path);
  const { startLine, endLine } = entry;
  if (
    source === undefined ||
    typeof startLine !== "number" ||
    typeof endLine !== "number" ||
    !Number.isInteger(startLine) ||
    !Number.isInteger(endLine)
  )
    return;
  const lines = source.replace(/\r?\n$/u, "").split(/\r?\n/u);
  if (startLine < 1 || endLine < startLine || endLine > lines.length) return;
  return { path, text: lines.slice(startLine - 1, endLine).join("\n") };
}

export function gradeCommand(
  answer: unknown,
  files: ReadonlyMap<string, string>,
) {
  const result = isRecord(answer) ? answer : {};
  const errors: string[] = [];
  if (result.cve !== cve || result.status !== "exploitable")
    errors.push(`Expected ${cve} with aggregate status exploitable`);
  const uses: unknown[] = Array.isArray(result.uses) ? result.uses : [];
  if (uses.length !== expectedUses.length)
    errors.push(`Expected two uses, received ${uses.length}`);
  const grades = expectedUses.map(({ service, version, verdict }) => {
    const issues: string[] = [];
    const matching = uses
      .filter(isRecord)
      .filter(
        (use) =>
          typeof use.location === "string" &&
          use.location.split(/[^\w-]+/u).includes(service),
      );
    const use = matching[0];
    if (matching.length !== 1)
      issues.push(
        `Expected one ${service} location, received ${matching.length}`,
      );
    if (use) {
      if (
        use.component !== "linkify-it" ||
        use.version !== version ||
        use.verdict !== verdict
      )
        issues.push(`Expected linkify-it ${version} to be ${verdict}`);
      if (use.deployment !== "configured")
        issues.push("Expected configured deployment");
      if (typeof use.reason !== "string" || !use.reason.trim())
        issues.push("Missing reason");
      const citations = (Array.isArray(use.evidence) ? use.evidence : []).map(
        (e: unknown) => citedText(e, files),
      );
      if (citations.includes(undefined)) issues.push("Invalid source citation");
      const cites = (path: string, text: string) =>
        citations.some((e) => e?.path === path && e.text.includes(text));
      if (
        !cites(`${service}/package-lock.json`, `"${version}"`) &&
        !cites(`${service}/package-lock.json`, `linkify-it-${version}.tgz`)
      )
        issues.push("Missing resolved version evidence");
      if (!cites("compose.yaml", `SERVICE: ${service}`))
        issues.push("Missing service build binding");
      if (
        !cites("Dockerfile", "COPY ${SERVICE}/package*.json") ||
        !cites("Dockerfile", "RUN npm ci") ||
        !cites("Dockerfile", 'CMD ["node", "server.mjs"]')
      )
        issues.push(
          "Missing evidence that the image installs this service's lockfile and runs the shared handler",
        );
      if (
        verdict === "exploitable" &&
        !cites("server.mjs", "links.match(await text(request))")
      )
        issues.push("Missing request processing evidence");
    }
    return { service, pass: issues.length === 0, errors: issues };
  });
  return {
    pass: errors.length === 0 && grades.every((g) => g.pass),
    errors,
    uses: grades,
  };
}
