import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import { errorMessage } from "./errors.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execute = promisify(execFile);
const traceOutput = z.object({
  results: z.array(
    z.object({
      path: z.string(),
      check_id: z.string(),
      start: z.object({ line: z.number().int().positive() }),
      end: z.object({ line: z.number().int().positive() }),
    }),
  ),
  paths: z.object({ scanned: z.array(z.string()) }),
  errors: z.array(z.unknown()),
});

export interface DependencyTrace {
  path: string;
  startLine: number;
  endLine: number;
  rule: string;
}

export interface TraceSource {
  path: string;
  bytes: Buffer;
  bindings: string[];
}

/** Matches are syntactic call candidates. The investigator still has to establish value flow. */
export async function traceDependencyCalls(
  repository: string,
  sources: TraceSource[],
  symbols: readonly string[],
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
): Promise<{ traces: DependencyTrace[]; gaps: string[] }> {
  const traces: DependencyTrace[] = [];
  const gaps: string[] = [];
  if (!sources.length) return { traces, gaps };
  const command = await resolveTrustedExecutable(
    "opengrep",
    environment,
    repository,
  );
  if (!command)
    return {
      traces,
      gaps: ["OpenGrep is unavailable; source call matching is incomplete."],
    };
  const identifiers = new Set<string>();
  for (const symbol of symbols) {
    const leaf = symbol
      .replace(/\(\)$/u, "")
      .split(/\.|::|#/u)
      .at(-1);
    if (leaf && /^[A-Za-z_][A-Za-z_0-9]*$/u.test(leaf)) identifiers.add(leaf);
  }
  for (const source of sources) {
    for (const binding of source.bindings) {
      if (/^[A-Za-z_][A-Za-z_0-9]*$/u.test(binding)) identifiers.add(binding);
    }
  }
  if (!identifiers.size)
    return {
      traces,
      gaps: ["No call symbol was identified for source tracing."],
    };
  const root = await mkdtemp(join(tmpdir(), "dependency-calls-"));
  try {
    const names = new Map<string, string>();
    const languages = new Set<string>();
    await mkdir(join(root, "input"));
    for (const [index, source] of sources.entries()) {
      const extension = extname(source.path).toLowerCase();
      languages.add(extension === ".py" ? "python" : "javascript");
      const name = `input/file-${index}${extension}`;
      names.set(name, source.path);
      await writeFile(join(root, name), source.bytes, { signal });
    }
    const calls = [...languages].flatMap((language) =>
      [...identifiers].map((id, i) => ({
        id: `${language}-call-${i}`,
        message: id,
        severity: "INFO",
        languages:
          language === "javascript" ? ["javascript", "typescript"] : ["python"],
        "pattern-either": [
          { pattern: `${id}(...)` },
          { pattern: `$RECEIVER.${id}(...)` },
          ...(language === "javascript" ? [{ pattern: `new ${id}(...)` }] : []),
        ],
      })),
    );
    const instances = languages.has("javascript")
      ? [...identifiers].map((name, i) => ({
          id: `javascript-instance-${i}`,
          message: `method on ${name}`,
          severity: "INFO",
          languages: ["javascript", "typescript"],
          patterns: [
            {
              "pattern-either": [
                { "pattern-inside": `const $OBJ = new ${name}(...); ...` },
                { "pattern-inside": `const $OBJ = ${name}(...); ...` },
              ],
            },
            { pattern: "$OBJ.$METHOD(...)" },
          ],
        }))
      : [];
    const rules = [...calls, ...instances];
    const ruleNames = new Map(rules.map((rule) => [rule.id, rule.message]));
    await writeFile(join(root, "rules.json"), JSON.stringify({ rules }));
    const { stdout } = await execute(
      command.executable,
      [
        "scan",
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--no-rewrite-rule-ids",
        "--config",
        "rules.json",
        "--",
        "input",
      ],
      {
        cwd: root,
        signal,
        maxBuffer: Infinity,
        env: {
          ...command.environment,
          OPENGREP_ENABLE_VERSION_CHECK: "0",
          SEMGREP_SEND_METRICS: "off",
        },
      },
    );
    const report = traceOutput.parse(JSON.parse(stdout));
    function originalPath(name: string) {
      return names.get(name.replaceAll("\\", "/").replace(/^\.\//u, ""));
    }
    const scanned = new Set(report.paths.scanned.map(originalPath));
    for (const name of names.values())
      if (!scanned.has(name)) gaps.push(`OpenGrep did not scan ${name}.`);
    if (report.errors.length)
      gaps.push(`OpenGrep reported ${report.errors.length} analysis errors.`);
    for (const match of report.results) {
      const path = originalPath(match.path);
      const rule = ruleNames.get(match.check_id);
      if (path && rule && match.end.line >= match.start.line) {
        traces.push({
          path,
          startLine: match.start.line,
          endLine: match.end.line,
          rule,
        });
      } else {
        gaps.push(
          "OpenGrep returned a match without a recognized source path, symbol or line range.",
        );
      }
    }
  } catch (error) {
    signal?.throwIfAborted();
    gaps.push(`OpenGrep call matching failed: ${errorMessage(error)}`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  return { traces, gaps };
}
