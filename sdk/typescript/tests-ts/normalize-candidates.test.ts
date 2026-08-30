import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  combine,
  normalizeCandidate,
} from "../../../plugins/codex-security/scripts/normalize_candidates.js";
import {
  normalizerArguments,
  runNormalizer,
  writeSource,
} from "./support/normalize-candidates.js";

const temporaryRoots: string[] = [];
const location = {
  path: "src/in-scope.ts",
  start_line: 1,
  role: "source",
} as const;
const candidate = {
  cwe_ids: ["CWE-79"],
  locations: [location],
  summary: "Candidate",
  evidence: "Evidence",
};

afterEach(() => {
  for (const root of temporaryRoots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function fixture() {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-normalizer-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  writeSource(repository, location.path, "one\ntwo\n");
  writeSource(repository, "src/out-of-scope.ts", "one\n");
  return { root, repository };
}

describe("candidate normalizer", () => {
  test.each(["\n", "\r\n"])(
    "normalizes and combines JSONL with %j line endings",
    (newline) => {
      const { root, repository } = fixture();
      writeSource(repository, location.path, `one${newline}two${newline}`);
      const inventory = join(root, "scope.txt");
      const first = join(root, "first.jsonl");
      const second = join(root, "second.jsonl");
      const output = join(root, "output.jsonl");
      writeFileSync(inventory, `${location.path}${newline}`);
      writeFileSync(
        first,
        [
          JSON.stringify({
            ...candidate,
            candidate_id: "discarded-id",
            cwe_ids: [" cwe-079 ", "CWE-89"],
            summary: " A summary ",
            locations: [location, location],
            instance: "route:a",
          }),
          JSON.stringify({
            ...candidate,
            summary: "Separate candidate",
            instance: "route:b",
          }),
        ].join(newline),
      );
      writeFileSync(
        second,
        `${JSON.stringify({ ...candidate, cwe_ids: ["CWE-89", "CWE-79"], summary: "B summary", evidence: "More evidence", context: "Context", instance: "route:a" })}${newline}`,
      );
      const result = runNormalizer(
        normalizerArguments(
          [second, first, first],
          output,
          repository,
          inventory,
        ),
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("Combined 3 candidate rows into 2 rows");
      const rows = readFileSync(output, "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line)) as ReturnType<typeof combine>;
      expect(rows).toHaveLength(2);
      const merged = rows.find((row) => row.instance === "route:a")!;
      expect(merged).toEqual({
        candidate_id: expect.stringMatching(/^candidate-[a-f0-9]{16}$/u),
        cwe_ids: ["CWE-79", "CWE-89"],
        locations: [{ ...location, end_line: 1 }],
        summary: "A summary\nB summary",
        evidence: "Evidence\nMore evidence",
        context: "Context",
        instance: "route:a",
      });
      expect(
        rows.find((row) => row.instance === "route:b")?.candidate_id,
      ).not.toBe(merged.candidate_id);
    },
  );

  test.each([
    { name: "empty locations", patch: { locations: [] } },
    { name: "blank summary", patch: { summary: " \t" } },
    { name: "blank evidence", patch: { evidence: "" } },
    { name: "invalid context", patch: { context: false } },
    { name: "invalid instance", patch: { instance: 1 } },
    { name: "invalid CWE", patch: { cwe_ids: ["CWE-0"] } },
    {
      name: "invalid role",
      patch: { locations: [{ ...location, role: "unknown" }] },
    },
    {
      name: "boolean line",
      patch: { locations: [{ ...location, start_line: true }] },
    },
    {
      name: "fractional line",
      patch: { locations: [{ ...location, start_line: 1.5 }] },
    },
    {
      name: "reversed range",
      patch: { locations: [{ ...location, start_line: 2, end_line: 1 }] },
    },
    {
      name: "line beyond file",
      patch: { locations: [{ ...location, start_line: 3 }] },
    },
    { name: "unknown field", patch: { unexpected: true } },
    {
      name: "unknown location field",
      patch: { locations: [{ ...location, extra: true }] },
    },
    {
      name: "path traversal",
      patch: { locations: [{ ...location, path: "../outside.ts" }] },
    },
    {
      name: "out of scope",
      patch: { locations: [{ ...location, path: "src/out-of-scope.ts" }] },
    },
  ])("rejects $name", ({ patch }) => {
    const { repository } = fixture();
    expect(() =>
      normalizeCandidate(
        { ...candidate, ...patch },
        repository,
        new Set([location.path]),
        new Map(),
      ),
    ).toThrow();
  });

  test("accepts explicit values for paths containing spaces or leading dashes", () => {
    const { root } = fixture();
    const input = "-candidate input.jsonl";
    writeFileSync(join(root, input), `${JSON.stringify(candidate)}\n`);
    writeFileSync(join(root, "in scope.txt"), `${location.path}\n`);
    const args = [
      `--input=${input}`,
      "--out=output.jsonl",
      "--repo-root=repository",
      "--in-scope-files=in scope.txt",
    ];
    const result = runNormalizer(args, undefined, { cwd: root });
    expect(result.status, result.stderr).toBe(0);
    expect(
      JSON.parse(readFileSync(join(root, "output.jsonl"), "utf8")).summary,
    ).toBe("Candidate");
    expect(
      runNormalizer([...args, input], undefined, { cwd: root }).status,
    ).toBe(2);
  });

  test("shows help and reports missing or unknown arguments", () => {
    for (const flag of ["--help", "-h"]) {
      const result = runNormalizer([flag]);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("Usage:");
    }
    for (const args of [[], ["--out"], ["--input"], ["--unknown"]]) {
      const result = runNormalizer(args);
      expect(result.status).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).not.toBe("");
    }
  });
});
