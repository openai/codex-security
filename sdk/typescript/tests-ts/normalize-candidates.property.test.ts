import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import fc from "fast-check";
import {
  combine,
  normalizeCandidate,
} from "../../../plugins/codex-security/scripts/normalize_candidates.js";
import { writeSource } from "./support/normalize-candidates.js";
import { propertyOptions } from "./support/property.js";

const text = fc
  .string({ unit: "binary", maxLength: 40 })
  .map((value) => ` ${value}x `);
const candidate = fc.record({
  cwe_ids: fc.array(
    fc.integer({ min: 1, max: 1000 }).map((value) => `cwe-0${value}`),
    { maxLength: 4 },
  ),
  locations: fc.array(
    fc.record({
      path: fc.constantFrom("src/alpha.ts", "src/é.ts", "src/😀.ts"),
      start_line: fc.integer({ min: 1, max: 3 }),
      role: fc.constantFrom("source", "sink", "evidence"),
    }),
    { minLength: 1, maxLength: 4 },
  ),
  summary: text,
  evidence: text,
  context: fc.option(text, { nil: undefined }),
  instance: fc.option(text, { nil: undefined }),
});

test("normalization is deterministic across row, location, and CWE order and duplicates", () => {
  const repository = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-normalizer-property-")),
  );
  const scope = new Set(["src/alpha.ts", "src/é.ts", "src/😀.ts"]);
  for (const path of scope) writeSource(repository, path, "one\ntwo\nthree\n");
  const lineCounts = new Map<string, number>();
  const normalize = (rows: unknown[]) =>
    combine(
      rows.map((row) => normalizeCandidate(row, repository, scope, lineCounts)),
    );
  try {
    fc.assert(
      fc.property(
        fc.array(candidate, { minLength: 1, maxLength: 10 }),
        (rows) => {
          const variants = rows.flatMap((row) => [
            row,
            { ...row, context: undefined },
          ]);
          const expected = normalize(variants);
          const reordered = variants.toReversed().map((row) => ({
            ...row,
            cwe_ids: [...row.cwe_ids.toReversed(), ...row.cwe_ids],
            locations: [...row.locations.toReversed(), ...row.locations],
          }));
          expect(JSON.stringify(normalize([...reordered, ...reordered]))).toBe(
            JSON.stringify(expected),
          );
          expect(new Set(expected.map((row) => row.candidate_id)).size).toBe(
            expected.length,
          );

          const changedText = rows.map((row) => ({
            ...row,
            candidate_id: "upstream-id",
            summary: "Reworded summary",
            evidence: "Additional evidence",
            context: "Additional context",
          }));
          expect(normalize(changedText).map((row) => row.candidate_id)).toEqual(
            expected.map((row) => row.candidate_id),
          );
        },
      ),
      propertyOptions,
    );
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});
