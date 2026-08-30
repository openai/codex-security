import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import fc from "fast-check";
import {
  normalizerArguments,
  runPythonNormalizer,
  runTypeScriptNormalizer,
  writeSource,
} from "./support/normalize-candidates.js";
import { propertyOptions } from "./support/property.js";

const ROLES = [
  "entrypoint",
  "entrypoint/wrapper",
  "source",
  "root_control",
  "sink",
  "concrete_implementation",
  "evidence",
] as const;
const SOURCES = [
  { contents: "one\ntwo\nthree\nfour\n", lines: 4, path: "src/ascii.ts" },
  { contents: "one\r\ntwo\r\nthree", lines: 3, path: "src/é.ts" },
  { contents: "one\rtwo\rthree\r", lines: 3, path: "src/\ue000.ts" },
  { contents: "one", lines: 1, path: "src/😀.ts" },
] as const;
const filesystemPropertyOptions = {
  ...propertyOptions,
  numRuns: Number(process.env["CODEX_SECURITY_PROPERTY_RUNS"] ?? "8"),
};

interface LocationRow {
  end_line?: number;
  path: string;
  role: (typeof ROLES)[number];
  start_line: number;
}

interface CandidateRow {
  candidate_id?: string;
  context?: string | null;
  cwe_ids: string[];
  evidence: string;
  instance?: string | null;
  locations: LocationRow[];
  summary: string;
}

const INVALID_KINDS = [
  "bad-cwe",
  "bad-role",
  "candidate-id",
  "empty-locations",
  "empty-summary",
  "end-before-start",
  "line-beyond-file",
  "malformed-json",
  "non-object",
  "out-of-scope",
  "path-traversal",
  "start-line-boolean",
  "unknown-candidate-field",
  "unknown-location-field",
] as const;
type InvalidKind = (typeof INVALID_KINDS)[number];
const VALID_EXAMPLE_ROWS: CandidateRow[] = [
  {
    cwe_ids: ["CWE-79"],
    locations: [{ path: "src/ascii.ts", start_line: 1, role: "source" }],
    summary: "Synthetic candidate",
    evidence: "Synthetic evidence",
  },
];

const edgeCharacter = fc.constantFrom(
  "a",
  "Z",
  "0",
  " ",
  "\t",
  "\r",
  "\n",
  "é",
  "e\u0301",
  "\ue000",
  "😀",
  "\u2028",
  "\u2029",
  "\0",
  ":",
  "\\",
  "/",
);
const pythonWhitespace = fc.constantFrom(
  "",
  " ",
  "\t",
  "\r\n",
  "\u001c",
  "\u0085",
  "\u00a0",
  "\u3000",
);
const textBody = fc.oneof(
  fc
    .array(edgeCharacter, { maxLength: 12 })
    .map((characters) => characters.join("")),
  fc.string({ unit: "binary", maxLength: 12 }),
);
const text = fc
  .tuple(pythonWhitespace, textBody, pythonWhitespace)
  .map(([prefix, body, suffix]) => `${prefix}x${body}y${suffix}`);
const optionalText = fc.oneof(fc.constant(undefined), fc.constant(null), text);
const cweNumber = fc.oneof(
  fc.integer({ min: 1, max: 1_000_000 }).map(String),
  fc.constant("9007199254740993"),
  fc.constant(`1${"0".repeat(80)}`),
);
const safeFilename = fc
  .array(
    fc.constantFrom(
      "a",
      "Z",
      "0",
      "-",
      "_",
      " ",
      "é",
      "e\u0301",
      "\ue000",
      "😀",
    ),
    { maxLength: 12 },
  )
  .map((characters) => `file-${characters.join("")}x.ts`);
const location = fc.constantFrom(...SOURCES).chain((source) =>
  fc.integer({ min: 1, max: source.lines }).chain((start) =>
    fc
      .record({
        end: fc.integer({ min: start, max: source.lines }),
        includeEnd: fc.boolean(),
        role: fc.constantFrom(...ROLES),
      })
      .map(
        ({ end, includeEnd, role }): LocationRow => ({
          path: source.path,
          start_line: start,
          ...(includeEnd ? { end_line: end } : {}),
          role,
        }),
      ),
  ),
);
const variant = fc.record({
  candidateId: fc.oneof(fc.constant(undefined), text),
  context: optionalText,
  evidence: text,
  summary: text,
});
const candidateGroup = fc
  .record({
    cweNumbers: fc.uniqueArray(cweNumber, {
      maxLength: 4,
      selector: (value) => BigInt(value).toString(),
    }),
    instance: optionalText,
    locations: fc.array(location, { minLength: 1, maxLength: 4 }),
    variants: fc.array(variant, { minLength: 1, maxLength: 4 }),
  })
  .map(({ cweNumbers, instance, locations, variants }) =>
    variants.map(
      ({ candidateId, context, evidence, summary }, index): CandidateRow => {
        const orderedLocations = (
          index % 2 === 0 ? locations : [...locations].reverse()
        ).map((item) => ({ ...item }));
        if (index % 3 === 0) {
          orderedLocations.push({ ...orderedLocations[0]! });
        }
        const formattedCwes = cweNumbers.map((number, cweIndex) => {
          const prefix = (index + cweIndex) % 2 === 0 ? "CWE-" : "cwe-";
          const padding = "0".repeat((index + cweIndex) % 3);
          const whitespace = (index + cweIndex) % 2 === 0 ? " " : "\u00a0";
          const digits = Array.from(
            ["0123456789", "٠١٢٣٤٥٦٧٨٩", "０１２３４５６７８９", "𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡"][
              (index + cweIndex) % 4
            ]!,
          );
          const value = `${padding}${number}`.replace(
            /\d/gu,
            (digit) => digits[Number(digit)]!,
          );
          return `${whitespace}${prefix}${value}${whitespace}`;
        });
        if (index % 2 === 1) formattedCwes.reverse();
        if (index % 3 === 0 && formattedCwes[0] !== undefined) {
          formattedCwes.push(formattedCwes[0]);
        }
        return {
          cwe_ids: formattedCwes,
          locations: orderedLocations,
          summary,
          evidence,
          ...(candidateId === undefined ? {} : { candidate_id: candidateId }),
          ...(context === undefined ? {} : { context }),
          ...(instance === undefined ? {} : { instance }),
        };
      },
    ),
  );
const candidateRows = fc
  .array(candidateGroup, { minLength: 1, maxLength: 4 })
  .map((groups) => groups.flat());
const invalidKind = fc.constantFrom(...INVALID_KINDS);

function fixture(
  lineEnding = "\n",
  finalLineEnding = true,
  includeDeleted = false,
): { inventory: string; repository: string; root: string } {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-normalizer-property-")),
  );
  const repository = join(root, "repository");
  mkdirSync(repository);
  for (const source of SOURCES) {
    writeSource(repository, source.path, source.contents);
  }
  writeSource(repository, "src/out-of-scope.ts", "outside\n");
  const inventory = join(root, "in-scope.txt");
  const paths: string[] = SOURCES.map((source) => source.path);
  if (includeDeleted) paths.push("src/deleted.ts");
  writeFileSync(
    inventory,
    `${paths.join(lineEnding)}${finalLineEnding ? lineEnding : ""}`,
  );
  return { inventory, repository, root };
}

function writeInputs(
  root: string,
  prefix: string,
  rows: CandidateRow[],
  fileCount: number,
): string[] {
  const buckets = Array.from({ length: fileCount }, () => [] as string[]);
  for (const [index, row] of rows.entries()) {
    buckets[index % fileCount]!.push(JSON.stringify(row));
  }
  return buckets.map((lines, index) => {
    const path = join(root, `${prefix}-${index}.jsonl`);
    writeFileSync(path, `\n${lines.join("\n\n")}\n`);
    return path;
  });
}

function inputArguments(paths: string[]): string[] {
  return [...paths].reverse().concat(paths[0]!);
}

function byteLineCount(contents: Uint8Array): number {
  let lines = 0;
  for (let index = 0; index < contents.length; index += 1) {
    if (contents[index] === 0x0d) {
      lines += 1;
      if (contents[index + 1] === 0x0a) index += 1;
    } else if (contents[index] === 0x0a) {
      lines += 1;
    }
  }
  const last = contents[contents.length - 1];
  return last === 0x0a || last === 0x0d ? lines : lines + 1;
}

function pathSpelling(filename: string, variant: number): string {
  switch (variant % 4) {
    case 1:
      return `src/./${filename}`;
    case 2:
      return `src//${filename}`;
    case 3:
      return process.platform === "win32"
        ? `src\\${filename}`
        : `src/${filename}`;
    default:
      return `src/${filename}`;
  }
}

function invalidLine(kind: InvalidKind, valid: CandidateRow): string {
  if (kind === "malformed-json") return '{"cwe_ids":';
  if (kind === "non-object") return JSON.stringify([valid]);
  const row = JSON.parse(JSON.stringify(valid)) as Record<string, unknown>;
  switch (kind) {
    case "bad-cwe":
      row["cwe_ids"] = ["CWE-0"];
      break;
    case "bad-role":
      row["locations"] = [
        { path: "src/ascii.ts", start_line: 1, role: "unknown" },
      ];
      break;
    case "candidate-id":
      row["candidate_id"] = "\u00a0\t";
      break;
    case "empty-locations":
      row["locations"] = [];
      break;
    case "empty-summary":
      row["summary"] = "\u001c\u00a0\t";
      break;
    case "end-before-start":
      row["locations"] = [
        {
          path: "src/ascii.ts",
          start_line: 2,
          end_line: 1,
          role: "source",
        },
      ];
      break;
    case "line-beyond-file":
      row["locations"] = [
        { path: "src/ascii.ts", start_line: 5, role: "source" },
      ];
      break;
    case "out-of-scope":
      row["locations"] = [
        { path: "src/out-of-scope.ts", start_line: 1, role: "source" },
      ];
      break;
    case "path-traversal":
      row["locations"] = [
        { path: "../outside.ts", start_line: 1, role: "source" },
      ];
      break;
    case "start-line-boolean":
      row["locations"] = [
        { path: "src/ascii.ts", start_line: true, role: "source" },
      ];
      break;
    case "unknown-candidate-field":
      row["unexpected"] = true;
      break;
    case "unknown-location-field":
      row["locations"] = [
        {
          path: "src/ascii.ts",
          start_line: 1,
          role: "source",
          unexpected: true,
        },
      ];
      break;
  }
  return JSON.stringify(row);
}

function expectedError(kind: InvalidKind): string | undefined {
  const messages: Partial<Record<InvalidKind, string>> = {
    "bad-cwe": "cwe_ids: unsupported value",
    "bad-role": "role: unsupported value",
    "candidate-id": "candidate_id: expected a non-empty string",
    "empty-locations": "locations: expected a non-empty array",
    "empty-summary": "summary: expected a non-empty string",
    "end-before-start": "end_line: must be greater than or equal to start_line",
    "line-beyond-file": "line range 5-5 exceeds src/ascii.ts:4",
    "non-object": "expected a JSON object",
    "out-of-scope": "locations: expected at least one in-scope file",
    "path-traversal":
      "path: expected a repository-relative path without traversal",
    "start-line-boolean": "start_line: expected a positive integer",
    "unknown-candidate-field": "unsupported fields unexpected",
    "unknown-location-field": "locations: unsupported fields unexpected",
  };
  return messages[kind];
}

function normalizedStdout(stdout: string, output: string): string {
  return stdout.replace(output, "<output>");
}

describe("candidate normalizer differential properties", () => {
  test("matches Python byte-for-byte and is invariant to order and duplicates", () => {
    fc.assert(
      fc.property(
        candidateRows,
        fc.integer({ min: 1, max: 3 }),
        fc.constantFrom("\n", "\r\n"),
        fc.boolean(),
        fc.boolean(),
        (rows, fileCount, lineEnding, finalLineEnding, includeDeleted) => {
          const { inventory, repository, root } = fixture(
            lineEnding,
            finalLineEnding,
            includeDeleted,
          );
          try {
            const originalInputs = inputArguments(
              writeInputs(root, "original", rows, fileCount),
            );
            const transformedRows = [...rows].reverse();
            transformedRows.splice(
              Math.floor(transformedRows.length / 2),
              0,
              rows[0]!,
            );
            const transformedInputs = inputArguments(
              writeInputs(root, "transformed", transformedRows, fileCount),
            );
            const outputs = {
              python: join(root, "python.jsonl"),
              pythonTransformed: join(root, "python-transformed.jsonl"),
              typescript: join(root, "typescript.jsonl"),
              typescriptTransformed: join(root, "typescript-transformed.jsonl"),
            };
            const allowMissing = includeDeleted;
            const results = [
              runPythonNormalizer(
                normalizerArguments(
                  originalInputs,
                  outputs.python,
                  repository,
                  inventory,
                  allowMissing,
                ),
              ),
              runTypeScriptNormalizer(
                normalizerArguments(
                  originalInputs,
                  outputs.typescript,
                  repository,
                  inventory,
                  allowMissing,
                ),
              ),
              runPythonNormalizer(
                normalizerArguments(
                  transformedInputs,
                  outputs.pythonTransformed,
                  repository,
                  inventory,
                  allowMissing,
                ),
              ),
              runTypeScriptNormalizer(
                normalizerArguments(
                  transformedInputs,
                  outputs.typescriptTransformed,
                  repository,
                  inventory,
                  allowMissing,
                ),
              ),
            ];
            for (const result of results) {
              expect(result.status, result.stderr).toBe(0);
              expect(result.stderr).toBe("");
            }
            expect(
              normalizedStdout(results[1]!.stdout, outputs.typescript),
            ).toBe(normalizedStdout(results[0]!.stdout, outputs.python));
            expect(
              normalizedStdout(
                results[3]!.stdout,
                outputs.typescriptTransformed,
              ),
            ).toBe(
              normalizedStdout(results[2]!.stdout, outputs.pythonTransformed),
            );
            const expected = readFileSync(outputs.python);
            expect(readFileSync(outputs.typescript).equals(expected)).toBe(
              true,
            );
            expect(
              readFileSync(outputs.pythonTransformed).equals(expected),
            ).toBe(true);
            expect(
              readFileSync(outputs.typescriptTransformed).equals(expected),
            ).toBe(true);
          } finally {
            rmSync(root, { recursive: true, force: true });
          }
        },
      ),
      filesystemPropertyOptions,
    );
  });

  test("matches Python for generated file bytes and Unicode path spellings", () => {
    fc.assert(
      fc.property(
        safeFilename,
        fc.uint8Array({ minLength: 1, maxLength: 128 }),
        fc.nat(),
        fc.nat(),
        fc.integer({ min: 0, max: 3 }),
        fc.integer({ min: 0, max: 3 }),
        fc.constantFrom(...ROLES),
        (
          filename,
          contents,
          firstLine,
          secondLine,
          scopeVariant,
          candidateVariant,
          role,
        ) => {
          const { inventory, repository, root } = fixture();
          try {
            const canonicalPath = `src/${filename}`;
            writeSource(repository, canonicalPath, contents);
            writeFileSync(
              inventory,
              `${pathSpelling(filename, scopeVariant)}\n`,
            );
            const lineCount = byteLineCount(contents);
            const left = (firstLine % lineCount) + 1;
            const right = (secondLine % lineCount) + 1;
            const input = join(root, "generated-path.jsonl");
            writeFileSync(
              input,
              `${JSON.stringify({
                cwe_ids: [],
                locations: [
                  {
                    path: pathSpelling(filename, candidateVariant),
                    start_line: Math.min(left, right),
                    end_line: Math.max(left, right),
                    role,
                  },
                ],
                summary: "Generated path candidate",
                evidence: "Generated path evidence",
              })}\n`,
            );
            const pythonOutput = join(root, "python-path.jsonl");
            const typescriptOutput = join(root, "typescript-path.jsonl");
            const pythonResult = runPythonNormalizer(
              normalizerArguments([input], pythonOutput, repository, inventory),
            );
            const typescriptResult = runTypeScriptNormalizer(
              normalizerArguments(
                [input],
                typescriptOutput,
                repository,
                inventory,
              ),
            );

            expect(pythonResult.status, pythonResult.stderr).toBe(0);
            expect(typescriptResult.status, typescriptResult.stderr).toBe(0);
            expect(pythonResult.stderr).toBe("");
            expect(typescriptResult.stderr).toBe("");
            expect(
              normalizedStdout(typescriptResult.stdout, typescriptOutput),
            ).toBe(normalizedStdout(pythonResult.stdout, pythonOutput));
            expect(
              readFileSync(typescriptOutput).equals(readFileSync(pythonOutput)),
            ).toBe(true);
          } finally {
            rmSync(root, { recursive: true, force: true });
          }
        },
      ),
      filesystemPropertyOptions,
    );
  });

  test("agrees with Python on arbitrary JSON documents", () => {
    fc.assert(
      fc.property(
        fc.jsonValue({ maxDepth: 4, stringUnit: "binary" }),
        (value) => {
          const { inventory, repository, root } = fixture();
          try {
            const input = join(root, "arbitrary.jsonl");
            writeFileSync(input, `${JSON.stringify(value)}\n`);
            const sentinel = Buffer.from("existing output\n");
            const pythonOutput = join(root, "python-arbitrary.jsonl");
            const typescriptOutput = join(root, "typescript-arbitrary.jsonl");
            writeFileSync(pythonOutput, sentinel);
            writeFileSync(typescriptOutput, sentinel);
            const pythonResult = runPythonNormalizer(
              normalizerArguments([input], pythonOutput, repository, inventory),
            );
            const typescriptResult = runTypeScriptNormalizer(
              normalizerArguments(
                [input],
                typescriptOutput,
                repository,
                inventory,
              ),
            );

            expect(pythonResult.status === 0 || pythonResult.status === 2).toBe(
              true,
            );
            expect(typescriptResult.status).toBe(pythonResult.status);
            if (pythonResult.status === 0) {
              expect(
                readFileSync(typescriptOutput).equals(
                  readFileSync(pythonOutput),
                ),
              ).toBe(true);
              expect(
                normalizedStdout(typescriptResult.stdout, typescriptOutput),
              ).toBe(normalizedStdout(pythonResult.stdout, pythonOutput));
            } else {
              expect(readFileSync(pythonOutput).equals(sentinel)).toBe(true);
              expect(readFileSync(typescriptOutput).equals(sentinel)).toBe(
                true,
              );
              expect(pythonResult.stderr).toMatch(/^normalize_candidates:/u);
              expect(typescriptResult.stderr).toMatch(
                /^normalize_candidates:/u,
              );
            }
          } finally {
            rmSync(root, { recursive: true, force: true });
          }
        },
      ),
      filesystemPropertyOptions,
    );
  });

  test("rejects the same invalid families without changing existing output", () => {
    fc.assert(
      fc.property(
        candidateRows,
        invalidKind,
        fc.uint8Array({ minLength: 1, maxLength: 32 }),
        (rows, kind, sentinel) => {
          const { inventory, repository, root } = fixture();
          try {
            const input = join(root, "invalid.jsonl");
            writeFileSync(input, `${invalidLine(kind, rows[0]!)}\n`);
            const pythonOutput = join(root, "python.jsonl");
            const typescriptOutput = join(root, "typescript.jsonl");
            writeFileSync(pythonOutput, sentinel);
            writeFileSync(typescriptOutput, sentinel);
            const before = readdirSync(root).sort();
            const pythonResult = runPythonNormalizer(
              normalizerArguments([input], pythonOutput, repository, inventory),
            );
            const typescriptResult = runTypeScriptNormalizer(
              normalizerArguments(
                [input],
                typescriptOutput,
                repository,
                inventory,
              ),
            );
            for (const result of [pythonResult, typescriptResult]) {
              expect(result.status).toBe(2);
              expect(result.stdout).toBe("");
              expect(result.stderr).toMatch(/^normalize_candidates:/u);
              const message = expectedError(kind);
              if (message !== undefined) {
                expect(result.stderr).toContain(message);
              }
            }
            expect(
              readFileSync(pythonOutput).equals(Buffer.from(sentinel)),
            ).toBe(true);
            expect(
              readFileSync(typescriptOutput).equals(Buffer.from(sentinel)),
            ).toBe(true);
            expect(readdirSync(root).sort()).toEqual(before);
          } finally {
            rmSync(root, { recursive: true, force: true });
          }
        },
      ),
      {
        ...filesystemPropertyOptions,
        numRuns: filesystemPropertyOptions.numRuns + INVALID_KINDS.length,
        examples: INVALID_KINDS.map(
          (kind, index): [CandidateRow[], InvalidKind, Uint8Array] => [
            VALID_EXAMPLE_ROWS,
            kind,
            Uint8Array.of(index + 1),
          ],
        ),
      },
    );
  });
});
