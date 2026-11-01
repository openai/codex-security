import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { normalizeCandidateBatch, normalizeCandidatesCommand } =
  await importSource(
    join(import.meta.dirname, "../src/helpers/normalize-candidates.ts"),
  );

const cases = [
  {
    name: "accepts LF inventories and preserves filename whitespace",
    files: [" file.ts", "other.ts"],
    inventory: "\n file.ts\nother.ts\n",
    candidate: " file.ts",
  },
  {
    name: "accepts CRLF inventories",
    files: ["file", "other"],
    inventory: "\r\nfile\r\nother\r\n",
    candidate: "file",
  },
  {
    name: "accepts an unterminated final row",
    files: ["file", "other"],
    inventory: "other\nfile",
    candidate: "file",
  },
  {
    name: "keeps missing diff-scope files with CRLF inventories",
    files: ["file"],
    inventory: "file\r\ndeleted\r\n",
    candidate: "file",
    allowMissing: true,
  },
  {
    name: "rejects a missing file outside diff mode",
    files: ["file"],
    inventory: "deleted\nfile\n",
    candidate: "file",
    error: /ENOENT/,
  },
];

for (const fixture of cases) {
  test(fixture.name, async (t) => {
    const root = await temporaryDirectory("normalize-candidates-");
    t.after(() => rm(root, { recursive: true, force: true }));
    const repo = join(root, "repo");
    await mkdir(repo);
    for (const name of fixture.files)
      await writeFile(join(repo, name), "source\n");
    const inventory = join(root, "inventory.txt");
    await writeFile(inventory, fixture.inventory);
    const input = join(root, "input.jsonl");
    await writeFile(
      input,
      JSON.stringify({
        cwe_ids: ["CWE-20"],
        locations: [
          {
            path: fixture.candidate,
            start_line: 1,
            end_line: 1,
            role: "entrypoint",
          },
        ],
        summary: "Synthetic candidate",
        evidence: "Synthetic evidence",
      }) + "\n",
    );
    const output = join(root, "output.jsonl");
    const errors: string[] = [];
    t.mock.method(console, "log", () => {});
    t.mock.method(console, "error", (message: string) => errors.push(message));
    const status = normalizeCandidatesCommand([
      "--input",
      input,
      "--out",
      output,
      "--repo-root",
      repo,
      "--in-scope-files",
      inventory,
      ...(fixture.allowMissing ? ["--allow-missing-in-scope"] : []),
    ]);
    if (fixture.error) {
      assert.equal(status, 2);
      assert.match(errors.join("\n"), fixture.error);
      await assert.rejects(readFile(output), { code: "ENOENT" });
    } else {
      assert.equal(status, 0, errors.join("\n"));
      const normalized = JSON.parse(await readFile(output, "utf8"));
      assert.equal(normalized.locations[0].path, fixture.candidate);
    }
  });
}

test("reports the candidate field that invalidates the second batch row", async (t) => {
  const root = await temporaryDirectory("normalize-candidates-");
  t.after(() => rm(root, { recursive: true, force: true }));
  const scopePath = join(root, "inventory.txt");
  await writeFile(scopePath, "source.ts\n");
  await writeFile(join(root, "source.ts"), "one\ntwo\n");
  const location = { path: "source.ts", start_line: 2, role: "entrypoint" };
  const valid = {
    cwe_ids: ["CWE-89"],
    locations: [location],
    summary: "Synthetic candidate",
    evidence: "Synthetic evidence",
  };

  for (const [change, error] of [
    [{ cwe_ids: null }, "cwe_ids: expected an array"],
    [{ cwe_ids: [12] }, "cwe_ids: expected CWE strings"],
    [
      { cwe_ids: ["SQL injection"] },
      'cwe_ids: unsupported value "SQL injection"',
    ],
    [{ cwe_ids: ["CWE-0"] }, 'cwe_ids: unsupported value "CWE-0"'],
    [{ locations: [] }, "locations: expected a non-empty array"],
    [{ locations: [null] }, "locations: expected location objects"],
    [
      { locations: [{ ...location, end_line: 1 }] },
      "end_line: must be greater than or equal to start_line",
    ],
    [
      { locations: [{ ...location, role: "rootControl" }] },
      "role: unsupported value rootControl",
    ],
    [
      { locations: [{ ...location, line: 2 }] },
      "locations: unsupported fields line",
    ],
    [{ disposition: "reportable" }, "unsupported fields disposition"],
    [{ candidate_id: " " }, "candidate_id: expected a non-empty string"],
    [{ summary: " \t\r\n" }, "summary: expected a non-empty string"],
    [{ evidence: null }, "evidence: expected a non-empty string"],
    [{ context: " " }, "context: expected a non-empty string"],
    [{ instance: false }, "instance: expected a non-empty string"],
  ] as const) {
    assert.throws(
      () =>
        normalizeCandidateBatch({
          repoRoot: root,
          scopePath,
          allowMissing: false,
          candidates: [valid, { ...valid, ...change }],
        }),
      { message: `discovery candidates: candidate input row 2: ${error}` },
    );
  }
});
