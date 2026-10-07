import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { normalizeCandidatesCommand } = await importSource(
  join(import.meta.dirname, "../src/helpers/normalize-candidates.ts"),
);

const cases = [
  {
    name: "preserves a literal trailing carriage return",
    files: ["file\r"],
    inventory: "file\r\n",
    candidate: "file\r",
  },
  {
    name: "accepts CRLF inventories",
    files: ["file", "other"],
    inventory: "\r\nfile\r\nother\r\n",
    candidate: "file",
  },
  {
    name: "uses independent CRLF evidence when filenames collide",
    files: ["file", "file\r", "other"],
    inventory: "file\r\nother\r\n",
    candidate: "file",
  },
  {
    name: "preserves separately listed carriage-return filenames",
    files: ["file", "file\r"],
    inventory: "file\nfile\r\n",
    candidate: "file\r",
  },
  {
    name: "preserves an unterminated final literal filename",
    files: ["file", "file\r", "other"],
    inventory: "other\r\nfile\r",
    candidate: "file\r",
  },
  {
    name: "uses independent literal filename evidence",
    files: ["file", "file\r", "literal\r"],
    inventory: "file\r\nliteral\r\n",
    candidate: "file\r",
  },
  {
    name: "does not strip an unterminated missing literal filename",
    files: ["file"],
    inventory: "file\r",
    candidate: "file",
    error: /ENOENT/,
  },
  {
    name: "keeps an unterminated missing literal outside a diff scope",
    files: ["file"],
    inventory: "file\r",
    candidate: "file",
    allowMissing: true,
    error: /expected at least one in-scope file/,
  },
  {
    name: "does not infer CRLF from an unterminated row",
    files: ["file", "file\r", "other"],
    inventory: "file\r\nother\r",
    candidate: "file",
    error: /ambiguous carriage-return paths/,
  },
  {
    name: "rejects an ambiguous inventory without selecting another file",
    files: ["file", "file\r"],
    inventory: "file\r\n",
    candidate: "file",
    error: /ambiguous carriage-return paths/,
  },
  {
    name: "keeps CRLF normalization for missing diff-scope files",
    files: ["file"],
    inventory: "file\r\ndeleted\r\n",
    candidate: "file",
    allowMissing: true,
  },
  {
    name: "does not replace a missing CRLF path with its literal sibling",
    files: ["file\r", "other"],
    inventory: "file\r\nother\r\n",
    candidate: "file\r",
    allowMissing: true,
    error: /ambiguous carriage-return paths/,
  },
  {
    name: "preserves explicitly listed literal siblings in a diff scope",
    files: ["file\r"],
    inventory: "file\nfile\r\n",
    candidate: "file\r",
    allowMissing: true,
  },
];

for (const fixture of cases) {
  test(fixture.name, { skip: process.platform === "win32" }, async (t) => {
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
