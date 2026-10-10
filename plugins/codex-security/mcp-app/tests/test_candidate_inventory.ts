import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import type { ArtifactContext } from "../src/artifact-io.js";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const { normalizeCandidatesCommand } = await importSource(
  new URL("../src/helpers/normalize-candidates.ts", import.meta.url).pathname,
);
const { recordCodexSecurityDiscoveryCandidates } = await importSource(
  path.join(import.meta.dirname, "../src/artifact-discovery.ts"),
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/server.mjs",
          import.meta.url,
        ).href,
      ),
    },
  },
);
const inventoryScript = path.join(
  import.meta.dirname,
  "../../scripts/generate_in_scope_files.py",
);

for (const deleted of [false, true]) {
  test(
    `normalizes a generated inventory with a ${deleted ? "deleted" : "present"} raw-byte path`,
    { skip: process.platform !== "linux" },
    async () => {
      const directories = createTemporaryDirectories(true);
      const root = await directories.create("candidate-inventory-");
      try {
        const repo = path.join(root, "repository");
        await mkdir(repo);
        const rawName = Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x2e, 0x70, 0x79]);
        const rawPath = Buffer.concat([Buffer.from(`${repo}/`), rawName]);
        const normalPath = path.join(repo, "app.py");
        await writeFile(rawPath, "first\n");
        await writeFile(normalPath, "first\n");
        const git = (...args: string[]) =>
          execFileSync(
            "git",
            [
              "-c",
              "user.name=Fixture",
              "-c",
              "user.email=fixture@example.invalid",
              ...args,
            ],
            { cwd: repo, encoding: "utf8" },
          ).trim();
        git("init", "-q");
        git("add", ".");
        git("commit", "-qm", "initial");
        const base = git("rev-parse", "HEAD");
        if (deleted) await unlink(rawPath);
        else await writeFile(rawPath, "changed\n");
        await writeFile(normalPath, "changed\n");
        git("add", ".");
        git("commit", "-qm", "change");

        const scope = path.join(root, "in-scope.txt");
        execFileSync(process.env.PYTHON ?? "python3", [
          inventoryScript,
          "--repo",
          repo,
          "--scope",
          ".",
          "--out",
          scope,
          "--diff-base",
          base,
          "--diff-head",
          "HEAD",
        ]);
        assert.deepEqual(
          await readFile(scope),
          Buffer.concat([Buffer.from("app.py\n"), rawName, Buffer.from("\n")]),
        );
        const input = path.join(root, "candidates.jsonl");
        const output = path.join(root, "combined.jsonl");
        const candidatePath = deleted ? "app.py" : "caf\udce9.py";
        await writeFile(
          input,
          JSON.stringify({
            cwe_ids: ["CWE-20"],
            locations: [{ path: candidatePath, start_line: 1, role: "source" }],
            summary: "Synthetic candidate",
            evidence: "Synthetic evidence",
          }) + "\n",
        );
        const args = [
          "--input",
          input,
          "--out",
          output,
          "--repo-root",
          repo,
          "--in-scope-files",
          scope,
        ];
        if (deleted) {
          assert.equal(normalizeCandidatesCommand(args), 2);
          args.push("--allow-missing-in-scope");
        }
        assert.equal(normalizeCandidatesCommand(args), 0);
        const retained = await readFile(output, "utf8");
        assert.equal(JSON.parse(retained).locations[0].path, candidatePath);

        const scanRoot = path.join(root, "scan");
        await mkdir(scanRoot, { mode: 0o700 });
        const discovery = path.join(scanRoot, "artifacts", "02_discovery");
        await mkdir(discovery, { recursive: true });
        await copyFile(scope, path.join(discovery, "in_scope_files.txt"));
        const context: ArtifactContext = {
          root: scanRoot,
          repoRoot: repo,
          scanId: "11111111-1111-4111-8111-111111111111",
          layout: "scan",
          pluginRoot: path.resolve(import.meta.dirname, "../.."),
          mode: "diff",
          targetContract: {
            diffTarget: {
              kind: "range",
              baseRevision: base,
              headRevision: git("rev-parse", "HEAD"),
            },
          },
        };
        for (const sourcePath of new Set(["app.py", candidatePath])) {
          assert.deepEqual(
            await recordCodexSecurityDiscoveryCandidates(
              {
                candidates: [
                  {
                    cwe_ids: ["CWE-20"],
                    locations: [
                      { path: sourcePath, start_line: 1, role: "source" },
                    ],
                    summary: "Synthetic candidate",
                    evidence: "Synthetic evidence",
                  },
                ],
              },
              context,
            ),
            { operation: "replace", candidatesRecorded: 1 },
          );
          const ledger = await readFile(
            path.join(discovery, "candidate_ledger.jsonl"),
            "utf8",
          );
          assert.equal(JSON.parse(ledger).locations[0].path, sourcePath);
        }

        // Candidate JSON remains UTF-8 even when inventory paths contain raw bytes.
        await writeFile(input, Buffer.from([0xff]));
        assert.equal(normalizeCandidatesCommand(args), 2);
        assert.equal(await readFile(output, "utf8"), retained);
      } finally {
        await directories.cleanup();
      }
    },
  );
}
