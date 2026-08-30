import { spawnSync } from "node:child_process";
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, relative, sep } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  normalizerArguments,
  runPythonNormalizer,
  runTypeScriptNormalizer,
  writeSource,
} from "./support/normalize-candidates.js";

const temporaryRoots: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;
const testWindows = process.platform === "win32" ? test : test.skip;
const directoryLinkType = process.platform === "win32" ? "junction" : "dir";

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function fixture(): { inventory: string; repository: string; root: string } {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-normalizer-filesystem-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  mkdirSync(repository);
  writeSource(repository, "src/in-scope.ts", "one\ntwo\n");
  const inventory = join(root, "in-scope.txt");
  writeFileSync(inventory, "src/in-scope.ts\n");
  return { inventory, repository, root };
}

function candidate(path = "src/in-scope.ts"): Record<string, unknown> {
  return {
    cwe_ids: ["CWE-79"],
    locations: [{ path, start_line: 1, role: "source" }],
    summary: "Synthetic candidate",
    evidence: "Synthetic evidence",
  };
}

function writeCandidate(root: string, row = candidate()): string {
  const input = join(root, "candidates.jsonl");
  writeFileSync(input, `${JSON.stringify(row)}\n`);
  return input;
}

describe("candidate normalizer filesystem parity", () => {
  testPosix(
    "resolves CLI paths after directory links and parent components",
    () => {
      const { repository, root } = fixture();
      writeCandidate(repository);
      writeFileSync(join(repository, "in-scope.txt"), "src/in-scope.ts\n");
      const nested = join(repository, "nested");
      mkdirSync(nested);
      const linked = join(root, "linked");
      symlinkSync(nested, linked, "dir");
      const outputs: Buffer[] = [];
      for (const [name, run] of [
        ["python", runPythonNormalizer],
        ["typescript", runTypeScriptNormalizer],
      ] as const) {
        const output = join(root, `${name}.jsonl`);
        const result = run(
          normalizerArguments(
            [`${linked}/../candidates.jsonl`],
            output,
            `${linked}/..`,
            `${linked}/../in-scope.txt`,
          ),
        );
        expect(result.status, result.stderr).toBe(0);
        outputs.push(readFileSync(output));
      }
      expect(outputs[1]).toEqual(outputs[0]);
    },
  );

  testPosix(
    "rejects expanding symlink loops and permits repeated non-cyclic links",
    () => {
      const { inventory, repository, root } = fixture();
      const input = writeCandidate(root);
      const loop = join(root, "loop");
      symlinkSync("loop/child", loop, "dir");
      const repeated = join(root, "repeated");
      symlinkSync(root, repeated, "dir");
      const outputs: Buffer[] = [];
      for (const [name, run] of [
        ["python", runPythonNormalizer],
        ["typescript", runTypeScriptNormalizer],
      ] as const) {
        const invalid = run(
          normalizerArguments(
            [input],
            join(loop, `${name}.jsonl`),
            repository,
            inventory,
          ),
          undefined,
          { timeout: 5_000 },
        );
        expect(invalid.error).toBeUndefined();
        expect(invalid.status, invalid.stderr).toBe(2);
        expect(invalid.stdout).toBe("");
        const result = run(
          normalizerArguments(
            [input],
            join(repeated, "repeated", `${name}.jsonl`),
            repository,
            inventory,
          ),
        );
        expect(result.status, result.stderr).toBe(0);
        outputs.push(readFileSync(join(root, `${name}.jsonl`)));
      }
      expect(outputs[1]).toEqual(outputs[0]);
    },
  );

  test("expands named-user home paths before resolving CLI paths", () => {
    const { inventory, repository, root } = fixture();
    const input = writeCandidate(root);
    const user = userInfo();
    const userName =
      process.platform === "win32" ? process.env["USERNAME"]! : user.username;
    const userDirectory =
      process.platform === "win32" ? process.env["USERPROFILE"]! : user.homedir;
    const namedPath = (path: string) =>
      `~${userName}${sep}${relative(userDirectory, path)}`;
    const outputs: Buffer[] = [];
    for (const [name, run] of [
      ["python", runPythonNormalizer],
      ["typescript", runTypeScriptNormalizer],
    ] as const) {
      const output = join(root, `${name}.jsonl`);
      const result = run(
        normalizerArguments(
          [namedPath(input)],
          namedPath(output),
          namedPath(repository),
          namedPath(inventory),
        ),
      );
      expect(result.status, result.stderr).toBe(0);
      outputs.push(readFileSync(output));
    }
    expect(outputs[1]).toEqual(outputs[0]);
  });

  test.each(["1.0", "1e0"])(
    "rejects floating line tokens %s without replacing output",
    (token) => {
      const { inventory, repository, root } = fixture();
      const input = join(root, "candidates.jsonl");
      for (const field of ["start_line", "end_line"]) {
        const row = {
          ...candidate(),
          locations: [
            {
              path: "src/in-scope.ts",
              start_line: 1,
              end_line: 1,
              role: "source",
            },
          ],
        };
        writeFileSync(
          input,
          JSON.stringify(row).replace(`"${field}":1`, `"${field}":${token}`) +
            "\n",
        );
        for (const [name, run] of [
          ["python", runPythonNormalizer],
          ["typescript", runTypeScriptNormalizer],
        ] as const) {
          const output = join(root, `${name}.jsonl`);
          writeFileSync(output, "existing output\n");
          const result = run(
            normalizerArguments([input], output, repository, inventory),
          );
          expect(result.status, `${name} ${field}=${token}`).toBe(2);
          expect(result.stderr).toContain(
            `${field}: expected a positive integer`,
          );
          expect(readFileSync(output, "utf8")).toBe("existing output\n");
        }
      }
    },
  );

  test("runs through a linked helper directory", () => {
    const { inventory, repository, root } = fixture();
    const input = writeCandidate(root);
    const linked = join(root, "linked-helpers");
    symlinkSync(join(PLUGIN_ROOT, "scripts"), linked, directoryLinkType);
    const outputs: Buffer[] = [];
    for (const [name, script, run] of [
      ["python", "normalize_candidates.py", runPythonNormalizer],
      ["typescript", "normalize_candidates.mjs", runTypeScriptNormalizer],
    ] as const) {
      const output = join(root, `${name}.jsonl`);
      const result = run(
        normalizerArguments([input], output, repository, inventory),
        join(linked, script),
      );
      expect(result.status, result.stderr).toBe(0);
      outputs.push(readFileSync(output));
    }
    expect(outputs[1]).toEqual(outputs[0]);
  });

  test("canonicalizes in-repository directory links and preserves hard-link names", () => {
    const { inventory, repository, root } = fixture();
    writeSource(repository, "real/target.ts", "target\n");
    mkdirSync(join(repository, "aliases"));
    linkSync(
      join(repository, "real", "target.ts"),
      join(repository, "aliases", "hard.ts"),
    );
    symlinkSync(
      join(repository, "real"),
      join(repository, "linked"),
      directoryLinkType,
    );
    writeFileSync(inventory, "linked/target.ts\naliases/hard.ts\n");
    const input = writeCandidate(root, {
      ...candidate(),
      locations: [
        { path: "linked/target.ts", start_line: 1, role: "sink" },
        { path: "aliases/hard.ts", start_line: 1, role: "source" },
      ],
    });
    const pythonOutput = join(root, "python.jsonl");
    const typescriptOutput = join(root, "typescript.jsonl");

    const pythonResult = runPythonNormalizer(
      normalizerArguments([input], pythonOutput, repository, inventory),
    );
    const typescriptResult = runTypeScriptNormalizer(
      normalizerArguments([input], typescriptOutput, repository, inventory),
    );

    expect(pythonResult.status, pythonResult.stderr).toBe(0);
    expect(typescriptResult.status, typescriptResult.stderr).toBe(0);
    const expected = readFileSync(pythonOutput);
    expect(readFileSync(typescriptOutput).equals(expected)).toBe(true);
    expect(expected.toString("utf8")).toContain('"path":"real/target.ts"');
    expect(expected.toString("utf8")).toContain('"path":"aliases/hard.ts"');
  });

  testPosix(
    "rejects directories, broken links, and FIFOs without changing output",
    () => {
      const { inventory, repository, root } = fixture();
      mkdirSync(join(repository, "src", "directory"));
      symlinkSync("missing.ts", join(repository, "src", "broken.ts"));
      const fifo = join(repository, "src", "named-pipe");
      const mkfifo = Bun.which("mkfifo");
      expect(mkfifo).not.toBeNull();
      const fifoResult = spawnSync(mkfifo!, [fifo], { encoding: "utf8" });
      expect(fifoResult.status, fifoResult.stderr).toBe(0);

      for (const [index, path] of [
        "src/directory",
        "src/broken.ts",
        "src/named-pipe",
      ].entries()) {
        const input = join(root, `invalid-${index}.jsonl`);
        writeFileSync(input, `${JSON.stringify(candidate(path))}\n`);
        const sentinel = Buffer.from(`sentinel-${index}\n`);
        const pythonOutput = join(root, `python-${index}.jsonl`);
        const typescriptOutput = join(root, `typescript-${index}.jsonl`);
        writeFileSync(pythonOutput, sentinel);
        writeFileSync(typescriptOutput, sentinel);
        const pythonResult = runPythonNormalizer(
          normalizerArguments([input], pythonOutput, repository, inventory),
        );
        const typescriptResult = runTypeScriptNormalizer(
          normalizerArguments([input], typescriptOutput, repository, inventory),
        );

        expect(pythonResult.status, path).toBe(2);
        expect(typescriptResult.status, path).toBe(2);
        expect(readFileSync(pythonOutput).equals(sentinel), path).toBe(true);
        expect(readFileSync(typescriptOutput).equals(sentinel), path).toBe(
          true,
        );
      }
    },
  );

  test("rejects invalid UTF-8 in either input without changing output", () => {
    const { inventory, repository, root } = fixture();
    const validInput = writeCandidate(root);
    const cases = [
      {
        input: validInput,
        inventoryContents: Buffer.from([0xff, 0x0a]),
        name: "scope",
      },
      {
        input: join(root, "invalid-utf8.jsonl"),
        inventoryContents: Buffer.from("src/in-scope.ts\n"),
        name: "candidate input",
      },
    ];
    writeFileSync(cases[1]!.input, Buffer.from([0xff, 0x0a]));

    for (const [index, item] of cases.entries()) {
      writeFileSync(inventory, item.inventoryContents);
      const sentinel = Buffer.from(`sentinel-${index}\n`);
      const pythonOutput = join(root, `python-utf8-${index}.jsonl`);
      const typescriptOutput = join(root, `typescript-utf8-${index}.jsonl`);
      writeFileSync(pythonOutput, sentinel);
      writeFileSync(typescriptOutput, sentinel);
      const pythonResult = runPythonNormalizer(
        normalizerArguments([item.input], pythonOutput, repository, inventory),
      );
      const typescriptResult = runTypeScriptNormalizer(
        normalizerArguments(
          [item.input],
          typescriptOutput,
          repository,
          inventory,
        ),
      );

      expect(pythonResult.status, item.name).toBe(2);
      expect(typescriptResult.status, item.name).toBe(2);
      expect(readFileSync(pythonOutput).equals(sentinel), item.name).toBe(true);
      expect(readFileSync(typescriptOutput).equals(sentinel), item.name).toBe(
        true,
      );
    }
  });

  testPosix("rejects ambiguous carriage-return scope paths", () => {
    const { inventory, repository, root } = fixture();
    writeSource(repository, "src/literal\r", "literal\n");
    writeSource(repository, "src/crlf", "crlf\n");
    writeSource(repository, "src/both", "both\n");
    writeSource(repository, "src/both\r", "both carriage\n");
    writeFileSync(inventory, "src/literal\r\nsrc/crlf\r\nsrc/both\r\n");
    const input = writeCandidate(root, candidate("src/crlf"));
    const pythonResult = runPythonNormalizer(
      normalizerArguments(
        [input],
        join(root, "python.jsonl"),
        repository,
        inventory,
      ),
    );
    const typescriptResult = runTypeScriptNormalizer(
      normalizerArguments(
        [input],
        join(root, "typescript.jsonl"),
        repository,
        inventory,
      ),
    );

    expect(pythonResult.status).toBe(2);
    expect(typescriptResult.status).toBe(2);
    expect(pythonResult.stderr).toContain("ambiguous carriage-return paths");
    expect(typescriptResult.stderr).toContain(
      "ambiguous carriage-return paths",
    );
  });

  test("protects candidate inputs and the scope inventory from output replacement", () => {
    const { inventory, repository, root } = fixture();
    const input = writeCandidate(root);
    const inputContents = readFileSync(input);
    const inventoryContents = readFileSync(inventory);

    for (const [name, output, expected] of [
      ["input", input, inputContents],
      ["scope", inventory, inventoryContents],
    ] as const) {
      const pythonResult = runPythonNormalizer(
        normalizerArguments([input], output, repository, inventory),
      );
      const typescriptResult = runTypeScriptNormalizer(
        normalizerArguments([input], output, repository, inventory),
      );
      expect(pythonResult.status, name).toBe(2);
      expect(typescriptResult.status, name).toBe(2);
      expect(readFileSync(output).equals(expected), name).toBe(true);
    }
  });

  test("replaces output with private files and cleans failed write temporaries", () => {
    const { inventory, repository, root } = fixture();
    const input = writeCandidate(root);
    const pythonOutput = join(root, "python.jsonl");
    const typescriptOutput = join(root, "typescript.jsonl");
    writeFileSync(pythonOutput, "old Python output\n", { mode: 0o644 });
    writeFileSync(typescriptOutput, "old TypeScript output\n", {
      mode: 0o644,
    });
    const before = readdirSync(root).sort();

    const pythonResult = runPythonNormalizer(
      normalizerArguments([input], pythonOutput, repository, inventory),
    );
    const typescriptResult = runTypeScriptNormalizer(
      normalizerArguments([input], typescriptOutput, repository, inventory),
    );

    expect(pythonResult.status, pythonResult.stderr).toBe(0);
    expect(typescriptResult.status, typescriptResult.stderr).toBe(0);
    expect(
      readFileSync(typescriptOutput).equals(readFileSync(pythonOutput)),
    ).toBe(true);
    if (process.platform !== "win32") {
      expect(statSync(pythonOutput).mode & 0o777).toBe(0o600);
      expect(statSync(typescriptOutput).mode & 0o777).toBe(0o600);
    }
    expect(readdirSync(root).sort()).toEqual(before);

    const blockedPythonOutput = join(root, "blocked-python.jsonl");
    const blockedTypeScriptOutput = join(root, "blocked-typescript.jsonl");
    mkdirSync(blockedPythonOutput);
    mkdirSync(blockedTypeScriptOutput);
    const beforeFailure = readdirSync(root).sort();
    const blockedPython = runPythonNormalizer(
      normalizerArguments([input], blockedPythonOutput, repository, inventory),
    );
    const blockedTypeScript = runTypeScriptNormalizer(
      normalizerArguments(
        [input],
        blockedTypeScriptOutput,
        repository,
        inventory,
      ),
    );
    expect(blockedPython.status).toBe(2);
    expect(blockedTypeScript.status).toBe(2);
    expect(statSync(blockedPythonOutput).isDirectory()).toBe(true);
    expect(statSync(blockedTypeScriptOutput).isDirectory()).toBe(true);
    expect(readdirSync(root).sort()).toEqual(beforeFailure);
  });

  testWindows("matches Python for Windows separators and drive paths", () => {
    const { inventory, repository, root } = fixture();
    writeFileSync(inventory, "src\\in-scope.ts\r\n");
    const input = writeCandidate(root, candidate("src\\in-scope.ts"));
    const pythonOutput = join(root, "python.jsonl");
    const typescriptOutput = join(root, "typescript.jsonl");
    const pythonResult = runPythonNormalizer(
      normalizerArguments([input], pythonOutput, repository, inventory),
    );
    const typescriptResult = runTypeScriptNormalizer(
      normalizerArguments([input], typescriptOutput, repository, inventory),
    );
    expect(pythonResult.status, pythonResult.stderr).toBe(0);
    expect(typescriptResult.status, typescriptResult.stderr).toBe(0);
    expect(
      readFileSync(typescriptOutput).equals(readFileSync(pythonOutput)),
    ).toBe(true);

    writeFileSync(input, `${JSON.stringify(candidate("C:\\outside.ts"))}\n`);
    expect(
      runPythonNormalizer(
        normalizerArguments([input], pythonOutput, repository, inventory),
      ).status,
    ).toBe(2);
    expect(
      runTypeScriptNormalizer(
        normalizerArguments([input], typescriptOutput, repository, inventory),
      ).status,
    ).toBe(2);
  });

  testWindows("protects differently cased input and scope paths", () => {
    const { inventory, repository, root } = fixture();
    const input = writeCandidate(root);
    for (const output of [input, inventory]) {
      const before = readFileSync(output);
      for (const run of [runPythonNormalizer, runTypeScriptNormalizer]) {
        const result = run(
          normalizerArguments(
            [input],
            output.toUpperCase(),
            repository,
            inventory,
          ),
        );
        expect(result.status, result.stderr).toBe(2);
        expect(readFileSync(output)).toEqual(before);
      }
    }
  });
});
