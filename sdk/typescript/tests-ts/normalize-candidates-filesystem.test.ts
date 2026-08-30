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
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  normalizerArguments,
  runNormalizer,
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

function candidate(path = "src/in-scope.ts") {
  return {
    cwe_ids: ["CWE-79"],
    locations: [{ path, start_line: 1, role: "source" }],
    summary: "Synthetic candidate",
    evidence: "Synthetic evidence",
  };
}

function fixture() {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-normalizer-filesystem-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  writeSource(repository, "src/in-scope.ts", "one\ntwo\n");
  const inventory = join(root, "in-scope.txt");
  const input = join(root, "candidates.jsonl");
  const output = join(root, "output.jsonl");
  writeFileSync(inventory, "src/in-scope.ts\n");
  writeFileSync(input, `${JSON.stringify(candidate())}\n`);
  const args = normalizerArguments([input], output, repository, inventory);
  return { root, repository, inventory, input, output, args };
}

describe("candidate normalizer filesystem contract", () => {
  test("runs through a linked helper directory", () => {
    const { root, output, args } = fixture();
    const linked = join(root, "linked-helpers");
    symlinkSync(join(PLUGIN_ROOT, "scripts"), linked, directoryLinkType);
    const result = runNormalizer(
      args,
      join(linked, "normalize_candidates.mjs"),
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(output, "utf8")).summary).toBe(
      "Synthetic candidate",
    );
  });

  test("canonicalizes directory links and preserves hard-link names", () => {
    const { inventory, repository, input, output, args } = fixture();
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
    writeFileSync(
      input,
      JSON.stringify({
        ...candidate(),
        locations: [
          { path: "linked/target.ts", start_line: 1, role: "sink" },
          { path: "aliases/hard.ts", start_line: 1, role: "source" },
        ],
      }) + "\n",
    );
    const result = runNormalizer(args);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(output, "utf8")).locations).toMatchObject([
      { path: "aliases/hard.ts" },
      { path: "real/target.ts" },
    ]);
  });

  testPosix(
    "rejects directories, broken links, and FIFOs without changing output",
    () => {
      const { repository, input, output, args } = fixture();
      mkdirSync(join(repository, "src", "directory"));
      symlinkSync("missing.ts", join(repository, "src", "broken.ts"));
      symlinkSync("loop.ts", join(repository, "src", "loop.ts"));
      const fifo = join(repository, "src", "named-pipe");
      const result = spawnSync("mkfifo", [fifo], { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
      writeFileSync(output, "existing output\n");
      for (const path of [
        "src/directory",
        "src/broken.ts",
        "src/loop.ts",
        "src/named-pipe",
      ]) {
        writeFileSync(input, `${JSON.stringify(candidate(path))}\n`);
        expect(
          runNormalizer(args, undefined, { timeout: 30_000 }).status,
          path,
        ).toBe(2);
        expect(readFileSync(output, "utf8")).toBe("existing output\n");
      }
    },
  );

  test.each(["scope", "candidate"])(
    "rejects invalid UTF-8 in %s without changing output",
    (kind) => {
      const { repository, inventory, input, output, args } = fixture();
      if (kind === "scope") {
        writeSource(repository, "src/�.ts", "one\n");
        writeFileSync(input, JSON.stringify(candidate("src/�.ts")) + "\n");
        writeFileSync(
          inventory,
          Buffer.concat([
            Buffer.from("src/"),
            Buffer.from([0xff]),
            Buffer.from(".ts\n"),
          ]),
        );
      } else {
        const contents = readFileSync(input);
        contents[contents.indexOf("Synthetic candidate")] = 0xff;
        writeFileSync(input, contents);
      }
      writeFileSync(output, "existing output\n");
      expect(runNormalizer(args).status).toBe(2);
      expect(readFileSync(output, "utf8")).toBe("existing output\n");
    },
  );

  test.each(["{", "null", "[]"])(
    "rejects invalid candidate document %s without changing output",
    (contents) => {
      const { input, output, args } = fixture();
      writeFileSync(input, `${contents}\n`);
      writeFileSync(output, "existing output\n");
      const result = runNormalizer(args);
      expect(result.status, result.stderr).toBe(2);
      expect(result.stderr).toContain("row 1");
      expect(readFileSync(output, "utf8")).toBe("existing output\n");
    },
  );

  test("skips missing scope entries without admitting files outside the repository", () => {
    const { root, repository, inventory, input, output, args } = fixture();
    const outside = join(root, "outside");
    mkdirSync(outside);
    symlinkSync(outside, join(repository, "linked"), directoryLinkType);
    writeFileSync(inventory, "src/in-scope.ts\nlinked/deleted.ts\n");
    expect(runNormalizer(args).status).toBe(2);
    const allowed = [...args, "--allow-missing-in-scope"];
    const result = runNormalizer(allowed);
    expect(result.status, result.stderr).toBe(0);
    const before = readFileSync(output);
    writeFileSync(join(outside, "deleted.ts"), "outside\n");
    expect(runNormalizer(allowed).status).toBe(2);
    expect(readFileSync(output)).toEqual(before);
    writeFileSync(inventory, "src/in-scope.ts\n");
    writeFileSync(input, JSON.stringify(candidate("linked/deleted.ts")) + "\n");
    expect(runNormalizer(allowed).status).toBe(2);
    expect(readFileSync(output)).toEqual(before);
  });

  testPosix("replaces an output symlink without changing its target", () => {
    const { root, output, args } = fixture();
    const target = join(root, "unrelated.txt");
    writeFileSync(target, "leave this alone\n");
    symlinkSync(target, output);
    const result = runNormalizer(args);
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(target, "utf8")).toBe("leave this alone\n");
    expect(JSON.parse(readFileSync(output, "utf8")).summary).toBe(
      "Synthetic candidate",
    );
  });

  test("protects candidate inputs and the scope inventory from output replacement", () => {
    const { inventory, repository, input } = fixture();
    for (const output of [input, inventory]) {
      const before = readFileSync(output);
      const result = runNormalizer(
        normalizerArguments([input], output, repository, inventory),
      );
      expect(result.status, result.stderr).toBe(2);
      expect(readFileSync(output)).toEqual(before);
    }
  });

  test("writes private files atomically and cleans failed write temporaries", () => {
    const { root, output, args } = fixture();
    writeFileSync(output, "existing output\n", { mode: 0o644 });
    const before = readdirSync(root).sort();
    const result = runNormalizer(args);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(output, "utf8")).summary).toBe(
      "Synthetic candidate",
    );
    if (process.platform !== "win32")
      expect(statSync(output).mode & 0o777).toBe(0o600);
    expect(readdirSync(root).sort()).toEqual(before);

    rmSync(output);
    mkdirSync(output);
    expect(runNormalizer(args).status).toBe(2);
    expect(statSync(output).isDirectory()).toBe(true);
    expect(readdirSync(root).sort()).toEqual(before);
  });

  testWindows(
    "accepts Windows separators and rejects absolute drive paths",
    () => {
      const { inventory, input, output, args } = fixture();
      writeFileSync(inventory, "src\\in-scope.ts\r\n");
      writeFileSync(
        input,
        JSON.stringify(candidate("src\\in-scope.ts")) + "\n",
      );
      const result = runNormalizer(args);
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(readFileSync(output, "utf8")).locations[0].path).toBe(
        "src/in-scope.ts",
      );
      writeFileSync(input, JSON.stringify(candidate("C:\\outside.ts")) + "\n");
      expect(runNormalizer(args).status).toBe(2);
    },
  );

  testWindows("protects differently cased input and scope paths", () => {
    const { inventory, repository, input } = fixture();
    for (const output of [input, inventory]) {
      const before = readFileSync(output);
      const result = runNormalizer(
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
  });
});
