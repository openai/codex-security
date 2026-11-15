import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { nodeCommand } from "./support/shell.js";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";

const temporary = createTemporaryDirectoriesSync(true);
afterEach(temporary.cleanup);

function contentQueue() {
  const root = temporary.create("standard-queue-content-");
  const repo = join(root, "repository");
  const scan = join(root, "scan");
  const context = join(scan, "artifacts", "01_context");
  mkdirSync(repo);
  mkdirSync(context, { recursive: true });

  return {
    write(name: string, contents: string | Buffer) {
      writeFileSync(join(repo, name), contents);
    },
    build(rules: { content?: string; path?: string }[], ...explicit: string[]) {
      writeFileSync(
        join(context, "standard-rules.json"),
        JSON.stringify(rules),
      );
      execFileSync(nodeCommand().command, [
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        "standard-queue",
        "build",
        scan,
        repo,
        ".",
        ...explicit,
      ]);
      return JSON.parse(
        readFileSync(join(context, "standard-queue.json"), "utf8"),
      ).batches.flat();
    },
  };
}

test("Standard matches complete UTF-8 and BOM-marked UTF-16 sources with the supplied regex", () => {
  const queue = contentQueue();
  // The named capture crosses a 64 KiB read boundary in the UTF-8 file.
  const source = " ".repeat(64 * 1024 - 2) + "key(😀)\nkey";
  queue.write("utf8.ts", source);
  queue.write("little.ts", Buffer.from("\ufeff" + source, "utf16le"));
  queue.write("big.ts", Buffer.from("\ufeff" + source, "utf16le").swap16());
  queue.write("other.ts", source.replace(/key$/u, "other"));
  expect(
    queue.build([{ content: "(?<word>key)\\(😀\\)\\n\\k<word>$" }]),
  ).toEqual(["big.ts", "little.ts", "utf8.ts"]);
});

test("Standard includes oversized text conservatively and honors binary path selection", () => {
  const queue = contentQueue();
  const text = "x".repeat(9 * 1024 * 1024);
  queue.write("large.ts", text);
  queue.write("large-match.ts", text + "needle");
  queue.write("binary.ts", Buffer.from("needle\0"));
  queue.write("binary-late.ts", text + "needle\0");
  queue.write("explicit.bin", Buffer.from("needle\0"));
  queue.write("path-only.bin", Buffer.from("needle\0"));
  queue.write("wrong-path.txt", text);
  queue.write("small.ts", "irrelevant");
  expect(
    queue.build(
      [{ path: "[.]ts$", content: "needle" }, { path: "^path-only[.]bin$" }],
      "explicit.bin",
    ),
  ).toEqual(["explicit.bin", "large-match.ts", "large.ts", "path-only.bin"]);
});
