import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, test } from "bun:test";

test("rejects a tokenizer build with no inventoried packages", async () => {
  const root = await mkdtemp(join(tmpdir(), "embedding-tokenizer-"));
  try {
    await mkdir(join(root, "src/server"), { recursive: true });
    await writeFile(
      join(root, "src/server/embedding-tokenizer.ts"),
      "export {};",
    );
    const build = fileURLToPath(
      new URL("../scripts/build-embedding-tokenizer.mjs", import.meta.url),
    );
    await expect(
      promisify(execFile)("node", [build], { cwd: root }),
    ).rejects.toThrow("Missing tokenizer bundle inputs");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
