import { createServer } from "node:net";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { normalizeTarget } from "../src/targets.js";

test.skipIf(process.platform === "win32")(
  "rejects special filesystem nodes during path-target preflight",
  async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-special-target-"));
    const repository = join(root, "repository");
    const socketPath = join(repository, "target.sock");
    await mkdir(repository);
    const server = createServer();

    try {
      await new Promise<void>((resolvePromise, reject) => {
        server.once("error", reject);
        server.listen(socketPath, () => resolvePromise());
      });

      await expect(normalizeTarget(repository, [socketPath])).rejects.toThrow(
        "Path target must be a regular file or directory",
      );
    } finally {
      await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("keeps ordinary file and directory path targets valid", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-security-regular-target-"));
  const repository = join(root, "repository");
  try {
    await mkdir(join(repository, "src"), { recursive: true });
    await writeFile(join(repository, "src", "app.ts"), "export {};\n");

    await expect(
      normalizeTarget(repository, ["src/app.ts", "src"]),
    ).resolves.toEqual({ kind: "paths", paths: ["src/app.ts", "src"] });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
