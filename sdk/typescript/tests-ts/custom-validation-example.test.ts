import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { runCommand } from "./support/shell.js";

test("compiled validation example saves HTTP proof and exits after server cleanup", async () => {
  const source = await mkdtemp(join(tmpdir(), "custom-validation-example-"));
  const output = await mkdtemp(join(tmpdir(), "custom-validation-proof-"));
  const packageRoot = fileURLToPath(new URL("..", import.meta.url));
  try {
    const build = await runCommand(
      "node",
      ["--run", "build:examples", "--", "--outDir", source],
      { cwd: packageRoot, timeout: 30_000 },
    );
    expect(build.status, build.stdout + build.stderr).toBe(0);
    const proofPath = join(output, "artifacts", "http-proof.json");
    const result = await runCommand(
      "node",
      [join(source, "validate.mjs"), "--output", proofPath],
      { timeout: 30_000 },
    );
    // A server left listening would prevent this process from exiting normally.
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    const proof = {
      anonymous: { status: 401, body: { error: "unauthorized" } },
      own_invoice: {
        status: 200,
        body: { id: "1001", owner: "alice", amount: 25 },
      },
      other_invoice: {
        status: 200,
        body: { id: "1002", owner: "bob", amount: 80 },
      },
      cross_account_read: true,
      server_stopped: true,
    };
    expect(JSON.parse(result.stdout)).toEqual(proof);
    expect(JSON.parse(await readFile(proofPath, "utf8"))).toEqual(proof);
  } finally {
    await Promise.all([
      rm(source, { recursive: true, force: true }),
      rm(output, { recursive: true, force: true }),
    ]);
  }
});
