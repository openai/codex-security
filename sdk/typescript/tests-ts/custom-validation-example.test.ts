import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { runCommand } from "./support/shell.js";

test("compiled validation example distinguishes vulnerable and repaired ownership checks", async () => {
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
    for (const mode of ["vulnerable", "repaired"] as const) {
      const proofPath = join(output, "artifacts", `${mode}-http-proof.json`);
      const result = await runCommand(
        "node",
        [
          join(source, "validate.mjs"),
          "--output",
          proofPath,
          ...(mode === "repaired" ? ["--mode", mode] : []),
        ],
        { timeout: 30_000 },
      );
      // A server left listening would prevent this process from exiting normally.
      expect(result.status, result.stderr).toBe(0);
      expect(result.stderr).toBe("");
      const proof = JSON.parse(result.stdout);
      expect(JSON.parse(await readFile(proofPath, "utf8"))).toEqual(proof);
      const targetInvoice = {
        status: 200,
        body: { id: "1002", owner: "bob", amount: 80 },
      };
      expect(proof).toEqual({
        mode,
        anonymous: { status: 401, body: { error: "unauthorized" } },
        own_invoice: {
          status: 200,
          body: { id: "1001", owner: "alice", amount: 25 },
        },
        target_owner_invoice: targetInvoice,
        other_invoice:
          mode === "vulnerable"
            ? targetInvoice
            : { status: 403, body: { error: "forbidden" } },
        cross_account_read: mode === "vulnerable",
        server_stopped: true,
      });
    }
  } finally {
    await Promise.all([
      rm(source, { recursive: true, force: true }),
      rm(output, { recursive: true, force: true }),
    ]);
  }
});
