import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("installed native registration preserves large context and joins the same parent", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-native-registration-")),
  );
  try {
    const repository = join(root, "repository");
    await mkdir(repository, { mode: 0o700 });
    await writeFile(join(repository, "source.py"), "# source fixture\n");
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const userContext = "security focus ".repeat(5_000).trim();
    const start = () => {
      const result = Bun.spawnSync(
        [
          python!,
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
          "begin-deep-scan",
          "--thread-id",
          "native-owner",
          "--target-path",
          repository,
          "--scope",
          ".",
          "--user-context-stdin",
          "--scan-root",
          join(root, "scans"),
        ],
        {
          env: {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: join(root, "state"),
          },
          stdin: Buffer.from(userContext),
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
      return JSON.parse(new TextDecoder().decode(result.stdout));
    };
    const started = start();
    expect(started.scan.userContext).toBe(userContext);
    expect(started.scan.handoffClaimToken).toBeString();
    const joined = start();
    expect(joined.scan.scanId).toBe(started.scan.scanId);
    expect(joined.scan.handoffClaimToken).toBe(started.scan.handoffClaimToken);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
