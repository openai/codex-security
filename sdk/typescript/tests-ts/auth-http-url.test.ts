import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { CodexLoginHandle } from "../src/auth.js";

test("skips external plaintext HTTP authentication URLs", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-security-auth-http-"));
  const script = join(root, "login.mjs");
  try {
    await writeFile(
      script,
      `
console.error("Open http://auth.example.test/insecure");
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
process.exit(0);
`,
    );
    const handle = new CodexLoginHandle(
      { command: process.execPath },
      [script],
      process.env,
      () => {},
    );

    await expect(handle.wait()).resolves.toMatchObject({ success: true });
    expect(handle.verificationUrl).toBe("https://auth.example.test/device");
    expect(handle.userCode).toBe("ABCD-EFGH");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
