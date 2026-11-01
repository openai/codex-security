import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { TestClient } from "./support/api-client.js";
import { nodeCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-api-login-",
);
afterEach(cleanup);

test.each(["loginChatGPT", "loginChatGPTDeviceCode"] as const)(
  "%s does not start a child when closed during provider command preparation",
  async (method) => {
    const root = await temporaryDirectory();
    const marker = join(root, "child-started");
    const script = join(root, "synthetic-native.mjs");
    await writeFile(
      script,
      `import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(marker)}, "synthetic child started");
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
process.exit(1);
`,
    );
    let closing: Promise<void> | undefined;
    const client = new TestClient(
      {},
      {
        environment: {
          ...process.env,
          CODEX_SECURITY_STATE_DIR: root,
          NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
        },
        resolveCodexCommand: () => {
          closing = Promise.resolve().then(() => client.close());
          return nodeCommand();
        },
      },
    );
    try {
      await expect(client[method]()).rejects.toThrow("CodexSecurity is closed");
      await closing;
      expect(existsSync(marker)).toBe(false);
    } finally {
      await client.close();
    }
  },
);
