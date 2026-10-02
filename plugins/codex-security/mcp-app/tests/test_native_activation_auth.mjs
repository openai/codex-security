import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { build } from "esbuild";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { captureEnvironment } from "../../../../sdk/typescript/tests-support/process-environment.mjs";

const sourceUrl = new URL("../src/native-scan.ts", import.meta.url);
const bundle = await build({
  bundle: true,
  entryPoints: [fileURLToPath(sourceUrl)],
  define: { "import.meta.url": JSON.stringify(sourceUrl.href) },
  format: "cjs",
  platform: "node",
  write: false,
});
const module = { exports: {} };
new Function("require", "module", "exports", bundle.outputFiles[0].text)(
  createRequire(import.meta.url),
  module,
  module.exports,
);
const { prepareNativeScan } = module.exports;
const pluginRoot = fileURLToPath(
  new URL("../../../../sdk/typescript/_bundled_plugin/", import.meta.url),
);
for (const [credential, auth, saved] of ["bearer", "env-key"].flatMap(
  (credential) =>
    ["auto", "api-key"].flatMap((auth) =>
      [false, true].map((saved) => [credential, auth, saved]),
    ),
)) {
  test(
    `native ${credential} credentials reach actual SDK authentication, auth=${auth}, saved=${saved}`,
    { skip: process.platform === "win32" },
    async () => {
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "native-bearer-auth-")),
      );
      const home = join(root, "home");
      const target = join(root, "repository");
      const executable = join(root, "codex");
      const restore = captureEnvironment([
        "CODEX_HOME",
        "CODEX_CLI_PATH",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "SYNTHETIC_PROVIDER_KEY",
      ]);
      try {
        await mkdir(home, { mode: 0o700 });
        await mkdir(target);
        await mkdir(join(root, "scan"), { mode: 0o700 });
        await writeFile(join(target, "source.py"), "print('synthetic')\n");
        await writeFile(
          executable,
          `#!${process.execPath}\nif (process.argv.includes("login")) {console.error("Not logged in"); process.exit(1);} console.error("Unexpected native command"); process.exit(2);\n`,
          { mode: 0o700 },
        );
        const config = {
          model: "gpt-6-astra",
          model_provider: "synthetic",
          model_providers: {
            synthetic: {
              name: "Synthetic",
              base_url: "https://example.invalid/v1",
              requires_openai_auth: true,
              ...(credential === "bearer"
                ? { experimental_bearer_token: "synthetic-provider-token" }
                : { env_key: "SYNTHETIC_PROVIDER_KEY" }),
            },
          },
        };
        await writeFile(
          join(home, "config.toml"),
          'model = "gpt-6-astra"\nmodel_provider = "synthetic"\n[model_providers.synthetic]\nname = "Synthetic"\nbase_url = "https://example.invalid/v1"\nrequires_openai_auth = true\n' +
            (credential === "bearer"
              ? 'experimental_bearer_token = "synthetic-provider-token"\n'
              : 'env_key = "SYNTHETIC_PROVIDER_KEY"\n'),
        );
        Object.assign(process.env, {
          CODEX_HOME: home,
          CODEX_CLI_PATH: executable,
          SYNTHETIC_PROVIDER_KEY: "synthetic-provider-key",
        });
        for (const key of [
          "CODEX_SECURITY_CONFIG_PATH",
          "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
          "CODEX_API_KEY",
          "OPENAI_API_KEY",
        ])
          delete process.env[key];
        const controller = new AbortController();
        const prepared = await prepareNativeScan(
          {
            scan: {
              scanId: randomUUID(),
              scanDir: join(root, "scan"),
              targetPath: target,
              userContext: "Review synthetic input.",
            },
            threadId: "synthetic-owner",
            pluginRoot,
            pythonPath: process.env.PYTHON || "python3",
            parentSandbox: { filesystemDenies: [] },
            recipe: { auth, ...(saved ? { config } : {}) },
          },
          controller.signal,
        );
        assert.equal(prepared.options.auth, auth);
        let authenticated = false;
        let failure;
        try {
          await assert.rejects(
            prepared.client.run(target, {
              ...prepared.options,
              signal: controller.signal,
              onAuthentication() {
                authenticated = true;
                controller.abort(
                  new Error("Synthetic authentication observed"),
                );
              },
            }),
            (error) => {
              failure = error;
              return true;
            },
          );
          assert.equal(
            authenticated,
            true,
            `configured provider token must pass the real SDK authentication boundary: ${failure?.stack}`,
          );
        } finally {
          await prepared.client.close();
        }
      } finally {
        restore();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}
