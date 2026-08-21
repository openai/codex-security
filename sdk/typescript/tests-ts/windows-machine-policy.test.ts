import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";

let temporaryRoot: string | undefined;
afterEach(async () => {
  if (temporaryRoot !== undefined)
    await rm(temporaryRoot, { recursive: true, force: true });
  temporaryRoot = undefined;
});

describe("runtime directories and plugin Python boundary", () => {
  test.skipIf(
    process.platform !== "win32" ||
      process.env["GITHUB_ACTIONS"] !== "true" ||
      process.env["RUNNER_ENVIRONMENT"] !== "github-hosted" ||
      process.env["CODEX_SECURITY_ALLOW_MACHINE_POLICY_TEST"] !== "true",
  )(
    "prepares managed credential homes under constrained PowerShell",
    async () => {
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-policy-")),
      );
      temporaryRoot = root;
      const powershell = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const constrainedEnvironment = {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        PSModulePath: join(root, "untrusted-or-incompatible-modules"),
        PSMODULEPATH: join(root, "uppercase-untrusted-modules"),
      };
      const registry = join(dirname(dirname(dirname(powershell))), "reg.exe");
      const policyKey =
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
      const policyName = "__PSLockdownPolicy";
      const original = spawnSync(
        registry,
        ["query", policyKey, "/v", policyName],
        { encoding: "utf8", timeout: 15_000, windowsHide: true },
      );
      expect(original.status === 0 || original.status === 1).toBe(true);
      const originalEntry =
        original.status === 0
          ? /^\s*__PSLockdownPolicy\s+(REG_[A-Z_]+)\s*(.*?)\s*$/mu.exec(
              original.stdout,
            )
          : null;
      if (original.status === 0) expect(originalEntry).not.toBeNull();
      const originalPolicy =
        originalEntry === null
          ? null
          : { type: originalEntry[1]!, value: originalEntry[2]! };
      const enabled = spawnSync(
        registry,
        ["add", policyKey, "/v", policyName, "/t", "REG_SZ", "/d", "4", "/f"],
        { encoding: "utf8", timeout: 15_000, windowsHide: true },
      );
      expect(enabled.status).toBe(0);

      try {
        const mode = spawnSync(
          powershell,
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ExecutionContext.SessionState.LanguageMode",
          ],
          {
            encoding: "utf8",
            env: constrainedEnvironment,
            timeout: 15_000,
            windowsHide: true,
          },
        );
        expect(mode.status).toBe(0);
        expect(mode.stdout.trim()).toBe("ConstrainedLanguage");

        const oldImplementation = spawnSync(
          powershell,
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference = 'Stop'; New-Object System.Security.AccessControl.DirectorySecurity",
          ],
          {
            encoding: "utf8",
            env: constrainedEnvironment,
            timeout: 15_000,
            windowsHide: true,
          },
        );
        expect(oldImplementation.status).not.toBe(0);

        const trustedPowerShellEnvironment = {
          ...Object.fromEntries(
            Object.entries(process.env).filter(
              ([name]) => name.toUpperCase() !== "PSMODULEPATH",
            ),
          ),
          PSModulePath: join(dirname(powershell), "Modules"),
        };
        const guest = spawnSync(
          powershell,
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            [
              "Microsoft.PowerShell.Utility\\ConvertFrom-SddlString -Sddl 'O:LGG:SYD:(A;;GA;;;SY)'",
              "Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty RawDescriptor",
              "Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Owner",
              "Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Value",
            ].join(" | "),
          ],
          {
            encoding: "utf8",
            env: trustedPowerShellEnvironment,
            timeout: 15_000,
            windowsHide: true,
          },
        );
        expect(guest.status).toBe(0);
        expect(guest.stdout.trim()).toMatch(/^S-1-(?:\d+-)*501$/u);
        const home = join(root, "state", "codex-home");
        await mkdir(home, { recursive: true });
        const foreignGrant = spawnSync(
          join(dirname(dirname(dirname(powershell))), "icacls.exe"),
          [home, "/grant", `*${guest.stdout.trim()}:(OI)(CI)R`],
          { encoding: "utf8", timeout: 15_000, windowsHide: true },
        );
        expect(foreignGrant.status).toBe(0);

        const fixtureModule = join(root, "runtime-node-fixture.mjs");
        const build = spawnSync(
          process.execPath,
          [
            "build",
            fileURLToPath(new URL("../src/runtime.ts", import.meta.url)),
            "--target=node",
            "--format=esm",
            `--outfile=${fixtureModule}`,
          ],
          { encoding: "utf8", timeout: 30_000, windowsHide: true },
        );
        expect(build.status).toBe(0);
        const selectedNode = spawnSync("node", ["-p", "process.execPath"], {
          encoding: "utf8",
          timeout: 15_000,
          windowsHide: true,
        });
        expect(selectedNode.status).toBe(0);
        const fixture = spawnSync(
          selectedNode.stdout.trim(),
          [
            "--input-type=module",
            "--eval",
            `import { prepareCodexSecurityCredentialHome } from ${JSON.stringify(pathToFileURL(fixtureModule).href)}; await prepareCodexSecurityCredentialHome();`,
          ],
          {
            encoding: "utf8",
            env: constrainedEnvironment,
            timeout: 30_000,
            windowsHide: true,
          },
        );
        expect(fixture.stderr).toBe("");
        expect(fixture.status).toBe(0);
        expect(existsSync(home)).toBe(true);
      } finally {
        const restore = spawnSync(
          registry,
          originalPolicy === null
            ? ["delete", policyKey, "/v", policyName, "/f"]
            : [
                "add",
                policyKey,
                "/v",
                policyName,
                "/t",
                originalPolicy.type,
                "/d",
                originalPolicy.value,
                "/f",
              ],
          { encoding: "utf8", timeout: 15_000, windowsHide: true },
        );
        expect(restore.status).toBe(0);
      }
    },
  );
});
