import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import { temporaryDirectory } from "./support/temporary-directories.js";
import {
  inspectWindowsCredentialAcl,
  prepareCodexSecurityCredentialHome,
  requireSecureCredentialHome,
} from "../src/runtime.js";

const testHostedWindows = test.skipIf(
  process.platform !== "win32" ||
    process.env["GITHUB_ACTIONS"] !== "true" ||
    process.env["RUNNER_ENVIRONMENT"] !== "github-hosted" ||
    process.env["CODEX_SECURITY_ALLOW_MACHINE_POLICY_TEST"] !== "true",
);

let temporaryRoot: string | undefined;
afterEach(async () => {
  if (temporaryRoot !== undefined)
    await rm(temporaryRoot, { recursive: true, force: true });
  temporaryRoot = undefined;
});

describe("runtime directories and plugin Python boundary", () => {
  testHostedWindows(
    "diagnoses an Everyone-owned Windows ancestor before repairing credential ACLs",
    async () => {
      const root = await temporaryDirectory("codex-security-owner-", true);
      temporaryRoot = root;
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const windowsTestCommand = (
        tool: string,
        args: readonly string[],
        environment?: NodeJS.ProcessEnv,
      ) =>
        spawnSync(join(systemDirectory, tool), args, {
          encoding: "utf8",
          windowsHide: true,
          env: environment,
        });
      const inspectWindowsTestAcl = (
        statements: string[],
        environment: NodeJS.ProcessEnv,
      ) =>
        windowsTestCommand(
          join("WindowsPowerShell", "v1.0", "powershell.exe"),
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            statements.join("; "),
          ],
          {
            ...Object.fromEntries(
              Object.entries(environment).filter(
                ([name]) => name.toUpperCase() !== "PSMODULEPATH",
              ),
            ),
            PSModulePath: join(
              systemDirectory,
              "WindowsPowerShell",
              "v1.0",
              "Modules",
            ),
          },
        );
      const state = dirname(home);
      const auth = join(home, "auth.json");
      const contents = '{"token":"synthetic-credential"}\n';
      await writeFile(auth, contents);
      const grant = windowsTestCommand("icacls.exe", [
        home,
        "/grant",
        "*S-1-1-0:(OI)(CI)R",
      ]);
      expect(grant.status, grant.stderr).toBe(0);

      const ancestors: string[] = [];
      for (let ancestor = state; ; ancestor = dirname(ancestor)) {
        ancestors.push(ancestor);
        if (ancestor === dirname(ancestor)) break;
      }
      const paths = [...ancestors, home, auth];
      const snapshot = () => {
        const result = inspectWindowsTestAcl(
          [
            "$ErrorActionPreference = 'Stop'",
            "$paths = ConvertFrom-Json -InputObject $env:CODEX_SECURITY_TEST_ACL_PATHS",
            "@($paths | ForEach-Object { $acl = Get-Acl -LiteralPath $_; [pscustomobject]@{ owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; sddl = $acl.Sddl } }) | ConvertTo-Json -Compress",
          ],
          {
            ...process.env,
            CODEX_SECURITY_TEST_ACL_PATHS: JSON.stringify(paths),
          },
        );
        expect(result.status, result.stderr).toBe(0);
        const descriptors = JSON.parse(result.stdout) as {
          owner: string;
          sddl: string;
        }[];
        expect(descriptors).toHaveLength(paths.length);
        return descriptors;
      };
      const setOwner = (owner: string) => {
        const result = inspectWindowsTestAcl(
          [
            "$ErrorActionPreference = 'Stop'",
            "$acl = Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH",
            "$acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new($env:CODEX_SECURITY_TEST_OWNER))",
            "Set-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH -AclObject $acl",
          ],
          {
            ...process.env,
            CODEX_SECURITY_TEST_ACL_PATH: state,
            CODEX_SECURITY_TEST_OWNER: owner,
          },
        );
        expect(result.status, result.stderr).toBe(0);
      };
      const original = snapshot();
      const identity = windowsTestCommand("whoami.exe", [
        "/user",
        "/fo",
        "csv",
        "/nh",
      ]);
      expect(identity.status, identity.stderr).toBe(0);
      const sid = /"(S-1-(?:\d+-)*\d+)"\s*$/u.exec(identity.stdout)?.[1];
      expect(sid).toBeDefined();
      const administrator = inspectWindowsTestAcl(
        [
          "$ErrorActionPreference = 'Stop'",
          "Microsoft.PowerShell.Utility\\ConvertFrom-SddlString -Sddl 'O:LAG:SYD:(A;;GA;;;SY)' | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty RawDescriptor | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Owner | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Value",
        ],
        process.env,
      );
      expect(administrator.status, administrator.stderr).toBe(0);
      const localAdministrator = administrator.stdout.trim();
      expect(localAdministrator).toMatch(/^S-1-(?:\d+-)*500$/u);
      const resolvedAliases = { LA: localAdministrator };
      expect(
        inspectWindowsCredentialAcl(original[ancestors.length]!.sddl, sid!, {
          resolvedAliases,
        }).untrustedPrincipals,
      ).toContain("S-1-1-0");

      try {
        setOwner("S-1-1-0");
        const before = snapshot();
        expect(before[0]!.owner).toBe("S-1-1-0");
        const failure = await prepareCodexSecurityCredentialHome({
          CODEX_SECURITY_STATE_DIR: state,
        }).catch((error: unknown) => error);
        expect(failure).toBeInstanceOf(Error);
        expect((failure as Error).message).toContain(
          `ancestor could not be trusted: ${state}.`,
        );
        expect((failure as Error).message).toContain(
          "owner is not a trusted principal: S-1-1-0",
        );
        expect(snapshot()).toEqual(before);
        expect(await readFile(auth, "utf8")).toBe(contents);
      } finally {
        setOwner(original[0]!.owner);
      }

      expect(snapshot()).toEqual(original);
      expect(
        await prepareCodexSecurityCredentialHome({
          CODEX_SECURITY_STATE_DIR: state,
        }),
      ).toBe(home);
      const repaired = snapshot();
      expect(repaired.slice(0, ancestors.length)).toEqual(
        original.slice(0, ancestors.length),
      );
      for (const [offset, scope] of [
        [0, "directory"],
        [1, "file"],
      ] as const) {
        expect(
          inspectWindowsCredentialAcl(
            repaired[ancestors.length + offset]!.sddl,
            sid!,
            { scope, resolvedAliases },
          ),
        ).toMatchObject({
          grantsCurrentUserAccess: true,
          untrustedPrincipals: [],
        });
      }
      await expect(requireSecureCredentialHome(home)).resolves.toBeDefined();
      expect(await readFile(auth, "utf8")).toBe(contents);
    },
  );

  testHostedWindows(
    "prepares managed credential homes under constrained PowerShell",
    async () => {
      const root = await temporaryDirectory("codex-security-policy-", true);
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
            timeout: 60_000,
            windowsHide: true,
          },
        );
        expect(mode.error).toBeUndefined();
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
            timeout: 60_000,
            windowsHide: true,
          },
        );
        expect(oldImplementation.error).toBeUndefined();
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
            timeout: 60_000,
            windowsHide: true,
          },
        );
        expect(guest.error).toBeUndefined();
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
