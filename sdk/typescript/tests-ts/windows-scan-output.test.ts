import { execFile } from "node:child_process";
import {
  cp,
  lstat,
  mkdir,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { promisify } from "node:util";
import { afterEach, expect, test } from "bun:test";
import { loadContract } from "../src/contract.js";
import { runMultiscan } from "../src/multiscan.js";
import * as runtime from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  client,
  completeRun,
  createMultiscanFixtures,
  options,
} from "./support/multiscan.js";

const { temporaryDirectory, repositoryFixture, cleanup } =
  createMultiscanFixtures();
afterEach(cleanup);
const exec = promisify(execFile);
const windowsTest = test.skipIf(process.platform !== "win32");
const example = join(PLUGIN_ROOT, "examples", "completed-scan");

const system = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
const powershell = join(system, "WindowsPowerShell", "v1.0");

async function icacls(path: string, ...args: string[]): Promise<void> {
  await exec(join(system, "icacls.exe"), [path, ...args]);
}

async function sharedRoot(): Promise<string> {
  const root = await temporaryDirectory();
  await icacls(root, "/grant", "*S-1-1-0:(OI)(CI)R");
  return root;
}

async function runPowerShell(script: string, environment: NodeJS.ProcessEnv) {
  const { stdout } = await exec(
    join(powershell, "powershell.exe"),
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(script, "utf16le").toString("base64"),
    ],
    {
      env: {
        ...Object.fromEntries(
          Object.entries({ ...process.env, ...environment }).filter(
            ([name]) => name.toUpperCase() !== "PSMODULEPATH",
          ),
        ),
        PSModulePath: join(powershell, "Modules"),
      },
    },
  );
  return stdout.trim();
}

windowsTest(
  "pins the system PowerShell modules for case-variant environment keys",
  async () => {
    const alternate = await temporaryDirectory();
    const result = await runPowerShell(
      [
        "$ErrorActionPreference = 'Stop'",
        "$null = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_MODULES",
        "($env:PSModulePath -split ';') -notcontains $env:CODEX_SECURITY_TEST_MODULES",
      ].join("; "),
      { PSMODULEPATH: alternate, CODEX_SECURITY_TEST_MODULES: alternate },
    );
    expect(result).toBe("True");
  },
);

function inspectAcl(path: string, expression: string): Promise<string> {
  return runPowerShell(
    `$ErrorActionPreference = 'Stop'; $acl = Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH; ${expression}`,
    { CODEX_SECURITY_TEST_ACL_PATH: path },
  );
}

async function descriptor(path: string): Promise<string> {
  return inspectAcl(path, "$acl.Sddl");
}

async function accessRules(path: string): Promise<string> {
  return inspectAcl(
    path,
    "[pscustomobject]@{ protected = $acl.AreAccessRulesProtected; entries = @($acl.Access | Select-Object FileSystemRights, AccessControlType, IdentityReference, IsInherited, InheritanceFlags, PropagationFlags) } | ConvertTo-Json -Depth 4 -Compress",
  );
}

async function createMultiscanCampaign(output: string): Promise<void> {
  const { paths } = await repositoryFixture("campaign-source");
  const result = await runMultiscan(
    options({ ...paths, output }, client(completeRun), { maxAttempts: 1 }),
  );
  expect(result).toMatchObject({ completed: 1, failed: 0 });
}

async function archiveSdkOutput(output: string, root: string): Promise<string> {
  let archive: string | undefined;
  await runtime.prepareOutputDir(
    output,
    "fixture",
    root,
    undefined,
    true,
    (path) => {
      archive = path;
    },
  );
  expect(archive).toBeDefined();
  return archive!;
}

async function archiveWorkbenchOutput(
  output: string,
  root: string,
): Promise<string> {
  const python = await runtime.resolvePluginPython();
  const result = await exec(
    python,
    [
      "-I",
      "-B",
      "-c",
      [
        "import argparse, json, sqlite3, sys",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "from workbench_scan_start import archive_scan",
        "connection = sqlite3.connect(':memory:')",
        "connection.execute('CREATE TABLE scans (id TEXT, status TEXT, scan_dir TEXT)')",
        "args = argparse.Namespace(archived_scan_dir=None, archive_existing=True)",
        "with archive_scan(connection, args, Path(sys.argv[2]), '2026-10-08T00:00:00Z', lambda path: path.resolve()) as archive:",
        "    print(json.dumps(str(archive)))",
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      output,
    ],
    {
      env: {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      },
    },
  );
  return JSON.parse(result.stdout) as string;
}

windowsTest(
  "new Windows scan roots start private beneath a shared parent",
  async () => {
    const root = await sharedRoot();
    const before = await descriptor(root);
    expect(before).toContain(";;;WD)");
    const explicit = join(root, "new parent", "scan");
    expect(await runtime.prepareOutputDir(explicit, "fixture")).toBe(
      await realpath(explicit),
    );
    const generated = await runtime.prepareOutputDir(
      undefined,
      "fixture",
      root,
    );
    const campaign = join(root, "campaign");
    await createMultiscanCampaign(campaign);
    for (const output of [
      join(root, "new parent"),
      explicit,
      generated,
      campaign,
      join(campaign, "artifacts"),
      join(campaign, "checkouts"),
    ]) {
      const acl = await descriptor(output);
      expect(acl).toContain("D:P");
      expect(acl).not.toContain(";;;WD)");
    }
    expect(await descriptor(root)).toBe(before);
  },
);

windowsTest.each([204, 233])(
  "generated Windows output supports a %i-character repository name",
  async (length) => {
    const root = await sharedRoot();
    const output = await runtime.prepareOutputDir(
      undefined,
      "r".repeat(length),
      root,
    );
    expect((await lstat(output)).isDirectory()).toBe(true);
    expect(basename(output).length).toBeLessThanOrEqual(255);
    expect(basename(output)).toMatch(
      /-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    const acl = await descriptor(output);
    expect(acl).toContain("D:P");
    expect(acl).not.toContain(";;;WD)");
  },
);

windowsTest(
  "fresh SDK output keeps its private identity through workbench registration",
  async () => {
    const root = await sharedRoot();
    const repository = join(root, "repository");
    await mkdir(repository);
    await writeFile(join(repository, "source.txt"), "Synthetic repository");
    const output = await runtime.prepareScanRegistrationOutput(
      undefined,
      "repository",
      root,
    );
    const before = await lstat(output, { bigint: true });
    const originalAcl = await descriptor(output);
    const registered = await runtime.runWorkbench(
      {
        python: await runtime.resolvePluginPython(),
        pluginRoot: PLUGIN_ROOT,
        environment: {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
        },
      },
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        output,
        "--registration-json-stdin",
      ],
      JSON.stringify({
        recipe: {
          config: {},
          mode: "standard",
          repository,
          target: { kind: "repository", paths: [] },
        },
      }),
    );
    expect(registered["scanDir"]).toBe(await realpath(output));
    const after = await lstat(output, { bigint: true });
    expect([after.dev, after.ino]).toEqual([before.dev, before.ino]);
    expect(originalAcl).not.toContain(";;;WD)");
    expect(await descriptor(output)).toBe(originalAcl);
  },
);

windowsTest.each(
  [190, 204, 233].flatMap((length) =>
    ["SDK", "workbench"].map((archiver) => [archiver, length] as const),
  ),
)(
  "generated Windows output remains archivable through %s for a %i-character repository name",
  async (archiver, length) => {
    const root = await sharedRoot();
    const output = await runtime.prepareOutputDir(
      undefined,
      "r".repeat(length),
      root,
    );
    await writeFile(
      join(output, "retained.txt"),
      "Synthetic retained scan data",
    );
    const original = await descriptor(output);
    const archive =
      archiver === "SDK"
        ? await archiveSdkOutput(output, root)
        : await archiveWorkbenchOutput(output, root);
    expect(await descriptor(output)).toBe(original);
    expect(basename(archive).length).toBeLessThanOrEqual(255);
    expect(await readFile(join(archive, "retained.txt"), "utf8")).toBe(
      "Synthetic retained scan data",
    );
    expect(await descriptor(archive)).toBe(original);
  },
);

windowsTest("existing Windows scan ACLs are preserved", async () => {
  const root = await temporaryDirectory();
  const output = join(root, "scan");
  await mkdir(output);
  // Built-in Users exists on every Windows host; only this fixture gets the grant.
  await icacls(output, "/grant", "*S-1-5-32-545:(OI)(CI)M");
  const before = await descriptor(output);
  const permissions = await accessRules(output);
  expect(before).toContain(";;;BU)");
  expect(await runtime.prepareOutputDir(output, "fixture")).toBe(
    await realpath(output),
  );
  expect(await descriptor(output)).toBe(before);
  await cp(example, output, { recursive: true });
  expect(
    await runtime.prepareScanRegistrationOutput(
      output,
      "fixture",
      root,
      undefined,
      true,
    ),
  ).toBe(await realpath(output));
  await loadContract(output, { pluginRoot: PLUGIN_ROOT });
  expect(await descriptor(output)).toBe(before);
  const archive = await archiveWorkbenchOutput(output, root);
  expect(await descriptor(archive)).toBe(before);
  // Creation can change the auto-inheritance marker without changing the rules.
  expect(await accessRules(output)).toBe(permissions);
  await icacls(root, "/grant", "*S-1-1-0:(OI)(CI)R");
  for (const path of [archive, output]) {
    expect(await descriptor(path)).toContain(";;;WD)");
  }
  await icacls(root, "/remove:g", "*S-1-1-0");
  for (const path of [archive, output]) {
    expect(await accessRules(path)).toBe(permissions);
  }
});

windowsTest(
  "existing Windows multiscan campaign ACLs are preserved",
  async () => {
    const root = await temporaryDirectory();
    const output = join(root, "campaign");
    await mkdir(output);
    await icacls(output, "/grant", "*S-1-5-32-545:(OI)(CI)M");
    const permissions = await accessRules(output);
    await createMultiscanCampaign(output);
    expect(await accessRules(output)).toBe(permissions);
  },
);

windowsTest(
  "archiving Windows output preserves old ACLs and privately creates the replacement",
  async () => {
    const root = await sharedRoot();
    const output = join(root, "scan");
    await mkdir(output);
    await writeFile(join(output, "retained.txt"), "Synthetic retained data");
    const original = await descriptor(output);
    const archive = await archiveSdkOutput(output, root);
    expect(await descriptor(archive)).toBe(original);
    expect(await readFile(join(archive, "retained.txt"), "utf8")).toBe(
      "Synthetic retained data",
    );
    expect(await descriptor(output)).not.toContain(";;;WD)");
  },
);

windowsTest(
  "new Windows output creation accepts parent aliases and leaves rejected locations absent",
  async () => {
    const root = await temporaryDirectory();
    const destination = join(root, "destination");
    const alias = join(root, "alias");
    await mkdir(destination);
    await symlink(destination, alias, "junction");
    const prepared = await runtime.prepareOutputDir(
      join(alias, "scan"),
      "fixture",
    );
    expect(prepared).toBe(await realpath(join(destination, "scan")));
    const rejected = join(alias, "rejected");
    const failure = new Error("Synthetic rejected location");
    await expect(
      runtime.prepareOutputDir(rejected, "fixture", root, () => {
        throw failure;
      }),
    ).rejects.toBe(failure);
    await expect(lstat(rejected)).rejects.toMatchObject({ code: "ENOENT" });
  },
);

// Creating a separate local account requires administrator rights and belongs on
// the disposable hosted Windows runners, not a developer's workstation.
test.skipIf(
  process.platform !== "win32" || process.env["GITHUB_ACTIONS"] !== "true",
)(
  "another local user cannot read or change new and archived scan output",
  async () => {
    const root = await sharedRoot();
    const writableParent = join(root, "writable parent");
    await mkdir(writableParent);
    await icacls(writableParent, "/grant", "*S-1-1-0:(OI)(CI)M");
    const shared = join(writableParent, "shared.txt");
    await writeFile(shared, "synthetic shared data");
    const explicit = await runtime.prepareOutputDir(
      join(root, "explicit"),
      "fixture",
    );
    const generated = await runtime.prepareOutputDir(
      undefined,
      "fixture",
      root,
    );
    const campaign = join(writableParent, "campaign");
    await createMultiscanCampaign(campaign);
    for (const output of [explicit, generated, campaign]) {
      await writeFile(join(output, "probe.txt"), "synthetic private data");
    }
    const archive = await archiveWorkbenchOutput(generated, root);
    await writeFile(join(generated, "probe.txt"), "synthetic private data");
    const privateProbes = [explicit, generated, archive, campaign].map((path) =>
      join(path, "probe.txt"),
    );
    const script = await readFile(
      join(import.meta.dir, "support", "windows-other-user-access.ps1"),
      "utf8",
    );
    const result = await runPowerShell(script, {
      CODEX_SECURITY_TEST_ACCESS_PATHS: JSON.stringify([
        shared,
        ...privateProbes,
      ]),
    });
    expect(JSON.parse(result)).toEqual([
      { read: true, write: true },
      ...privateProbes.map(() => ({ read: false, write: false })),
    ]);
    for (const path of privateProbes) {
      expect(await readFile(path, "utf8")).toBe("synthetic private data");
    }
  },
  60_000,
);
