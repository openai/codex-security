import { afterEach, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { readFile, realpath, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import packageJson from "../package.json" with { type: "json" };
import { resolveBundledCodexExecutable } from "../src/codex-sdk-environment.js";
import { inlineToml } from "../src/config.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "patch-windows-minimal-",
);
afterEach(cleanup);

test.skipIf(process.platform !== "win32")(
  "a write-enabled minimal Windows sandbox isolates sibling reads or rejects the profile before dispatch",
  async () => {
    const [home, work, temporary, sibling] = await Promise.all([
      temporaryDirectory(),
      temporaryDirectory(),
      temporaryDirectory(),
      temporaryDirectory(),
    ]);
    const node = await realpath(Bun.which("node")!);
    const git = await realpath(Bun.which("git")!);
    const codex = await realpath(resolveBundledCodexExecutable());
    const env = patchSnapshotEnvironment(temporary, {
      ...process.env,
      CODEX_HOME: home,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: join(work, "input.gitconfig"),
    });
    const options = {
      cwd: work,
      env,
      encoding: "utf8" as const,
      timeout: 60_000,
    };
    expect(execFileSync(codex, ["--version"], options).trim()).toBe(
      "codex-cli " + packageJson.dependencies["@openai/codex"],
    );
    await writeFile(
      join(work, "input.gitconfig"),
      "[fixture]\nvalue = from-project\n",
    );
    execFileSync(git, ["init", "--template=", "--quiet", "."], options);
    const canary = join(sibling, "synthetic.txt");
    await writeFile(canary, "outside-project");
    // Ensure the positive control's Windows account can read this synthetic file.
    execFileSync(
      join(process.env["SystemRoot"]!, "System32", "icacls.exe"),
      [sibling, "/grant", "*S-1-1-0:(OI)(CI)RX"],
      options,
    );
    const gitExecPath = await realpath(
      execFileSync(git, ["--exec-path"], options).trim(),
    );
    // The Git for Windows shim loads the real Git executable and its DLLs from this bin directory.
    const gitBin = join(dirname(dirname(gitExecPath)), "bin");
    const filesystem = Object.fromEntries(
      [node, git, codex, gitBin].map((p) => [p, { ".": "read" }]),
    );
    filesystem[temporary] = { ".": "write" };
    const profile = (base: string) => ({
      network: { enabled: false },
      workspace_roots: {},
      filesystem: {
        ...filesystem,
        [base]: "read",
        ":workspace_roots": "write",
      },
    });
    const backend = patchSnapshotWindowsConfig();
    await writeFile(
      join(home, "config.toml"),
      backend +
        "permissions = " +
        inlineToml({
          witness_root: profile(":root"),
          witness_minimal: profile(":minimal"),
        }) +
        "\n",
    );

    const workMarker = join(work, "write-marker");
    const tempMarker = join(temporary, "write-marker");
    const probe = `
const fs = require("node:fs");
fs.writeSync(1, "dispatched\\n");
const [git, workMarker, tempMarker, canary] = process.argv.slice(1);
require("node:child_process").execFile(git, ["config", "--file", "input.gitconfig", "--get", "fixture.value"], { encoding: "utf8" }, (error, stdout) => {
  if (error) throw error;
  fs.writeFileSync(workMarker, stdout.trim(), { flag: "wx" });
  fs.writeFileSync(tempMarker, stdout.trim(), { flag: "wx" });
  try { fs.writeSync(1, fs.readFileSync(canary, "utf8") + "\\n"); }
  catch (error) {
    if (!["EACCES", "EPERM", "ENOENT"].includes(error.code)) throw error;
    fs.writeSync(1, "sibling-denied\\n");
  }
});`;
    const args = ["-e", probe, "--", git, workMarker, tempMarker, canary];
    for (const name of ["unrestricted", "witness_root", "witness_minimal"]) {
      const result =
        name === "unrestricted"
          ? spawnSync(node, args, options)
          : spawnSync(
              codex,
              [
                "sandbox",
                "--cd",
                work,
                "--permission-profile",
                name,
                "--",
                node,
                ...args,
              ],
              options,
            );
      expect(result.error).toBeUndefined();
      expect(result.signal).toBeNull();
      if (name === "witness_minimal" && result.status !== 0) {
        expect(result.status).not.toBeNull();
        const unsupported = backend.includes('"elevated"')
          ? "elevated Windows sandbox requires effective `:root` read access"
          : "windows unelevated restricted-token sandbox cannot enforce split filesystem read restrictions directly; refusing to run unsandboxed";
        expect(result.stderr).toContain(unsupported);
        expect(result.stdout).not.toContain("dispatched");
        for (const marker of [workMarker, tempMarker])
          await expect(readFile(marker)).rejects.toMatchObject({
            code: "ENOENT",
          });
        console.info(
          "Windows write-enabled :minimal rejected before child dispatch:",
          unsupported,
        );
        return;
      }
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout.trim().split(/\r?\n/u)).toEqual([
        "dispatched",
        name === "witness_minimal" ? "sibling-denied" : "outside-project",
      ]);
      for (const marker of [workMarker, tempMarker]) {
        expect(await readFile(marker, "utf8")).toBe("from-project");
        await unlink(marker);
      }
      if (name === "witness_minimal")
        console.info(
          "Windows write-enabled :minimal dispatched, wrote both authorized markers and denied the sibling read.",
        );
    }
  },
  120_000,
);
