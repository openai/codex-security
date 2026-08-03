import {
  execFileSync,
  spawnSync,
  type SpawnSyncReturns,
} from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, test } from "bun:test";

// The `tar` shims below are POSIX shell scripts, so the listing behavior of
// other platforms is reproduced here rather than exercised natively.
const testPosix = process.platform === "win32" ? test.skip : test;

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const checkPackageScript = fileURLToPath(
  new URL("../scripts/check-package.mjs", import.meta.url),
);
const pluginContract = fileURLToPath(
  new URL("../plugin-files.json", import.meta.url),
);
const temporaryDirectories: string[] = [];

afterAll(async () => {
  for (const directory of temporaryDirectories) {
    await rm(directory, { recursive: true, force: true });
  }
});

async function temporaryDirectory(prefix: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

let packedTarball: Promise<string> | undefined;

function packTarball(): Promise<string> {
  packedTarball ??= (async () => {
    const destination = await temporaryDirectory("codex-security-pack-");
    const pack = spawnSync(
      "pnpm",
      ["pack", "--pack-destination", destination],
      { cwd: packageRoot, encoding: "utf8" },
    );
    if (pack.status !== 0) throw new Error(`pnpm pack failed: ${pack.stderr}`);
    const tarball = (await readdir(destination)).find((name) =>
      name.endsWith(".tgz"),
    );
    if (tarball === undefined) {
      throw new Error("pnpm pack did not produce a tarball.");
    }
    return join(destination, tarball);
  })();
  return packedTarball;
}

// Rewrites only the verbose listing that the entry-type check reads. Every
// other invocation reaches the real `tar`, so the archive stays valid and the
// files extracted from it are untouched.
async function tarShimPath(filter: string): Promise<string> {
  const directory = await temporaryDirectory("codex-security-tar-shim-");
  const realTar = execFileSync("which", ["tar"], { encoding: "utf8" }).trim();
  await writeFile(
    join(directory, "tar"),
    [
      "#!/bin/sh",
      'for arg in "$@"; do',
      '  if [ "$arg" = "-tvzf" ]; then',
      `    "${realTar}" "$@" | ${filter}`,
      "    exit $?",
      "  fi",
      "done",
      `exec "${realTar}" "$@"`,
      "",
    ].join("\n"),
    { mode: 0o700 },
  );
  return directory;
}

async function checkPackage(
  archive: string,
  shimDirectory?: string,
): Promise<SpawnSyncReturns<string>> {
  const path = process.env["PATH"] ?? "";
  return spawnSync(
    process.execPath,
    [checkPackageScript, archive, pluginContract],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH:
          shimDirectory === undefined
            ? path
            : `${shimDirectory}${delimiter}${path}`,
      },
      timeout: 30_000,
    },
  );
}

describe("npm tarball package check", () => {
  testPosix(
    "accepts a valid tarball listed with CRLF line endings",
    async () => {
      const tarball = await packTarball();

      const native = await checkPackage(tarball);
      expect(native.stderr).toBe("");
      expect(native.status).toBe(0);

      // Windows `tar` terminates listing lines with CRLF. A multiline regular
      // expression treats the CR as a line terminator of its own, so the
      // trailing LF used to be inspected as an entry in its own right.
      const crlf = await checkPackage(
        tarball,
        await tarShimPath(`awk '{printf "%s\\r\\n", $0}'`),
      );
      expect(crlf.stderr).toBe("");
      expect(crlf.status).toBe(0);
    },
  );

  testPosix("still rejects a tarball holding a non-regular entry", async () => {
    const rejected = await checkPackage(
      await packTarball(),
      await tarShimPath("sed 's#^-#l#'"),
    );
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain(
      "npm tarball contains a non-regular entry",
    );
  });
});
