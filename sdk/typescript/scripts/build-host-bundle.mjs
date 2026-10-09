// Development bundle: the exact locally built CLI, plugin, Linux dependencies,
// and Node executable. Nothing is published or installed in the scan checkout.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const packageRoot = resolve(import.meta.dirname, "..");
const output = process.argv[2];
if (!output)
  throw new Error(
    "Usage: node scripts/build-host-bundle.mjs /absolute/output.tar.gz",
  );
if (
  process.platform !== "linux" ||
  process.arch !== "x64" ||
  !process.report.getReport().header.glibcVersionRuntime
)
  throw new Error("Build the hosted bundle on Linux x64 with glibc.");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const run = (command, args, cwd = packageRoot) =>
  execFileSync(command, args, { cwd, stdio: "inherit" });
const staging = await mkdtemp(join(tmpdir(), "codex-security-host-bundle-"));
try {
  run("pnpm", ["pack", "--pack-destination", staging]);
  const archive = (await readdir(staging)).find((name) =>
    name.endsWith(".tgz"),
  );
  if (!archive) throw new Error("Package build did not create an archive.");
  const bundle = join(staging, "bundle");
  await mkdir(join(bundle, "bin"), { recursive: true });
  await mkdir(join(bundle, "cli"));
  run("tar", [
    "-xzf",
    join(staging, archive),
    "--strip-components=1",
    "-C",
    join(bundle, "cli"),
  ]);
  for (const name of ["pnpm-lock.yaml", "pnpm-workspace.yaml"])
    await cp(join(packageRoot, name), join(bundle, "cli", name));
  run(
    "pnpm",
    [
      "install",
      "--prod",
      "--frozen-lockfile",
      "--ignore-scripts",
      "--store-dir",
      process.env["PNPM_STORE_DIR"] ??
        join(tmpdir(), "codex-security-pnpm-store"),
    ],
    join(bundle, "cli"),
  );
  await cp(process.execPath, join(bundle, "bin", "node"));
  const pluginRoot = join(bundle, "cli", "_bundled_plugin");
  async function files(root, prefix = "") {
    const result = [];
    for (const entry of await readdir(join(root, prefix), {
      withFileTypes: true,
    })) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) result.push(...(await files(root, path)));
      else if (entry.isFile()) result.push(path);
      else
        throw new Error(`Plugin payload contains a non-regular file: ${path}`);
    }
    return result.sort();
  }
  const pluginHash = createHash("sha256");
  for (const path of await files(pluginRoot))
    pluginHash.update(
      `${path}\0${sha(await readFile(join(pluginRoot, path)))}\n`,
    );
  const pluginSha256 = pluginHash.digest("hex");
  const packageSha256 = sha(await readFile(join(staging, archive)));
  const nodeSha256 = sha(await readFile(process.execPath));
  const pkg = JSON.parse(
    await readFile(join(bundle, "cli", "package.json"), "utf8"),
  );
  const plugin = JSON.parse(
    await readFile(join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"),
  );
  const identity = {
    version: 1,
    hostProtocolVersion: 2,
    buildId: sha(`${packageSha256}\0${nodeSha256}\0${pluginSha256}`),
    sourceRevision: execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: packageRoot,
      encoding: "utf8",
    }).trim(),
    cliVersion: pkg.version,
    pluginVersion: plugin.version,
    nodeVersion: process.version.slice(1),
    platform: "linux-x64",
    pluginSha256,
  };
  await writeFile(
    join(bundle, "runtime.json"),
    `${JSON.stringify(identity, null, 2)}\n`,
  );
  await mkdir(dirname(resolve(output)), { recursive: true });
  run("tar", [
    "--hard-dereference",
    "-czf",
    resolve(output),
    "-C",
    bundle,
    "bin",
    "cli",
    "runtime.json",
  ]);
  const digest = sha(await readFile(resolve(output)));
  await writeFile(
    `${resolve(output)}.sha256`,
    `${digest}  ${resolve(output)}\n`,
  );
  await writeFile(
    `${resolve(output)}.json`,
    `${JSON.stringify(identity, null, 2)}\n`,
  );
  console.log(
    JSON.stringify({ bundle: resolve(output), sha256: digest, ...identity }),
  );
} finally {
  await rm(staging, { recursive: true, force: true });
}
