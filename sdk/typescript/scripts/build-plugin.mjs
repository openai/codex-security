import { execFileSync } from "node:child_process";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
} from "node:fs/promises";
import { dirname, join, posix, resolve } from "node:path";
import { isMain } from "./is-main.mjs";
import { pluginContractFiles } from "./plugin-contract.mjs";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");

function validatePath(path) {
  const parts = path.split("/");
  if (
    path.includes("\\") ||
    posix.isAbsolute(path) ||
    parts.some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error(
      `Plugin projection contract contains an unsafe path: ${path}.`,
    );
  }
}

async function destinationFiles(root, prefix = "") {
  const entries = await readdir(join(root, prefix), {
    withFileTypes: true,
  });
  const files = [];
  for (const entry of entries) {
    const path = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...(await destinationFiles(root, path)));
    } else if (entry.isFile()) {
      files.push(path);
    } else {
      throw new Error(`Bundled plugin generated an unsafe path: ${path}.`);
    }
  }
  return files.sort();
}

/** @returns {Promise<string[]>} */
export async function buildBundledPlugin({
  contractPath = join(
    repositoryRoot,
    "plugins",
    "codex-security",
    "plugin-files.json",
  ),
  destination = join(packageRoot, "_bundled_plugin"),
  source = join(repositoryRoot, "plugins", "codex-security"),
} = {}) {
  const contract = JSON.parse(await readFile(contractPath, "utf8"));
  const files = pluginContractFiles(contract);
  files.forEach(validatePath);
  if (new Set(files).size !== files.length) {
    throw new Error("Plugin projection contract contains duplicate paths.");
  }

  const copiedPaths = files.filter((path) => !path.startsWith("mcp/"));
  const sourceFiles = await Promise.all(
    copiedPaths.map(async (path) => {
      const file = join(source, path);
      let metadata;
      try {
        metadata = await lstat(file);
      } catch (error) {
        if (error?.code === "ENOENT") {
          throw new Error(`Canonical plugin source is missing ${path}.`);
        }
        throw error;
      }
      if (!metadata.isFile()) {
        throw new Error(
          `Canonical plugin source is not a regular file: ${path}.`,
        );
      }
      return { file, mode: metadata.mode & 0o777, path };
    }),
  );

  await mkdir(dirname(destination), { recursive: true });
  const staging = await mkdtemp(join(dirname(destination), ".plugin-build-"));
  const staged = join(staging, "bundle");
  const previous = join(staging, "previous");
  let preservePrevious = false;
  try {
    if (files.some((path) => path.startsWith("mcp/"))) {
      const mcpApp = join(source, "mcp-app");
      execFileSync(
        process.execPath,
        [
          join(mcpApp, "scripts/build_mcp_app.mjs"),
          "--output",
          join(staged, "mcp"),
        ],
        { cwd: mcpApp, stdio: "inherit" },
      );
    }
    for (const { file, mode, path } of sourceFiles) {
      const output = join(staged, path);
      await mkdir(dirname(output), { recursive: true });
      await copyFile(file, output);
      await chmod(output, mode);
    }

    const generated = await destinationFiles(staged);
    const expected = [...files].sort();
    if (
      generated.length !== expected.length ||
      generated.some((path, index) => path !== expected[index])
    ) {
      throw new Error("Bundled plugin generated files outside its contract.");
    }
    try {
      await rename(destination, previous);
      preservePrevious = true;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    try {
      await rename(staged, destination);
    } catch (error) {
      if (preservePrevious) {
        await rename(previous, destination);
        preservePrevious = false;
      }
      throw error;
    }
    preservePrevious = false;
  } finally {
    // Leave the previous bundle available if restoring it fails.
    if (!preservePrevious) await rm(staging, { recursive: true, force: true });
  }

  return files;
}

if (isMain(import.meta.url)) {
  buildBundledPlugin()
    .then((files) => {
      console.log(`Generated bundled plugin with ${files.length} files.`);
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 1;
    });
}
