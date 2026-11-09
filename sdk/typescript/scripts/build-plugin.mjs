import { execFileSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
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
import { retryWindowsRename } from "../src/retry-windows-rename.js";
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

export async function bundledPluginFiles(root, prefix = "") {
  const entries = await readdir(join(root, prefix), {
    withFileTypes: true,
  });
  const files = [];
  for (const entry of entries) {
    const path = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...(await bundledPluginFiles(root, path)));
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
  const files = pluginContractFiles(contract, validatePath);

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
    if (copiedPaths.length < files.length) {
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

    if (
      !isDeepStrictEqual(await bundledPluginFiles(staged), [...files].sort())
    ) {
      throw new Error("Bundled plugin generated files outside its contract.");
    }
    await retryWindowsRename(
      async () => {
        try {
          await rename(destination, previous);
          preservePrevious = true;
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
        await rename(staged, destination);
      },
      async () => {
        // Keep the previous bundle available to readers during publication backoff.
        if (preservePrevious) {
          await retryWindowsRename(() => rename(previous, destination));
          preservePrevious = false;
        }
      },
    );
    if (preservePrevious && process.platform === "win32") {
      // A loaded addon can still prevent unlinking. Use the publication backoff
      // for the whole old tree because recursive rm retries vary by runtime.
      try {
        await retryWindowsRename(() =>
          rm(previous, { recursive: true, force: true }),
        );
      } catch (error) {
        if (!["EPERM", "EACCES", "EBUSY"].includes(error.code)) throw error;
        console.warn(
          `Published bundled plugin at ${destination}. Remove staging directory ${staging} after readers exit. ${error.message}`,
        );
        return files;
      }
    }
    preservePrevious = false;
  } finally {
    // Retain the previous bundle if rollback fails or a reader keeps it open.
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
