import { execFile } from "node:child_process";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  rm,
} from "node:fs/promises";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const publicManifest = ".codex-plugin/plugin.json";
const execFileAsync = promisify(execFile);

function sourcePath(root, relativePath) {
  return join(root, ...relativePath.split("/"));
}

function validatePath(path) {
  const parts = path.split("/");
  if (
    path === "" ||
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
  const entries = await readdir(sourcePath(root, prefix), {
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
  const { externalOwnedExact, shippedExact } = contract;
  if (
    !Array.isArray(externalOwnedExact) ||
    !externalOwnedExact.every((path) => typeof path === "string") ||
    !Array.isArray(shippedExact) ||
    !shippedExact.every((path) => typeof path === "string")
  ) {
    throw new Error("Plugin projection contract contains invalid paths.");
  }
  if (!externalOwnedExact.includes(publicManifest)) {
    throw new Error(
      "Plugin projection contract must declare the public manifest as externally owned.",
    );
  }

  const files = [
    publicManifest,
    ...shippedExact.filter((path) => !path.startsWith("sdk/")),
  ];
  files.forEach(validatePath);
  if (new Set(files).size !== files.length) {
    throw new Error("Plugin projection contract contains duplicate paths.");
  }

  const copiedPaths = files.filter((path) => !path.startsWith("mcp/"));
  const sourceFiles = await Promise.all(
    copiedPaths.map(async (path) => {
      const file = sourcePath(source, path);
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

  await rm(destination, { force: true, recursive: true });
  if (files.some((path) => path.startsWith("mcp/"))) {
    const mcpApp = sourcePath(source, "mcp-app");
    await execFileAsync(
      process.execPath,
      [
        sourcePath(mcpApp, "scripts/build_mcp_app.mjs"),
        "--output",
        sourcePath(destination, "mcp"),
      ],
      { cwd: mcpApp, maxBuffer: 10 * 1024 * 1024 },
    );
  }
  for (const { file, mode, path } of sourceFiles) {
    const output = sourcePath(destination, path);
    await mkdir(dirname(output), { recursive: true });
    await copyFile(file, output);
    await chmod(output, mode);
  }

  const generated = await destinationFiles(destination);
  const expected = [...files].sort();
  if (
    generated.length !== expected.length ||
    generated.some((path, index) => path !== expected[index])
  ) {
    throw new Error("Bundled plugin generated files outside its contract.");
  }

  return files;
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  pathToFileURL(resolve(invokedPath)).href === import.meta.url
) {
  buildBundledPlugin()
    .then((files) => {
      console.log(`Generated bundled plugin with ${files.length} files.`);
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 1;
    });
}
