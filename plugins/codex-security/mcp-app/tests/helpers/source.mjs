import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { mcpBundleOptions } from "../../scripts/bundle_options.mjs";

export async function privateDirectory(prefix) {
  return realpath(await mkdtemp(join(tmpdir(), prefix)));
}

export async function privateDirectories(...directories) {
  await Promise.all(
    directories.map((directory) =>
      mkdir(directory, { recursive: true, mode: 0o700 }),
    ),
  );
}

/** Compile the source entrypoint and load it as a regular module. */
export async function loadSourceModule(url, options = {}) {
  const root = await privateDirectory("codex-security-source-");
  const output = join(root, "source.cjs");
  const entrypoint = fileURLToPath(url);
  try {
    await build({
      ...mcpBundleOptions,
      entryPoints: [entrypoint],
      define: {
        "import.meta.url": JSON.stringify(url.href),
        __dirname: JSON.stringify(dirname(entrypoint)),
      },
      ...options,
      outfile: output,
    });
    return createRequire(import.meta.url)(output);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
