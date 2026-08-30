import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { releaseVersion } from "./release-automation.mjs";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const componentManifests = [
  "plugins/codex-security/.codex-plugin/plugin.json",
  "plugins/codex-security/mcp-app/package.json",
  "plugins/codex-security/pyproject.toml",
];

export async function syncVersions({
  root = repositoryRoot,
  check = false,
} = {}) {
  const version = releaseVersion(
    JSON.parse(
      await readFile(join(root, "sdk/typescript/package.json"), "utf8"),
    ),
  );
  const updates = await Promise.all(
    componentManifests.map(async (path) => {
      const contents = await readFile(join(root, path), "utf8");
      const field = path.endsWith(".json")
        ? /^([ \t]*"version"[ \t]*:[ \t]*")[^"]+("[ \t]*,?)/mu
        : /^(version[ \t]*=[ \t]*")[^"]+(")/mu;
      if (!field.test(contents)) {
        throw new Error(`${path} must declare its component version.`);
      }
      return {
        path,
        contents,
        updated: contents.replace(
          field,
          (_match, prefix, suffix) => `${prefix}${version}${suffix}`,
        ),
      };
    }),
  );
  const changed = updates.filter(
    ({ contents, updated }) => contents !== updated,
  );
  if (check && changed.length > 0) {
    throw new Error(
      `Component versions must match ${version}:\n${changed.map(({ path }) => path).join("\n")}\nRun pnpm --dir sdk/typescript run sync:versions.`,
    );
  }
  if (!check) {
    for (const { path, updated } of changed) {
      await writeFile(join(root, path), updated);
    }
  }
  return { version, changed: changed.map(({ path }) => path) };
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  pathToFileURL(resolve(invokedPath)).href === import.meta.url
) {
  try {
    const args = process.argv.slice(2);
    if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
      throw new Error("Usage: node scripts/sync-versions.mjs [--check]");
    }
    const check = args[0] === "--check";
    const { version, changed } = await syncVersions({ check });
    console.log(
      check
        ? `Verified component versions match ${version}.`
        : `Synchronized ${changed.length} component manifests to ${version}.`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
