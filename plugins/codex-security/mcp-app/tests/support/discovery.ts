import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { importSource } from "../import-module.ts";

export const discoveryPluginRoot = path.resolve(
  process.env["CODEX_SECURITY_TEST_PLUGIN_ROOT"] ??
    path.join(
      import.meta.dirname,
      "../../../../../sdk/typescript/_bundled_plugin",
    ),
);

export function importDiscoverySource() {
  const source = path.join(
    import.meta.dirname,
    "../../src/artifact-discovery.ts",
  );
  return importSource(source, {
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(path.join(discoveryPluginRoot, "mcp/server.mjs")).href,
      ),
    },
  });
}

const execFileAsync = promisify(execFile);
const sourceRoot = path.resolve(import.meta.dirname, "../../..");

export async function createTestWorkbench(
  directory: string,
  pluginRoot = sourceRoot,
) {
  const home = path.join(directory, "home");
  await mkdir(home, { mode: 0o700 });
  return async (args: string[]) => {
    const { stdout } = await execFileAsync(
      process.env["PYTHON"]?.trim() || "python3",
      [path.join(pluginRoot, "scripts/workbench_db.py"), ...args],
      {
        env: {
          ...process.env,
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: path.join(directory, "state"),
        },
      },
    );
    return JSON.parse(stdout);
  };
}

export async function startDiffScan(directory: string, pluginRoot = sourceRoot) {
  const workbench = await createTestWorkbench(directory, pluginRoot);
  const repository = path.join(directory, "repository");
  await mkdir(repository);
  await writeFile(path.join(repository, "app.ts"), "export const value = 1;\n");
  const git = async (...args: string[]) => {
    const { stdout } = await execFileAsync("git", [
      "-C",
      repository,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      ...args,
    ]);
    return stdout.trim();
  };
  await git("init", "-q");
  await git("add", "app.ts");
  await git("commit", "-qm", "Synthetic fixture");
  const revision = await git("rev-parse", "HEAD");
  const { scan } = await workbench([
    "start-prompt-only-scan",
    "--thread-id",
    "synthetic-diff-review",
    "--target-path",
    repository,
    "--scope",
    ".",
    "--mode",
    "diff",
    "--diff-target-kind",
    "commit",
    "--diff-head-revision",
    revision,
    "--scan-root",
    path.join(directory, "scans"),
  ]);
  return { repository, revision, workbench, scan };
}

export async function discoverCandidate(
  api: Awaited<ReturnType<typeof importDiscoverySource>>,
  context: { root: string },
  filename = "app.ts",
  evidence = "Synthetic evidence",
): Promise<string> {
  const discovery = path.join(context.root, "artifacts/02_discovery");
  await mkdir(discovery, { recursive: true });
  await writeFile(path.join(discovery, "in_scope_files.txt"), filename + "\n");
  await api.recordCodexSecurityDiscoveryCandidates(
    {
      candidates: [
        {
          cwe_ids: [],
          locations: [
            { path: filename, start_line: 1, end_line: 1, role: "evidence" },
          ],
          summary: "Synthetic review candidate",
          evidence,
        },
      ],
    },
    context,
  );
  const listed = await api.listCodexSecurityCandidates({}, context);
  return listed.rows[0].candidate_id;
}

export async function rememberCheckpoints(root: string) {
  const checkpoints = path.join(root, "checkpoints");
  const originals = await Promise.all(
    (await readdir(checkpoints)).map(
      async (name) =>
        [name, await readFile(path.join(checkpoints, name))] as const,
    ),
  );
  return async () => {
    for (const [name, bytes] of originals)
      assert.deepEqual(await readFile(path.join(checkpoints, name)), bytes);
  };
}
