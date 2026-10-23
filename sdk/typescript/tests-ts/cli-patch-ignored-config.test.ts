import { afterEach, expect, test } from "bun:test";
import { execFileSync, spawn } from "node:child_process";
import { cp, lstat, readFile, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import type { runWorkflow } from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

async function runBounded(script: string, cwd: string) {
  const child = spawn(process.execPath, ["test", script], {
    cwd,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let timedOut = false;
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  const timer = setTimeout(() => {
    timedOut = true;
    process.kill(-child.pid!, "SIGKILL");
  }, 10_000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    return { code, stdout, stderr, timedOut };
  } finally {
    clearTimeout(timer);
  }
}

for (const layout of [
  "linked-private",
  "selected-common",
  "nested-linked-private",
] as const) {
  test.skipIf(process.platform === "win32")(
    `patch preserves an ignored configuration FIFO in ${layout} Git layout`,
    async () => {
      const root = await fixtures.create("patch-ignored-config-");
      const support = await fixtures.create("patch-ignored-config-probe-");
      const globalConfig = join(support, "global-config");
      await writeFile(globalConfig, "");
      const environment: NodeJS.ProcessEnv = {
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: globalConfig,
        LC_ALL: "C",
      };
      const git = (cwd: string, args: string[]) =>
        execFileSync("git", args, {
          cwd,
          env: { ...process.env, ...environment },
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          timeout: 3000,
        }).trim();
      git(root, ["init", "--initial-branch=main"]);
      git(root, ["config", "user.name", "Synthetic User"]);
      git(root, ["config", "user.email", "synthetic@example.test"]);
      await writeFile(join(root, "app.ts"), "before\n");
      git(root, ["add", "app.ts"]);
      git(root, ["commit", "-m", "Synthetic configuration baseline"]);
      let selected = root;
      let observed = root;
      if (layout === "linked-private") {
        selected = await fixtures.create("patch-ignored-linked-");
        git(root, ["worktree", "add", "-b", "synthetic-linked", selected]);
        observed = selected;
      } else if (layout === "nested-linked-private") {
        observed = join(root, "nested");
        git(root, ["worktree", "add", "-b", "synthetic-linked", observed]);
        git(root, ["add", "nested"]);
        git(root, ["commit", "-m", "Synthetic linked worktree input"]);
      } else {
        const common = join(support, "common");
        await cp(join(root, ".git"), common, { recursive: true });
        environment["GIT_COMMON_DIR"] = common;
      }
      const administration = git(observed, ["rev-parse", "--absolute-git-dir"]);
      const fifo = join(administration, "config");
      if (layout === "selected-common") await unlink(fifo);
      execFileSync("mkfifo", [fifo]);
      expect(git(selected, ["status", "--porcelain"])).toBe("");
      expect(git(observed, ["status", "--porcelain"])).toBe("");
      const head = git(observed, ["rev-parse", "HEAD"]);
      const index = await readFile(join(administration, "index"));
      const rootHead = git(root, ["rev-parse", "HEAD"]);
      const rootIndex = await readFile(join(root, ".git", "index"));
      if (layout === "selected-common") {
        expect(git(selected, ["rev-parse", "--git-common-dir"])).toBe(
          environment["GIT_COMMON_DIR"]!,
        );
      }
      const script = join(support, "probe.test.ts");
      await writeFile(
        script,
        `
import { test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runWorkflow, runGitRepositoryCommand } from ${JSON.stringify(new URL("./cli-patch-fixtures.ts", import.meta.url).href)};
test("bounded ignored configuration probe", async () => {
  const environment = ${JSON.stringify(environment)};
  let launches = 0;
  let controls = [];
  process.stdout.write("PROBE_READY\\n");
  const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
    currentDirectory: ${JSON.stringify(selected)}, environment,
    onRepositoryCommand: (command, args, cwd, options) => runGitRepositoryCommand(command, args, cwd, {
      ...options, environment: { ...environment, ...options?.environment }
    }),
    onCodex: async (_args, output) => {
      launches++;
      controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
      await writeFile(join(${JSON.stringify(selected)}, "app.ts"), "after\\n");
      output?.stdout.write("Synthetic patch complete.\\n");
      return 0;
    }
  });
  process.stdout.write(JSON.stringify({ ...outcome, launches, controls }));
});
`,
      );
      const result = await runBounded(script, selected);
      expect(result.timedOut, result.stderr).toBe(false);
      expect(result.code, result.stderr).toBe(0);
      const marker = "PROBE_READY\n";
      const offset = result.stdout.indexOf(marker);
      expect(offset, result.stderr).toBeGreaterThanOrEqual(0);
      const outcome: Awaited<ReturnType<typeof runWorkflow>> & {
        launches: number;
        controls: string[];
      } = JSON.parse(result.stdout.slice(offset + marker.length));
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(outcome.launches).toBe(1);
      expect(outcome.controls).toContain(administration);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(await readFile(join(selected, "app.ts"), "utf8")).toBe("after\n");
      expect(git(observed, ["rev-parse", "HEAD"])).toBe(head);
      expect(await readFile(join(administration, "index"))).toEqual(index);
      expect(git(root, ["rev-parse", "HEAD"])).toBe(rootHead);
      expect(await readFile(join(root, ".git", "index"))).toEqual(rootIndex);
      if (layout === "nested-linked-private")
        expect(await readFile(join(observed, "app.ts"), "utf8")).toBe(
          "before\n",
        );
      expect((await lstat(fifo)).isFIFO()).toBe(true);
    },
    15_000,
  );
}
