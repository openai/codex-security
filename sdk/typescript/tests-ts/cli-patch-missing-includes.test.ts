import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { buildPatchGitControlsForNode } from "./support/node-patch-git-controls.js";
import { repositoryGit } from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const blocker of ["missing", "ordinary file"] as const) {
  test.skipIf(process.platform === "win32").each([false, true])(
    `preserves unresolved include traversal through ${blocker} (activated: %p)`,
    async (activate) => {
      const root = await fixtures.create("patch-unresolved-include-");
      const support = await fixtures.create(
        "patch-unresolved-include-support-",
      );
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      const source = join(root, "app.ts");
      const unavailable = join(root, "unavailable");
      await writeFile(source, "[synthetic]\n value = before\n");
      if (blocker === "ordinary file")
        await writeFile(unavailable, "ordinary source\n");
      git("add", ".");
      git("commit", "-m", "Synthetic unresolved include baseline");
      git("config", "include.path", "../unavailable/../app.ts");
      expect(git("config", "--includes", "--list")).not.toContain(
        "synthetic.value",
      );
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const config = await readFile(join(root, ".git", "config"));
      // Exercise the supported Node CLI runtime with native Git path lookups.
      const program = `
import { execFileSync } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { capturePatchGitControls } from ${JSON.stringify(await buildPatchGitControlsForNode(support))};
const root = ${JSON.stringify(root)};
const controls = await capturePatchGitControls(root, async (repository, checkout, args, options) => execFileSync("git", repository === checkout ? args : ["-C", checkout, ...args], {cwd: repository, input: options?.input, env: {...process.env, ...(options?.indexFile === undefined ? {} : {GIT_INDEX_FILE: options.indexFile}), ...options?.environment}}).toString(options?.encoding ?? "utf8"), true);
if (!controls) throw new Error("Synthetic repository was not discovered.");
if (${activate}) {
  if (${blocker === "ordinary file"}) await rm(${JSON.stringify(unavailable)});
  await mkdir(${JSON.stringify(unavailable)});
}
await writeFile(${JSON.stringify(source)}, "[synthetic]\\n value = after\\n");
const bookkeeping = [];
let error;
let files = [];
try {
  await controls.validate();
  const stage = (args) => {
    bookkeeping.push(args);
    return execFileSync("git", args, {cwd: root, env: {...process.env, GIT_INDEX_FILE: ${JSON.stringify(join(support, "snapshot-index"))}}}).toString().trim();
  };
  stage(["read-tree", "HEAD"]);
  stage(["--literal-pathspecs", "add", "--all"]);
  const tree = stage(["write-tree"]);
  files = execFileSync("git", ["diff", "--name-only", "--no-renames", "-z", "HEAD", tree], {cwd: root}).toString().split("\\0").filter(Boolean);
} catch (failure) { error = failure.message; }
process.stdout.write(JSON.stringify({paths: controls.readOnlyPaths, error, bookkeeping, files}));
`;
      const result = JSON.parse(
        execFileSync("node", ["--input-type=module", "-e", program], {
          encoding: "utf8",
        }),
      ) as {
        paths: string[];
        error?: string;
        bookkeeping: string[][];
        files: string[];
      };
      expect(result.paths).not.toContain(source);
      if (activate) {
        expect(result.error).toContain(
          "Git configuration or hooks changed location during the patch",
        );
        expect(result.bookkeeping).toEqual([]);
      } else {
        expect(result.error).toBeUndefined();
        expect(result.bookkeeping.length).toBeGreaterThan(0);
        expect(result.files).toEqual(["app.ts"]);
        if (blocker === "ordinary file")
          expect(await readFile(unavailable, "utf8")).toBe("ordinary source\n");
      }
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(root, ".git", "config"))).toEqual(config);
      expect(await readFile(source, "utf8")).toBe(
        "[synthetic]\n value = after\n",
      );
    },
  );
}
