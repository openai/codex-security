import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  readlink,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { buildPatchGitControlsForNode } from "./support/node-patch-git-controls.js";
import { repositoryGit } from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

// Exercise POSIX filesystem traversal through a symlink before "..".
test
  .skipIf(process.platform === "win32")
  .each(["actual-hook", "ordinary-shadow"])(
  "preserves physical symlink traversal when the model replaces %s",
  async (mutation) => {
    const root = await fixtures.create("patch-physical-hook-");
    const support = await fixtures.create("patch-physical-hook-support-");
    const hooks = join(root, "actual", "hooks");
    const actualHook = join(hooks, "post-index-change");
    const shadow = join(root, "hooks", "post-index-change");
    const effect = join(support, "hook-effect");
    const link = join(root, "link");
    await mkdir(join(root, "actual", "child"), { recursive: true });
    await mkdir(hooks);
    await mkdir(join(root, "hooks"));
    await symlink("actual/child", link);
    const shellPath = `'${effect.replaceAll("'", "'\\''")}'`;
    const script = (value: string) =>
      `#!/bin/sh\nprintf '${value}\\n' >> ${shellPath}\n`;
    await writeFile(actualHook, script("operator"), { mode: 0o755 });
    await writeFile(shadow, "ordinary source\n");
    await writeFile(join(root, "app.txt"), "before\n");
    const git = repositoryGit(root);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    git("add", ".");
    git("commit", "-m", "Synthetic physical hook baseline");
    git("config", "core.hooksPath", "link/../hooks");
    expect(
      git("rev-parse", "--path-format=absolute", "--git-path", "hooks"),
    ).toBe(hooks);
    git("update-index", "--assume-unchanged", "app.txt");
    git("update-index", "--no-assume-unchanged", "app.txt");
    expect(await readFile(effect, "utf8")).toContain("operator");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const actualReplacement = mutation === "actual-hook";
    // Node resolves symlink/.. physically; Bun's realpath normalizes it lexically.
    const source = `
import { execFileSync } from "node:child_process";
import { readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { capturePatchGitControls } from ${JSON.stringify(await buildPatchGitControlsForNode(support))};
const root = ${JSON.stringify(root)};
const controls = await capturePatchGitControls(root, async (repository, checkout, args, options) => {
  return execFileSync("git", repository === checkout ? args : ["-C", checkout, ...args], { cwd: repository, input: options?.input, env: { ...process.env, ...(options?.indexFile === undefined ? {} : { GIT_INDEX_FILE: options.indexFile }), ...options?.environment } }).toString(options?.encoding ?? "utf8");
}, true);
if (!controls) throw new Error("Synthetic repository was not discovered.");
const beforeTurnEffects = await readFile(${JSON.stringify(effect)}, "utf8");
const edited = ${JSON.stringify(actualReplacement ? actualHook : shadow)};
await rename(edited, ${JSON.stringify(join(support, "original-input"))});
await writeFile(edited, ${JSON.stringify(actualReplacement ? script("rewritten") : "edited ordinary source\n")}, { mode: ${actualReplacement ? 0o755 : 0o644} });
await writeFile(join(root, "app.txt"), "after\\n");
const bookkeeping = [];
let error;
let files = [];
try {
  await controls.validate();
  const stage = (args) => {
    bookkeeping.push(args);
    return execFileSync("git", args, { cwd: root, env: { ...process.env, GIT_INDEX_FILE: ${JSON.stringify(join(support, "snapshot-index"))} } }).toString().trim();
  };
  stage(["read-tree", "HEAD"]);
  stage(["--literal-pathspecs", "add", "--all"]);
  const tree = stage(["write-tree"]);
  files = execFileSync("git", ["diff", "--name-only", "--no-renames", "-z", "HEAD", tree], { cwd: root }).toString().split("\\0").filter(Boolean);
} catch (failure) { error = failure.message; }
process.stdout.write(JSON.stringify({ paths: controls.readOnlyPaths, error, bookkeeping, beforeTurnEffects, files }));
`;
    const result = JSON.parse(
      execFileSync("node", ["--input-type=module", "-e", source], {
        encoding: "utf8",
      }),
    ) as {
      paths: string[];
      error?: string;
      bookkeeping: string[][];
      beforeTurnEffects: string;
      files: string[];
    };
    expect(result.paths).toContain(actualHook);
    expect(result.paths).not.toContain(shadow);
    const afterEffects = await readFile(effect, "utf8");
    if (actualReplacement) {
      expect(result.error).toContain(
        "Git configuration or hooks changed location during the patch",
      );
      expect(result.bookkeeping).toEqual([]);
      expect(afterEffects).toBe(result.beforeTurnEffects);
      expect(await readFile(actualHook, "utf8")).toBe(script("rewritten"));
      expect(await readFile(shadow, "utf8")).toBe("ordinary source\n");
    } else {
      expect(result.error).toBeUndefined();
      expect(result.files).toEqual(["app.txt", "hooks/post-index-change"]);
      expect(result.bookkeeping.length).toBeGreaterThan(0);
      expect(afterEffects.length).toBeGreaterThan(
        result.beforeTurnEffects.length,
      );
      expect(
        afterEffects
          .split("\n")
          .filter(Boolean)
          .every((line) => line === "operator"),
      ).toBe(true);
      expect(await readFile(actualHook, "utf8")).toBe(script("operator"));
      expect(await readFile(shadow, "utf8")).toBe("edited ordinary source\n");
    }
    expect(await readlink(link)).toBe("actual/child");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, "app.txt"), "utf8")).toBe("after\n");
  },
);
