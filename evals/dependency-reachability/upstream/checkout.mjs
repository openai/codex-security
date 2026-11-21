import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { basename, dirname } from "node:path";

export function checkoutOf(file, dirtyScope = "worktree") {
  if (!file) return null;
  try {
    const entry = realpathSync(file);
    const git = (...args) =>
      execFileSync(
        "git",
        ["--no-optional-locks", "--literal-pathspecs", ...args],
        {
          cwd: dirname(entry),
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
        },
      );
    // An installed CLI under node_modules can sit inside an unrelated checkout.
    git("ls-files", "--error-unmatch", "--", basename(entry));
    const commit = git("rev-parse", "--verify", "HEAD").trim();
    const scope = dirtyScope === "directory" ? ["--", "."] : [];
    const status = git(
      "status",
      "--porcelain",
      "--untracked-files=no",
      ...scope,
    );
    return { commit, trackedDirty: status.length > 0, dirtyScope };
  } catch {
    return null;
  }
}
