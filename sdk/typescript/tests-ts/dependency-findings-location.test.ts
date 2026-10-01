import { spawnSync } from "node:child_process";
import { mkdir, symlink } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import { DependencyFindings } from "../src/dependency-findings.js";
import { OutputInsideProtectedRootError } from "../src/errors.js";
import { createApiTestFixtures } from "./support/api-events.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test.each(["import", "assess"] as const)(
  "%s rejects state within the enclosing repository before persisting work",
  async (operation) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const target = join(repository, "app");
    await mkdir(target, { recursive: true });
    const git = spawnSync("git", ["init", repository], { encoding: "utf8" });
    expect(git.status, git.stderr).toBe(0);
    const alias = join(root, "repository-link");
    await symlink(
      repository,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    const environments: NodeJS.ProcessEnv[] = [
      { CODEX_SECURITY_STATE_DIR: join(repository, "state") },
      { CODEX_SECURITY_STATE_DIR: join(alias, "state") },
      { CODEX_HOME: join(repository, "codex-home") },
      { CODEX_SECURITY_STATE_DIR: join(root, "safe-state") },
    ];
    for (const [index, environment] of environments.entries()) {
      const workbench = mock(async () => ({
        report: { id: "report-1", targetPath: target },
        assessment: {
          id: "assessment-1",
          targetPath: target,
          state: "complete",
        },
      }));
      const runSkill = mock(async () => "Complete");
      const client = new DependencyFindings(
        { environment },
        {
          currentDirectory: () => root,
          workbench,
          runSkill,
        },
      );
      const result =
        operation === "import"
          ? client.import("report.json", { vendor: "snyk", targetPath: target })
          : client.assess("report-1", ["finding-1"]);
      if (index === environments.length - 1) {
        await result;
        expect(workbench.mock.calls.length).toBe(
          operation === "import" ? 1 : 3,
        );
        expect(runSkill.mock.calls.length).toBe(operation === "import" ? 0 : 1);
      } else {
        await expect(result).rejects.toBeInstanceOf(
          OutputInsideProtectedRootError,
        );
        expect(workbench.mock.calls.length).toBe(
          operation === "import" ? 0 : 1,
        );
        expect(runSkill).not.toHaveBeenCalled();
      }
    }
  },
);
