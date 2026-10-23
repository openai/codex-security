import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Real Git checkout and separate state, shared by normalized and vendor import tests. */
export async function localFindingsFixture(options: { remote?: string } = {}) {
  const root = await mkdtemp(
    join(await realpath(tmpdir()), "codex-security-external-local-"),
  );
  const repository = join(root, "repository");
  await mkdir(repository);
  execFileSync("git", ["init", "--quiet", repository]);
  if (options.remote !== undefined)
    execFileSync("git", [
      "-C",
      repository,
      "remote",
      "add",
      "origin",
      options.remote,
    ]);
  const stateDirectory = join(root, "state");
  return {
    root,
    repository,
    stateDirectory,
    environment: {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: stateDirectory,
      CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
    },
    dispose: () => rm(root, { recursive: true, force: true }),
  };
}
