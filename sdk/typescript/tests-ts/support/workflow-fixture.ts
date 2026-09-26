import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FindingsDocument } from "../../src/models.js";
import { PLUGIN_ROOT } from "../plugin-root.js";

export async function workflowFixture() {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "findings-workflow-")),
  );
  const scanDir = join(root, "scan");
  const repository = join(root, "repository");
  try {
    await mkdir(repository);
    await cp(join(PLUGIN_ROOT, "examples/completed-scan"), scanDir, {
      recursive: true,
    });
    if (process.platform !== "win32") await chmod(scanDir, 0o700);
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: join(root, "codex"),
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    const document = JSON.parse(
      await readFile(join(scanDir, "findings.json"), "utf8"),
    ) as FindingsDocument;
    return {
      root,
      scanDir,
      repository,
      environment,
      document,
      async [Symbol.asyncDispose]() {
        await rm(root, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
}
