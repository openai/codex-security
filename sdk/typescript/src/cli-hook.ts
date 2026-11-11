import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  lstat,
  mkdir,
  open,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname } from "node:path";
import {
  REPORTABLE_SEVERITIES,
  type FailureSeverity,
} from "./scan-settings.js";
import { UNSUPPORTED_GIT_ENVIRONMENT } from "./targets.js";

export async function installManagedHook(
  hook: string,
  command: string,
  threshold: FailureSeverity,
): Promise<void> {
  const header = "#!/bin/sh\nset -eu\n";
  const unset = `unset ${[...UNSUPPORTED_GIT_ENVIRONMENT].join(" ")}\n`;
  const scan = (launcher: string, level: FailureSeverity) =>
    `exec ${launcher} scan . --working-tree --fail-on-severity ${level}\n`;
  const contents = header + unset + scan(command, threshold);
  await mkdir(dirname(hook), { recursive: true });
  try {
    await writeFile(hook, contents, { flag: "wx", mode: 0o755 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }

  const refuse = () =>
    new Error(`A pre-commit hook already exists at ${hook}.`);
  const templates = REPORTABLE_SEVERITIES.flatMap((level) => [
    header + unset + scan(command, level),
    header +
      "unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE\n" +
      scan(command, level),
    header + scan(command, level),
    header + scan("npx --no-install codex-security", level),
  ]);
  const selected = await lstat(hook, { bigint: true });
  if (!selected.isFile()) throw refuse();
  const file = await open(
    hook,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const opened = await file.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== selected.dev ||
      opened.ino !== selected.ino ||
      opened.nlink !== 1n ||
      opened.size > Math.max(...templates.map((t) => Buffer.byteLength(t)))
    )
      throw refuse();
    const previous = await file.readFile("utf8");
    if (!templates.includes(previous)) throw refuse();
    if (previous === contents) {
      if (process.platform !== "win32") {
        try {
          await access(hook, constants.X_OK);
        } catch {
          await file.chmod((Number(opened.mode) & 0o777) | 0o100);
          await access(hook, constants.X_OK);
        }
      }
      return;
    }
  } finally {
    // Windows can deny replacement while the destination is open.
    await file.close();
  }

  const staged = `${hook}.${randomUUID()}.tmp`;
  const replacement = await open(staged, "wx", 0o600);
  try {
    try {
      await replacement.writeFile(contents);
      if (process.platform !== "win32")
        await replacement.chmod((Number(selected.mode) & 0o777) | 0o100);
    } finally {
      await replacement.close();
    }
    const current = await lstat(hook, { bigint: true });
    if (
      !current.isFile() ||
      current.dev !== selected.dev ||
      current.ino !== selected.ino ||
      current.ctimeNs !== selected.ctimeNs ||
      current.nlink !== selected.nlink
    )
      throw refuse();
    await rename(staged, hook);
    if (process.platform !== "win32") await access(hook, constants.X_OK);
  } finally {
    await rm(staged, { force: true });
  }
}
