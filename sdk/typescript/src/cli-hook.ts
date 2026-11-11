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
  if (!(await lstat(hook)).isFile()) throw refuse();
  const file = await open(
    hook,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await file.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size > Math.max(...templates.map((t) => Buffer.byteLength(t)))
    )
      throw refuse();
    const previous = await file.readFile("utf8");
    if (!templates.includes(previous)) throw refuse();
    if (previous !== contents) {
      // Stage the entire update beside the hook so failed writes leave a working hook in place.
      const staged = `${hook}.${randomUUID()}.tmp`;
      const replacement = await open(staged, "wx", 0o600);
      try {
        await replacement.writeFile(contents);
        if (process.platform !== "win32")
          await replacement.chmod((Number(before.mode) & 0o777) | 0o100);
        await replacement.close();
        const current = await lstat(hook, { bigint: true });
        if (
          current.dev !== before.dev ||
          current.ino !== before.ino ||
          current.ctimeNs !== before.ctimeNs ||
          current.nlink !== 1n
        )
          throw refuse();
        await rename(staged, hook);
      } finally {
        await replacement.close();
        await rm(staged, { force: true });
      }
    } else if (process.platform !== "win32") {
      try {
        await access(hook, constants.X_OK);
      } catch {
        await file.chmod((Number(before.mode) & 0o777) | 0o100);
      }
    }
    if (process.platform !== "win32") await access(hook, constants.X_OK);
  } finally {
    await file.close();
  }
}
