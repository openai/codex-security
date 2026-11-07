import { lstat, realpath } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

function missing(error: unknown): boolean {
  return ["ENOENT", "ENOTDIR"].includes(
    (error as NodeJS.ErrnoException).code ?? "",
  );
}

/** Include the parent that supplied the source and any enclosing checkout, including worktrees. */
export async function workerExecutableRoots(
  target: string | undefined,
  sources: readonly string[],
): Promise<string[]> {
  const roots = new Set<string>();
  const add = async (directory: string) => {
    roots.add(directory);
    for (let parent = directory; ; parent = dirname(parent)) {
      try {
        await lstat(resolve(parent, ".git"));
        roots.add(parent);
      } catch (error) {
        if (!missing(error)) throw error;
      }
      if (parent === dirname(parent)) break;
    }
  };
  for (const path of [...(target ? [target] : []), ...sources]) {
    if (!isAbsolute(path))
      throw new Error(
        "Deep Scan executable protection requires absolute source paths.",
      );
    const directory = path === target ? path : dirname(path);
    await add(resolve(directory));
    const physicalDirectory = await realpath(directory).catch(
      (error: unknown) => {
        if (!missing(error)) throw error;
      },
    );
    if (physicalDirectory && physicalDirectory !== resolve(directory))
      await add(physicalDirectory);
    const physical = await realpath(path).catch((error: unknown) => {
      if (!missing(error)) throw error;
    });
    if (physical && physical !== path)
      await add(path === target ? physical : dirname(physical));
  }
  return [...roots];
}

export function outsideExecutableRoots(
  path: string,
  roots: readonly string[],
): boolean {
  if (roots.length === 0) return true;
  const outside = (value: string) =>
    roots.every((root) => {
      const part = relative(root, value);
      return part === ".." || part.startsWith(".." + sep) || isAbsolute(part);
    });
  if (!outside(resolve(path))) return false;
  try {
    return outside(realpathSync.native(path));
  } catch (error) {
    if (missing(error)) return true;
    throw error;
  }
}
