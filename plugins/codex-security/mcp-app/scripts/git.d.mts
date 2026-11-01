import type { ExecFileSyncOptions } from "node:child_process";

export function gitText(
  args: readonly string[],
  options?: Omit<ExecFileSyncOptions, "encoding">,
): string;
