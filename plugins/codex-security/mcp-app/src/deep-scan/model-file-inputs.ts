import { createHash } from "node:crypto";
import { constants, open } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { z } from "zod";

const modelFileSettings = ["model_instructions_file"] as const;

const fileInput = z
  .object({
    // Preview SDK recipes only recorded the digest.
    path: z.string().min(1).optional(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .nullable();
export const modelFileInputsSchema = z.partialRecord(
  z.enum(modelFileSettings),
  fileInput,
);
export type ModelFileInputs = z.output<typeof modelFileInputsSchema>;

export function modelFilePath(value: string, directory: string): string {
  const expanded = value.replace(/^~(?=[/\\]|$)/u, () => homedir());
  // POSIX resolves a symlink followed by .. through the symlink's destination.
  return process.platform !== "win32" && isAbsolute(expanded)
    ? expanded
    : resolve(directory, expanded);
}

export async function readModelFileInputs(
  config: Record<string, unknown>,
  settings: readonly (typeof modelFileSettings)[number][] = modelFileSettings,
  signal?: AbortSignal,
): Promise<ModelFileInputs> {
  const inputs: ModelFileInputs = {};
  for (const setting of settings) {
    signal?.throwIfAborted();
    const value = config[setting];
    if (typeof value !== "string" || value.length === 0) {
      inputs[setting] = null;
      continue;
    }
    const file = await open(value, constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      if (!(await file.stat()).isFile())
        throw new Error(`Expected a regular file for ${setting}: ${value}`);
      inputs[setting] = {
        path: value,
        sha256: createHash("sha256")
          .update(await file.readFile({ signal }))
          .digest("hex"),
      };
    } finally {
      await file.close();
    }
  }
  return inputs;
}

export class DeepScanModelInputRecoveryError extends Error {}

export async function validateModelFileInputs(
  saved: ModelFileInputs,
  config: Record<string, unknown>,
  signal: AbortSignal,
): Promise<void> {
  for (const setting of modelFileSettings) {
    const expected = saved[setting];
    if (expected === undefined) continue;
    let actual;
    try {
      actual = (await readModelFileInputs(config, [setting], signal))[setting];
    } catch (cause) {
      signal.throwIfAborted();
      throw new DeepScanModelInputRecoveryError(
        `Could not read the saved Deep Scan's ${setting}: ${cause instanceof Error ? cause.message : String(cause)}. Restore the original input and resume this scan.`,
        { cause },
      );
    }
    if (
      (expected?.path !== undefined && actual?.path !== expected.path) ||
      actual?.sha256 !== expected?.sha256
    )
      throw new DeepScanModelInputRecoveryError(
        `The saved Deep Scan's ${setting} changed. Restore the original input and resume this scan, or start a new scan.`,
      );
  }
}
