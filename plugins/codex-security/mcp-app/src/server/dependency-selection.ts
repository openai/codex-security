import { readFile } from "node:fs/promises";
import { join } from "node:path";
import * as z from "zod/v4";
import type { DependencyScanDependency } from "../dependency-scans.js";

export const selectableDependencySchema = z
  .object({
    ecosystem: z.literal("npm"),
    registry: z.literal("https://registry.npmjs.org"),
    package: z
      .string()
      .regex(/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/),
    oldVersion: z.null(),
    newVersion: z
      .string()
      .regex(
        /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/,
      ),
  })
  .strict();

export const selectedDependenciesSchema = z
  .array(selectableDependencySchema)
  .min(1)
  .max(20)
  .refine(
    (entries) => new Set(entries.map(dependencyKey)).size === entries.length,
    "Select each package version only once.",
  );

function dependencyKey(dependency: DependencyScanDependency): string {
  return JSON.stringify([
    dependency.ecosystem,
    dependency.registry,
    dependency.package,
    dependency.oldVersion,
    dependency.newVersion,
  ]);
}

export async function requireSelectedDependencyBatch(
  dependencies: DependencyScanDependency[],
  selection: unknown,
  scanDir: string | undefined,
): Promise<void> {
  const selected = selectedDependenciesSchema.parse(selection);
  const expected = new Set(selected.map(dependencyKey));
  if (
    dependencies.length !== expected.size ||
    new Set(dependencies.map(dependencyKey)).size !== expected.size ||
    dependencies.some((dependency) => !expected.has(dependencyKey(dependency)))
  ) {
    throw new Error(
      "The submitted packages must exactly match the selected dependency versions.",
    );
  }
  if (!scanDir) {
    throw new Error(
      "Selected dependency scanning requires the current scan's resolved inventory.",
    );
  }
  const discovery: unknown = JSON.parse(
    await readFile(
      join(
        scanDir,
        "artifacts",
        "02_discovery",
        "dependency-update-scan",
        "dependency-discovery.json",
      ),
      "utf8",
    ),
  );
  const inventory = z
    .object({
      dependencies: z.array(
        z.object({
          ecosystem: z.string(),
          registry: z.string(),
          package: z.string(),
          oldVersion: z.string().nullable(),
          newVersion: z.string(),
        }),
      ),
    })
    .parse(discovery);
  const resolved = new Set(inventory.dependencies.map(dependencyKey));
  if (selected.some((dependency) => !resolved.has(dependencyKey(dependency)))) {
    throw new Error(
      "A selected version is missing from the current resolved inventory. Calculate dependencies again.",
    );
  }
}
