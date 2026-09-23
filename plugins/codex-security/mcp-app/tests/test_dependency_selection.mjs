import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const compiled = await build({
  bundle: true,
  entryPoints: [
    fileURLToPath(
      new URL("../src/server/dependency-selection.ts", import.meta.url),
    ),
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { requireSelectedDependencyBatch, selectableDependencySchema } =
  await import(
    "data:text/javascript;base64," +
      Buffer.from(compiled.outputFiles[0].contents).toString("base64")
  );
const root = await mkdtemp(join(tmpdir(), "dependency-selection-"));
const selected = {
  ecosystem: "npm",
  registry: "https://registry.npmjs.org",
  package: "example",
  oldVersion: null,
  newVersion: "1.2.3",
};
const another = { ...selected, package: "unselected" };
for (const newVersion of ["1.2.3-01", "1.2.3-alpha.01"]) {
  assert.equal(
    selectableDependencySchema.safeParse({ ...selected, newVersion }).success,
    false,
  );
}
for (const newVersion of ["1.2.3-alpha.1", "1.2.3-0+build.01"]) {
  assert.equal(
    selectableDependencySchema.safeParse({ ...selected, newVersion }).success,
    true,
  );
}

try {
  const directory = join(
    root,
    "artifacts",
    "02_discovery",
    "dependency-update-scan",
  );
  await mkdir(directory, { recursive: true });
  const discovery = join(directory, "dependency-discovery.json");
  await writeFile(
    discovery,
    JSON.stringify({ dependencies: [selected, another] }),
  );
  await requireSelectedDependencyBatch([selected], [selected], root);
  await assert.rejects(
    requireSelectedDependencyBatch([selected, another], [selected], root),
    /exactly match/,
  );
  await assert.rejects(
    requireSelectedDependencyBatch([], [selected], root),
    /exactly match/,
  );
  await assert.rejects(
    requireSelectedDependencyBatch([selected, selected], [selected], root),
    /exactly match/,
  );
  await assert.rejects(
    requireSelectedDependencyBatch([selected], [selected], undefined),
    /resolved inventory/,
  );
  await writeFile(discovery, JSON.stringify({ dependencies: [another] }));
  await assert.rejects(
    requireSelectedDependencyBatch([selected], [selected], root),
    /current resolved inventory/,
  );
  console.log(
    "Selected dependency submission preserves exact scope and current inventory.",
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
