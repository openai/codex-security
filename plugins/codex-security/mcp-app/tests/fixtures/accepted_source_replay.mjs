import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importSource } from "../import-module.ts";
import { scanId, workers } from "./accepted_source_bank.mjs";

const { mergeBatch } = await importSource(
  fileURLToPath(new URL("../../src/deep-scan/iteration.ts", import.meta.url)),
);

async function compare(prompt, schema) {
  const rows = JSON.parse(prompt.split("\n").at(-1));
  if (schema.properties.reviews) return JSON.stringify({ reviews: [] });
  const groups = new Map();
  for (const { id, fix, locations } of rows) {
    const group = groups.get(fix) ?? {
      operation: fix,
      failure: fix,
      path: locations[0][0],
      reports: [],
    };
    group.reports.push({ id, evidence: 0 });
    groups.set(fix, group);
  }
  return JSON.stringify({ defects: [...groups.values()], uncertain: [] });
}

export async function replay(root, batches) {
  const records = new Map();
  for (const worker of workers) {
    const artifactDir = path.join(
      root,
      "artifacts",
      "deep_discovery",
      "workers",
      worker.id,
      "output",
    );
    await mkdir(artifactDir, { recursive: true });
    const resultPath = path.join(artifactDir, "result.json");
    await writeFile(resultPath, JSON.stringify(worker.result));
    records.set(worker.id, { id: worker.id, artifactDir, resultPath });
  }
  let result = { scanId, findings: [] };
  for (const [index, ids] of batches.entries()) {
    const inputs = await Promise.all(
      ids.map(async (id) => {
        const worker = records.get(id);
        return {
          ...worker,
          result: JSON.parse(await readFile(worker.resultPath, "utf8")),
        };
      }),
    );
    await mergeBatch(result, inputs, root, compare, (error) => {
      throw error;
    });
    const checkpoint = path.join(root, `iteration-${index}.json`);
    await writeFile(checkpoint, JSON.stringify(result));
    result = JSON.parse(await readFile(checkpoint, "utf8"));
  }
  return result;
}
