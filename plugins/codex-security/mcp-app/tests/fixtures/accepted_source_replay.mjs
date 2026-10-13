import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { proposal, scanId, workers } from "./accepted_source_bank.mjs";

export async function loadReducer() {
  const bundled = await build({
    bundle: true,
    entryPoints: [
      fileURLToPath(
        new URL("../../src/artifact-deep-reducer.ts", import.meta.url),
      ),
    ],
    format: "esm",
    platform: "node",
    write: false,
  });
  return import(
    "data:text/javascript;base64," +
      Buffer.from(bundled.outputFiles[0].contents).toString("base64")
  );
}

export async function prepareReplay(root, bank = workers) {
  const workerRoot = path.join(root, "artifacts", "deep_discovery", "workers");
  const records = new Map();
  for (const [i, worker] of bank.entries()) {
    const output = path.join(workerRoot, worker.id, "output");
    await mkdir(output, { recursive: true });
    const resultPath = path.join(output, "result.json");
    await writeFile(resultPath, JSON.stringify(worker.result) + "\n");
    records.set(worker.id, {
      id: worker.id,
      resultPath,
      completionSequence: i + 1,
    });
  }
  return records;
}

export async function runBatch(
  reducer,
  root,
  records,
  ids,
  index,
  previous,
  propose = proposal,
) {
  const output = path.join(
    root,
    "artifacts",
    "deep_discovery",
    "dedup",
    `dedup-${index}`,
    "output",
  );
  await mkdir(output, { recursive: true });
  const context = {
    root: output,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot: root,
      claimedWorkers: ids.map((id) => records.get(id)),
      ...(previous ? { previousReducerResultPath: previous } : {}),
    },
  };
  const inputs = await reducer.getCodexSecurityDeepReducerInputs(context);
  const submitted = propose(inputs);
  const receipt = await reducer.recordCodexSecurityDeepReduction(
    context,
    submitted,
  );
  const resultPath = path.join(output, "result.json");
  return {
    inputs,
    submitted,
    receipt,
    resultPath,
    result: JSON.parse(await readFile(resultPath, "utf8")),
  };
}

export async function replay(reducer, root, batches, propose = proposal) {
  const records = await prepareReplay(root);
  const steps = [];
  let previous;
  for (const [index, batch] of batches.entries()) {
    const step = await runBatch(
      reducer,
      root,
      records,
      batch,
      index,
      previous,
      propose,
    );
    steps.push(step);
    previous = step.resultPath;
  }
  return { steps, result: steps.at(-1).result };
}
