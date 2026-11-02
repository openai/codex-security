import {
  appendFile,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import { main } from "../src/cli.js";
import { runMultiscan } from "../src/multiscan.js";
import { loadContract } from "../src/contract.js";
import * as contracts from "../src/contract.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  type SecurityClient,
  createMultiscanFixtures,
  completedScan,
  completeRun,
  client,
  options,
  results,
} from "./support/multiscan.js";

const { repositoryFixture, cleanup } = createMultiscanFixtures();
afterEach(cleanup);

test.each(["missing", "malformed", "missing status"] as const)(
  "retains repaired completion evidence with a %s manifest",
  async (problem) => {
    const { paths } = await repositoryFixture("completion-evidence");
    const run = mock(completeRun);
    const configured = options(paths, client(run));
    const initial = await runMultiscan(configured);
    const [receipt] = await results(initial.resultsPath);
    const scanDir = receipt!["outputDir"] as string;
    const manifest = join(scanDir, "scan-manifest.json");
    if (problem === "missing") await rm(manifest);
    else
      await writeFile(manifest, problem === "malformed" ? "{" : '{"scan":{}}');
    const bytes = await readFile(manifest).catch((error) =>
      error.code === "ENOENT" ? null : Promise.reject(error),
    );
    await writeFile(
      initial.resultsPath,
      `${JSON.stringify({ ...receipt, warnings: {} })}\n`,
    );
    const recoverScan = mock(async () => {
      throw new Error("Invalid completion cannot be resumed");
    });
    expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 0,
    });
    expect(run).toHaveBeenCalledTimes(2);
    expect(recoverScan).not.toHaveBeenCalled();
    expect((await results(initial.resultsPath)).at(-1)).toMatchObject({
      attempt: 2,
      status: "completed",
    });
    expect(
      await readFile(manifest).catch((error) =>
        error.code === "ENOENT" ? null : Promise.reject(error),
      ),
    ).toEqual(bytes);
    expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 1,
    });
  },
);

test("repeated receipt repair retains known completion state", async () => {
  const { paths } = await repositoryFixture("repeat-completion-repair");
  const run = mock(completeRun);
  const configured = options(paths, client(run));
  const initial = await runMultiscan(configured);
  const [receipt] = await results(initial.resultsPath);
  const scanDir = receipt!["outputDir"] as string;
  await rm(join(scanDir, "scan-manifest.json"));
  await writeFile(
    initial.resultsPath,
    `${JSON.stringify({ ...receipt, warnings: {} })}\n`,
  );
  const controller = new AbortController();
  const interrupted = new Error("Synthetic interrupted repair");
  const renamed = filesystem.rename;
  const renaming = spyOn(filesystem, "rename").mockImplementation(
    async (...args: Parameters<typeof filesystem.rename>) => {
      await renamed(...args);
      if (String(args[0]).includes(".results.repair-"))
        controller.abort(interrupted);
    },
  );
  const recoverScan = mock(async () => {
    throw new Error("Invalid completion cannot be resumed");
  });
  try {
    await expect(
      runMultiscan({ ...configured, recoverScan, signal: controller.signal }),
    ).rejects.toBe(interrupted);
  } finally {
    renaming.mockRestore();
  }
  const [marker] = await results(initial.resultsPath);
  expect(marker).toMatchObject({ attempt: 1, recoveryRequired: "completed" });
  await writeFile(
    initial.resultsPath,
    `${JSON.stringify({ ...marker, warnings: {} })}\n`,
  );
  expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
    completed: 1,
    failed: 0,
    skipped: 0,
  });
  expect(recoverScan).not.toHaveBeenCalled();
  expect(run).toHaveBeenCalledTimes(2);
  expect((await results(initial.resultsPath)).at(-1)).toMatchObject({
    attempt: 2,
    status: "completed",
  });
});

test("saved manifest I/O failures remain local to their repository", async () => {
  const { paths, source } = await repositoryFixture("manifest-io", "first");
  await appendFile(paths.input, `second,${source.path},${source.revision}\n`);
  const run = mock<SecurityClient["run"]>(async (_repository, scan = {}) => {
    await completedScan(scan.outputDir!);
    throw new Error("Synthetic interrupted scan");
  });
  const configured = options(paths, client(run), {
    workers: 1,
    maxAttempts: 1,
  });
  const initial = await runMultiscan(configured);
  expect(initial.failed).toBe(2);
  const read = contracts.readScanFile;
  const failure = Object.assign(new Error("Synthetic manifest EACCES"), {
    code: "EACCES",
  });
  const reading = spyOn(contracts, "readScanFile").mockImplementation(
    async (...args: Parameters<typeof contracts.readScanFile>) => {
      if (args[0].includes(join("artifacts", "first"))) throw failure;
      return read(...args);
    },
  );
  const recoverScan = mock(async () => fakeResult());
  try {
    expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
      completed: 1,
      failed: 1,
      skipped: 0,
    });
    expect(recoverScan).toHaveBeenCalledTimes(1);
    expect((await results(initial.resultsPath)).slice(-2)).toMatchObject([
      { id: "first", status: "failed", error: "Synthetic manifest EACCES" },
      { id: "second", status: "completed" },
    ]);
  } finally {
    reading.mockRestore();
  }
});

test("interrupted repair persists every attempted watermark before ordinary resume", async () => {
  const { paths, source } = await repositoryFixture("repair-watermarks");
  const moved = join(paths.root, "temporarily-moved-source");
  await rename(source.path, moved);
  const run = mock(completeRun);
  const configured = options(paths, client(run), { maxAttempts: 3 });
  const initial = await runMultiscan(configured);
  await rename(moved, source.path);
  const original = await results(initial.resultsPath);
  expect(original.map((row) => row["attempt"])).toEqual([1, 2, 3]);
  expect(
    await readdir(join(paths.output, "artifacts", "repair-watermarks")),
  ).toEqual([]);
  await completedScan(
    join(paths.output, "artifacts", "repair-watermarks", "attempt-3"),
  );
  await writeFile(
    initial.resultsPath,
    original.map((row) => JSON.stringify({ ...row, warnings: {} })).join("\n") +
      "\n",
  );
  const controller = new AbortController();
  const interruption = new Error("Synthetic interrupted repair");
  const renamed = filesystem.rename;
  const renaming = spyOn(filesystem, "rename").mockImplementation(
    async (...args: Parameters<typeof filesystem.rename>) => {
      await renamed(...args);
      if (String(args[0]).includes(".results.repair-"))
        controller.abort(interruption);
    },
  );
  const recoverScan = mock(async () => fakeResult());
  try {
    await expect(
      runMultiscan({ ...configured, recoverScan, signal: controller.signal }),
    ).rejects.toBe(interruption);
  } finally {
    renaming.mockRestore();
  }
  const repaired = await readFile(initial.resultsPath);
  expect(
    (await results(initial.resultsPath)).map((row) => row["attempt"]),
  ).toEqual([1, 2, 3]);
  await expect(runMultiscan(configured)).rejects.toThrow("requires --recover");
  expect(await readFile(initial.resultsPath)).toEqual(repaired);
  expect(run).not.toHaveBeenCalled();
  expect(await runMultiscan({ ...configured, recoverScan })).toMatchObject({
    completed: 1,
    failed: 0,
    skipped: 0,
  });
  expect(recoverScan).toHaveBeenCalledTimes(1);
  expect((await results(initial.resultsPath)).at(-1)).toMatchObject({
    attempt: 3,
    status: "completed",
  });
});

test("ambiguous repaired state preserves the committed ledger with restoration guidance", async () => {
  const { paths } = await repositoryFixture("ambiguous-repair");
  const run = mock(completeRun);
  const configured = options(paths, client(run));
  const initial = await runMultiscan(configured);
  const [receipt] = await results(initial.resultsPath);
  await writeFile(
    join(receipt!["outputDir"] as string, "scan-manifest.json"),
    "{",
  );
  const damaged = Buffer.from(
    `${JSON.stringify({ ...receipt, status: "unknown", warnings: {} })}\n`,
  );
  await writeFile(initial.resultsPath, damaged);
  const recoverScan = mock(async () => undefined);
  await expect(runMultiscan({ ...configured, recoverScan })).rejects.toThrow(
    "Restore a complete backup of all committed attempts",
  );
  expect(await readFile(initial.resultsPath)).toEqual(damaged);
  expect(run).toHaveBeenCalledTimes(1);
  expect(recoverScan).not.toHaveBeenCalled();
});

test("CLI starts a new attempt for an orphaned Workbench completion with a damaged manifest", async () => {
  const { paths } = await repositoryFixture("cli-orphan");
  let saved:
    | { scanId: string; scanDir: string; progress: { status: string } }
    | undefined;
  const deps = dependencies({
    onWorkbench: async (args) =>
      args[0] === "list-scans" && saved ? { scans: [saved] } : { scans: [] },
  });
  const run = mock(completeRun);
  const configured = {
    ...deps,
    createSecurity: (config: Parameters<typeof deps.createSecurity>[0]) => ({
      ...deps.createSecurity(config),
      run,
    }),
  };
  const args = [
    "bulk-scan",
    paths.input,
    "--output-dir",
    paths.output,
    "--max-attempts",
    "1",
    "--json",
  ];
  const initial = capture();
  expect(await main(args, initial.stream, capture().stream, configured)).toBe(
    0,
  );
  const ledger = JSON.parse(initial.text()).resultsPath as string;
  const [receipt] = await results(ledger);
  const scanDir = receipt!["outputDir"] as string;
  const contract = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
  saved = {
    scanId: contract.manifest.scan.id,
    scanDir,
    progress: { status: "complete" },
  };
  await writeFile(ledger, "");
  await writeFile(join(scanDir, "scan-manifest.json"), "{");
  const recovered = capture();
  expect(
    await main(
      [...args, "--recover"],
      recovered.stream,
      capture().stream,
      configured,
    ),
  ).toBe(0);
  expect(run).toHaveBeenCalledTimes(2);
  expect((await results(ledger)).at(-1)).toMatchObject({
    attempt: 2,
    status: "completed",
  });
  expect(
    await main(
      [...args, "--recover"],
      capture().stream,
      capture().stream,
      configured,
    ),
  ).toBe(0);
  expect(run).toHaveBeenCalledTimes(2);
});
