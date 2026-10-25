import { gitText } from "./shell.js";
import { readJsonLines } from "./json.js";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { zipSync } from "fflate";
import type { ScanResult } from "../../src/result.js";
import type { runMultiscan } from "../../src/multiscan.js";
import { fakeResult } from "../cli-fixtures.js";
import { createApiTestFixtures } from "./temporary-directories.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "../plugin-root.js";

export type MultiscanOptions = Parameters<typeof runMultiscan>[0];
export type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

export function createMultiscanFixtures() {
  const { temporaryDirectory, cleanup } = createApiTestFixtures(
    "codex-security-multiscan-",
  );

  async function fixture() {
    const root = await temporaryDirectory();
    return {
      root,
      input: join(root, "repositories.csv"),
      output: join(root, "results"),
    };
  }

  async function repositoryFixture(name: string, id = name) {
    const paths = await fixture();
    const source = await repository(paths.root, name);
    await writeFile(
      paths.input,
      `id,repository,revision\n${id},${source.path},${source.revision}\n`,
    );
    return { paths, source };
  }

  return { temporaryDirectory, cleanup, fixture, repositoryFixture };
}

export function git(repository: string, ...args: string[]): string {
  return gitText(["-C", repository, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export async function repository(
  root: string,
  name: string,
  objectFormat = "sha1",
) {
  const path = join(root, name);
  await mkdir(join(path, "src"), { recursive: true });
  await writeFile(
    join(path, "src", "app.ts"),
    `export const name = "${name}";\n`,
  );
  git(path, "init", "-q", `--object-format=${objectFormat}`);
  git(path, "add", ".");
  git(
    path,
    "-c",
    "user.name=Multiscan Test",
    "-c",
    "user.email=multiscan@example.test",
    "commit",
    "-qm",
    "initial",
  );
  return { path, revision: git(path, "rev-parse", "HEAD") };
}

export async function completedScan(
  outputDir: string,
  completeness?: "complete" | "partial" | "unknown",
): Promise<ScanResult> {
  await mkdir(outputDir, { recursive: true, mode: 0o700 });
  await chmod(outputDir, 0o700);
  await copyCompletedScanFixture(outputDir);
  await writeFile(join(outputDir, "report.md"), "{}\n");
  if (completeness !== undefined) {
    const coveragePath = join(outputDir, "coverage.json");
    const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
    coverage.completeness = completeness;
    await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
    await reseal(outputDir);
  }
  const result = fakeResult([], completeness);
  return { manifest: result.manifest, coverage: result.coverage } as ScanResult;
}

export async function reseal(scanDir: string): Promise<void> {
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = createHash("sha256")
      .update(await readFile(join(scanDir, artifact.path)))
      .digest("hex");
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

export async function customPlugin(
  root: string,
  format: "directory" | "zip",
): Promise<string> {
  const files: Record<string, Uint8Array> = {};
  for (const name of [
    ".codex-plugin/plugin.json",
    "schemas/scan-manifest.schema.json",
    "schemas/findings.schema.json",
    "schemas/coverage.schema.json",
  ]) {
    files[name] = await readFile(join(PLUGIN_ROOT, name));
  }
  const coverage = JSON.parse(
    Buffer.from(files["schemas/coverage.schema.json"]!).toString("utf8"),
  );
  coverage.properties.schemaVersion = { enum: ["1.0", "custom-test"] };
  files["schemas/coverage.schema.json"] = Buffer.from(JSON.stringify(coverage));
  const path = join(root, format === "zip" ? "plugin.zip" : "plugin");
  if (format === "zip") {
    await writeFile(path, zipSync(files));
  } else {
    await mkdir(join(path, ".codex-plugin"), { recursive: true });
    await mkdir(join(path, "schemas"));
    for (const [name, bytes] of Object.entries(files)) {
      await writeFile(join(path, name), bytes);
    }
  }
  return path;
}

export const completeRun: SecurityClient["run"] = (
  _repository,
  scanOptions = {},
) => completedScan(scanOptions.outputDir!);

export function client<Run extends SecurityClient["run"]>(
  run: Run,
  close: SecurityClient["close"] = async () => {},
): SecurityClient & { run: Run } {
  return { run, close };
}

export function options(
  paths: { input: string; output: string },
  security: SecurityClient,
  overrides: Partial<MultiscanOptions> = {},
): MultiscanOptions {
  return {
    inputPath: paths.input,
    outputDir: paths.output,
    workers: 1,
    mode: "standard",
    maxAttempts: 2,
    config: {},
    createSecurity: () => security,
    ...overrides,
  };
}

export const results = readJsonLines<Record<string, unknown>>;
