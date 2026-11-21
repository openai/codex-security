import { mkdir, readFile, writeFile } from "node:fs/promises";
import { replaceArtifactText } from "./artifact-io.js";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { readSelectedProjectConfig } from "./deep-scan/project-config.js";
import {
  validationProviderFromConfiguration,
  assessPluginFindings,
  type ValidationProviderConfiguration,
} from "#validation-runtime";
import type { JsonObject } from "./types.js";
import { protectedHostPathResolver } from "./helpers/inventory-git.js";

/** Text accompanies structured content so every MCP client exposes the result. */
export function validationCompletionText(
  validation: JsonObject | undefined,
): string {
  if (!validation) return "";
  return `\n\nSupplemental validation (${validation.provider ?? "provider"}): ${validation.status}\n${validation.summary ?? validation.report ?? validation.message ?? ""}${validation.reportPath ? `\nReport: ${validation.reportPath}` : ""}${validation.recordsPath ? `\nRecords: ${validation.recordsPath}` : ""}`;
}

function configurationPath(scanId: string): string {
  return join(
    process.env.CODEX_SECURITY_STATE_DIR?.trim() ||
      join(homedir(), ".codex-security"),
    "validation-providers",
    `${scanId}.json`,
  );
}

/** Bind explicitly selected host configuration, never repository-discovered settings. */
export async function bindValidationProvider(
  scanId: string,
  repositoryPath: string,
  projectConfigPath: string | undefined,
  created: boolean,
): Promise<void> {
  if (!created || projectConfigPath === undefined) return;
  const project = await readSelectedProjectConfig(
    projectConfigPath,
    repositoryPath,
  );
  const configuration = project.input.scan?.validation;
  await bindValidationProviderConfiguration(scanId, configuration, created);
}

/** Bind the host-owned setup snapshot without rereading a changed project file. */
export async function bindValidationProviderConfiguration(
  scanId: string,
  configuration: ValidationProviderConfiguration | undefined,
  created: boolean,
): Promise<void> {
  if (!created || configuration === undefined) return;
  validationProviderFromConfiguration(configuration);
  const path = configurationPath(scanId);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, JSON.stringify(configuration), {
    flag: "wx",
    mode: 0o600,
  });
}

/** Run only after the workbench has sealed the scan. Its artifacts stay unchanged. */
export async function validateCompletedScan(
  scan: JsonObject,
  resolveProvider = validationProviderFromConfiguration,
): Promise<JsonObject | undefined> {
  if (typeof scan.scanId !== "string") return;
  let configuration: ValidationProviderConfiguration;
  try {
    configuration = JSON.parse(
      await readFile(configurationPath(scan.scanId), "utf8"),
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    return { status: "failed", message: String(error) };
  }
  try {
    const scanDir = String(scan.scanDir);
    const repositoryPath = String(scan.targetPath);
    const reportPath = join(scanDir, "validation.md");
    const recordsPath = join(scanDir, "validation.json");
    // Only protected host state can establish that this provider already ran.
    const cachePath = `${configurationPath(scan.scanId)}.result`;
    let cached;
    try {
      cached = JSON.parse(await readFile(cachePath, "utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (cached) {
      if (
        JSON.stringify(cached.configuration) !==
          JSON.stringify(configuration) ||
        cached.repositoryPath !== repositoryPath
      )
        throw new Error(
          "Saved validation does not match this scan's provider configuration.",
        );
      await replaceArtifactText(reportPath, cached.result.report);
      await replaceArtifactText(
        recordsPath,
        JSON.stringify(cached.records, null, 2) + "\n",
      );
      return { ...cached.result, reportPath, recordsPath };
    }
    const { findings }: { findings: Record<string, unknown>[] } = JSON.parse(
      await readFile(join(scanDir, "findings.json"), "utf8"),
    );
    const context = {
      repositoryPath,
      resolveHostPaths: protectedHostPathResolver,
    };
    const { providerName, summary, report, records } =
      await assessPluginFindings(
        configuration,
        findings,
        context,
        resolveProvider,
      );
    const result = {
      status: "complete",
      provider: providerName,
      findings: findings.length,
      reportPath,
      recordsPath,
      report,
      summary,
    };
    await writeFile(
      cachePath,
      JSON.stringify({ configuration, repositoryPath, records, result }),
      {
        flag: "wx",
        mode: 0o600,
      },
    );
    // These model-writable files are projections, never authoritative cache input.
    await replaceArtifactText(reportPath, report);
    await replaceArtifactText(
      recordsPath,
      JSON.stringify(records, null, 2) + "\n",
    );
    return result;
  } catch (error) {
    // An unavailable supplemental provider must not turn a sealed scan into a failure.
    return {
      status: "failed",
      provider: configuration.provider,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
