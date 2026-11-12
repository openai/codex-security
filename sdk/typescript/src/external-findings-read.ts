import type {
  ExternalFinding,
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import { readScannerJson, sarifRunRepositories } from "./scanner-import.js";
import type { Provider } from "./external-import-models.js";
import { CodexSecurityError } from "./errors.js";
import { readTenableFindings } from "./tenable-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import { dependabotRepository } from "./github-dependabot-findings.js";
import {
  normalizeSnykFile,
  emptySnykReportRepositories,
  snykRepositoryUrls,
} from "./snyk-findings.js";
import {
  isSemgrepSarifDriver,
  normalizeSemgrepFindings,
  readSemgrepReport,
} from "./semgrep-findings.js";
import { semgrepPlatformReportRepository } from "./semgrep-platform-findings.js";
import { normalizeTrivyFindings } from "./trivy-findings.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import {
  normalizeEndorFindings,
  endorRepositoryUrls,
} from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readSonarFindings } from "./sonar-findings.js";
import { normalizeVeracodeFindings } from "./veracode-findings.js";
import { normalizeBlackDuckFindings } from "./blackduck-findings.js";
import { normalizeContinuumFindings } from "./continuum-findings.js";
import { readCheckmarxFindings } from "./checkmarx-findings.js";
import { normalizeInspectorFindings } from "./inspector-findings.js";
import { isRecord } from "./record.js";
import { readWizSelection, wizFindingRepository } from "./wiz-findings.js";
import { normalizeArmorCodeFindings } from "./armorcode-findings.js";

export type LocalFindingProvider = Provider | "tenable";

/** File reader names mapped to the provider stored with each finding. */
export const EXTERNAL_FINDINGS_PROVIDERS = {
  wiz: "wiz",
  armorcode: "armorcode",
  snyk: "snyk",
  semgrep: "semgrep",
  trivy: "trivy",
  // OpenGrep uses the existing SAST contract; evidence retains its scanner origin.
  opengrep: "semgrep",
  endor: "endor",
  github: "github",
  inspector: "inspector",
  blackduck: "blackduck",
  veracode: "veracode",
  sonar: "sonar",
  continuum: "continuum",
  checkmarx: "checkmarx",
  tenable: "tenable",
} as const satisfies Record<string, LocalFindingProvider>;

export type ExternalFindingsReader = keyof typeof EXTERNAL_FINDINGS_PROVIDERS;
export type CloudFindingsReader = Exclude<ExternalFindingsReader, "tenable">;

export function requireCloudReader(
  options: ExternalFindingsReaderOptions,
): asserts options is ExternalFindingsReaderOptions & {
  provider: CloudFindingsReader;
} {
  if (options.provider === "tenable")
    throw new CodexSecurityError(
      "Tenable findings require a local import (--to local).",
    );
}

export const EXTERNAL_FINDINGS_READERS = Object.keys(
  EXTERNAL_FINDINGS_PROVIDERS,
) as ExternalFindingsReader[];

/** File readers available in this SDK. Cloud supports a subset of these readers. */
export interface ExternalFindingsReaderOptions {
  provider: ExternalFindingsReader;
  sourceRepositoryUrl?: string;
  inspectorProjectMap?: ReadonlyMap<string, string>;
  trivyScanRoot?: string;
}

/** @internal Normalized file contents and any repository claims supplied by its reader. */
export interface ReadExternalFindings {
  findings: ExternalFindings;
  sourceRepositories?: ExternalSourceRepository[];
}

/** Repository references retained by a provider's individual finding. */
export function localFindingRepositories(
  provider: Provider,
  finding: ExternalFinding,
): ExternalSourceRepository[] {
  const { evidence } = finding;
  if (provider === "snyk")
    return snykRepositoryUrls(evidence.source_data, {
      normalizeGitRemote: false,
    }).map((url) => ({ url }));
  if (provider === "endor")
    return endorRepositoryUrls(evidence.source_data).map((url) => ({ url }));
  if (provider === "wiz") {
    const repository = wizFindingRepository(evidence);
    return repository ? [repository] : [];
  }
  if (provider === "github") {
    const url = dependabotRepository(finding);
    if (url) return [{ url, platform: "github" }];
  }
  return [];
}

/** Repository claims retained by the Semgrep SARIF reader. */
export function semgrepSarifRepositories(
  { evidence }: ExternalFinding,
  allowPartialCloudUrl = false,
): { url: string; branch?: string }[] {
  const data = evidence.source_data;
  const document = data?.["documentContext"];
  const driver = data?.["driverContext"];
  const partial = allowPartialCloudUrl && document === undefined;
  if (
    (!partial && (!isRecord(document) || document["version"] !== "2.1.0")) ||
    !isRecord(driver) ||
    typeof driver["name"] !== "string" ||
    !isSemgrepSarifDriver(driver["name"]) ||
    !isRecord(data?.["result"])
  )
    return [];
  const context = data["runContext"];
  const references = isRecord(context)
    ? context["versionControlProvenance"]
    : undefined;
  return Array.isArray(references)
    ? references.flatMap((reference) =>
        isRecord(reference) &&
        typeof reference["repositoryUri"] === "string" &&
        reference["repositoryUri"].trim()
          ? [
              {
                url: reference["repositoryUri"],
                ...(!partial &&
                  typeof reference["branch"] === "string" && {
                    branch: reference["branch"],
                  }),
              },
            ]
          : [],
      )
    : [];
}

/** A run may name a repository even when it produces no findings. */
function sarifFileRepositories(
  input: unknown,
  producer: "Endor" | "Semgrep" | "Snyk",
) {
  if (
    isRecord(input) &&
    input["version"] === "2.1.0" &&
    Array.isArray(input["runs"])
  )
    return input["runs"].flatMap((run) => sarifRunRepositories(run, producer));
}

/** Repository claims from every project or SARIF run, even those with no findings. */
export function snykFileRepositories(input: unknown) {
  return (
    sarifFileRepositories(input, "Snyk") ?? emptySnykReportRepositories(input)
  );
}

/** @internal Read vendor evidence for the local and Cloud import entrypoints. */
export async function readExternalFindings(
  path: string,
  options: ExternalFindingsReaderOptions,
  target: ExternalImportTarget = "cloud",
  references: readonly ExternalSourceRepository[] = [],
): Promise<ReadExternalFindings> {
  const { provider } = options;
  const url = options.sourceRepositoryUrl ?? "";
  if (provider === "tenable") {
    if (target === "cloud") requireCloudReader(options);
    return { findings: await readTenableFindings(path, url) };
  }
  if (provider === "sonar") {
    const findings = await readSonarFindings(path, url, target);
    const binding = findings.report?.["repositoryUrl"];
    return {
      findings,
      sourceRepositories: typeof binding === "string" ? [{ url: binding }] : [],
    };
  }
  if (provider === "opengrep" || provider === "checkmarx") {
    const findings =
      provider === "opengrep"
        ? await readOpenGrepFindings(path, { sourceRepositoryUrl: url }, target)
        : await readCheckmarxFindings(path, url, target);
    return { findings, sourceRepositories: [{ url }] };
  }
  if (provider === "snyk") {
    const input = await readScannerJson(path);
    const findings = await normalizeSnykFile(input, target, references);
    return { findings, sourceRepositories: snykFileRepositories(input) };
  }
  if (provider === "semgrep") {
    const input = await readSemgrepReport(path);
    const findings = normalizeSemgrepFindings(
      input,
      {
        sourceRepositoryUrl: options.sourceRepositoryUrl,
        sourceRepositories: references,
      },
      target,
    );
    if (semgrepPlatformReportRepository(findings)) return { findings };
    const sourceRepositories = sarifFileRepositories(input, "Semgrep") ?? [];
    if (!sourceRepositories.length && options.sourceRepositoryUrl)
      sourceRepositories.push({ url: options.sourceRepositoryUrl });
    return { findings, sourceRepositories };
  }
  if (provider === "armorcode") {
    const input = await readScannerJson(path);
    return {
      findings: normalizeArmorCodeFindings(
        input,
        target,
        options.sourceRepositoryUrl,
      ),
    };
  }
  if (provider === "github")
    return { findings: await readGitHubFindings(path, target) };
  if (provider === "wiz") {
    const wiz = await readWizSelection(path, target);
    const sourceRepositories = wiz.findings.findings.flatMap((finding) =>
      localFindingRepositories("wiz", finding),
    );
    return {
      findings: wiz.findings,
      sourceRepositories: [...wiz.sourceRepositories, ...sourceRepositories],
    };
  }
  const input = await readScannerJson(path);
  if (provider === "trivy")
    return {
      findings: normalizeTrivyFindings(input, target, options.trivyScanRoot),
    };
  if (provider === "endor") {
    const findings = normalizeEndorFindings(input, target);
    return {
      findings,
      sourceRepositories:
        sarifFileRepositories(input, "Endor") ??
        findings.findings.flatMap((row) =>
          localFindingRepositories(provider, row),
        ),
    };
  }
  if (provider === "continuum") {
    const findings = normalizeContinuumFindings(input, url, target);
    const binding = findings.report?.["sourceRepositoryUrl"];
    return {
      findings,
      sourceRepositories: [
        { url: typeof binding === "string" ? binding : url },
      ],
    };
  }
  const normalize = {
    inspector: normalizeInspectorFindings,
    blackduck: normalizeBlackDuckFindings,
    veracode: normalizeVeracodeFindings,
  }[provider];
  return {
    findings: normalize(input, url, target, options.inspectorProjectMap),
    sourceRepositories: [{ url }],
  };
}
