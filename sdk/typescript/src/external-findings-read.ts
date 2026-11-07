import type {
  ExternalFinding,
  ExternalFindings,
  ExternalPublicationInput,
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
  readSnykReport,
  emptySnykReportRepositories,
  snykRepositoryUrls,
} from "./snyk-findings.js";
import {
  isSemgrepSarifDriver,
  normalizeSemgrepFindings,
  readSemgrepReport,
} from "./semgrep-findings.js";
import { semgrepPlatformReportRepository } from "./semgrep-platform-findings.js";
import {
  normalizeTrivyFindings,
  needsPreviousTrivyProjection,
  normalizePreviousTrivyFindings,
} from "./trivy-findings.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import {
  normalizeEndorFindings,
  normalizePreviousEndorFindings,
  endorRepositoryUrls,
} from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readSonarFindings } from "./sonar-findings.js";
import {
  normalizeVeracodeFindings,
  normalizePreviousVeracodeFindings,
} from "./veracode-findings.js";
import {
  needsPreviousBlackDuckProjection,
  normalizeBlackDuckFindings,
  normalizePreviousBlackDuckFindings,
} from "./blackduck-findings.js";
import {
  normalizeContinuumFindings,
  normalizePreviousContinuumFindings,
} from "./continuum-findings.js";
import { readCheckmarxFindings } from "./checkmarx-findings.js";
import {
  normalizeInspectorFindings,
  normalizePreviousInspectorFindings,
} from "./inspector-findings.js";
import { hasPreviousCloudProjection } from "./reader-selection.js";
import { isRecord } from "./record.js";
import {
  readLocalWizFindings,
  readVendorFindingsForPublication,
  wizFindingRepository,
} from "./wiz-findings.js";

export type LocalFindingProvider = Provider | "tenable";

/** File reader names mapped to the provider stored with each finding. */
export const EXTERNAL_FINDINGS_PROVIDERS = {
  wiz: "wiz",
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

/** @internal Shared parser output, including immutable Cloud retry projections. */
export interface ReadExternalFindings {
  findings: ExternalFindings;
  previousFindings?: () => ExternalFindings;
  /** Preserve previous Wiz projections when resuming immutable Cloud requests. */
  publication?: ExternalPublicationInput;
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
  // Both projections describe the same captured rows, including exclusions.
  function withReplay(
    findings: ExternalFindings,
    couldDiffer: (findings: ExternalFindings) => boolean,
    previous: () => ExternalFindings,
  ): ReadExternalFindings {
    return {
      findings,
      previousFindings:
        target === "cloud" && couldDiffer(findings) ? previous : undefined,
    };
  }
  if (provider === "tenable") {
    if (target === "cloud") requireCloudReader(options);
    return { findings: await readTenableFindings(path, url) };
  }
  if (provider === "trivy") {
    const args = [
      await readScannerJson(path),
      target,
      options.trivyScanRoot,
    ] as const;
    return withReplay(
      normalizeTrivyFindings(...args),
      needsPreviousTrivyProjection,
      () => normalizePreviousTrivyFindings(...args),
    );
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
    const input = await readSnykReport(path);
    const findings = await normalizeSnykFile(input, target, references);
    return { findings, sourceRepositories: snykFileRepositories(input) };
  }
  if (provider === "endor") {
    const input = await readScannerJson(path);
    const findings = normalizeEndorFindings(input, target);
    return {
      ...withReplay(findings, hasPreviousCloudProjection, () =>
        normalizePreviousEndorFindings(input, target),
      ),
      sourceRepositories:
        sarifFileRepositories(input, "Endor") ??
        findings.findings.flatMap((row) =>
          localFindingRepositories(provider, row),
        ),
    };
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
  if (provider === "github")
    return { findings: await readGitHubFindings(path, target) };
  if (provider === "wiz") {
    const wiz =
      target === "local"
        ? await readLocalWizFindings(path)
        : await readVendorFindingsForPublication(path, target);
    const sourceRepositories = wiz.current.findings.flatMap((finding) =>
      localFindingRepositories("wiz", finding),
    );
    return {
      findings: wiz.current,
      ...("legacy" in wiz && { publication: wiz }),
      sourceRepositories: [...wiz.sourceRepositories, ...sourceRepositories],
    };
  }
  const mapping =
    options.inspectorProjectMap && new Map(options.inspectorProjectMap);
  const input = await readScannerJson(path);
  const [normalize, previous, couldDiffer] = (
    {
      inspector: [
        normalizeInspectorFindings,
        normalizePreviousInspectorFindings,
        () => true,
      ],
      continuum: [
        normalizeContinuumFindings,
        normalizePreviousContinuumFindings,
        () => !Array.isArray(input),
      ],
      blackduck: [
        normalizeBlackDuckFindings,
        normalizePreviousBlackDuckFindings,
        needsPreviousBlackDuckProjection,
      ],
      veracode: [
        normalizeVeracodeFindings,
        normalizePreviousVeracodeFindings,
        hasPreviousCloudProjection,
      ],
    } as const
  )[provider];
  const args = [input, url, target, mapping] as const;
  return {
    ...withReplay(normalize(...args), couldDiffer, () => previous(...args)),
    sourceRepositories: [{ url }],
  };
}
