import type {
  ExternalFinding,
  ExternalFindings,
  ExternalPublicationInput,
  ExternalSourceRepository,
} from "./external-findings.js";
import { hasNoExternalRecords } from "./external-findings.js";
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
import { readTrivyFindings } from "./trivy-findings.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import {
  normalizeEndorFindings,
  endorRepositoryUrls,
} from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readSonarFindings } from "./sonar-findings.js";
import { readVeracodeFindings } from "./veracode-findings.js";
import { readBlackDuckFindings } from "./blackduck-findings.js";
import {
  normalizeContinuumFindings,
  normalizePreviousContinuumFindings,
} from "./continuum-findings.js";
import { readCheckmarxFindings } from "./checkmarx-findings.js";
import {
  normalizeInspectorFindings,
  normalizePreviousInspectorFindings,
} from "./inspector-findings.js";
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
  provider: ExternalFindingsReader,
): asserts provider is CloudFindingsReader {
  if (provider === "tenable")
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

/** @internal Read vendor evidence for the local and Cloud import entrypoints. */
export async function readExternalFindings(
  path: string,
  options: ExternalFindingsReaderOptions,
  target: ExternalImportTarget = "cloud",
  references: readonly ExternalSourceRepository[] = [],
): Promise<ReadExternalFindings> {
  const { provider } = options;
  if (provider === "tenable") {
    if (target === "cloud") requireCloudReader(provider);
    return {
      findings: await readTenableFindings(
        path,
        options.sourceRepositoryUrl ?? "",
      ),
    };
  }
  if (provider === "trivy")
    return {
      findings: await readTrivyFindings(path, target, options.trivyScanRoot),
    };
  if (provider === "sonar") {
    const url = options.sourceRepositoryUrl;
    const findings = await readSonarFindings(path, url ?? "", target);
    const binding = findings.report?.["repositoryUrl"];
    return {
      findings,
      sourceRepositories: typeof binding === "string" ? [{ url: binding }] : [],
    };
  }
  if (provider === "opengrep") {
    const sourceRepositoryUrl = options.sourceRepositoryUrl ?? "";
    return {
      findings: await readOpenGrepFindings(
        path,
        { sourceRepositoryUrl },
        target,
      ),
      sourceRepositories: [{ url: sourceRepositoryUrl }],
    };
  }
  if (provider === "snyk" || provider === "endor") {
    const snyk = provider === "snyk";
    const input = await (snyk ? readSnykReport : readScannerJson)(path);
    const findings = snyk
      ? await normalizeSnykFile(input, target, references)
      : normalizeEndorFindings(input, target);
    const header = sarifFileRepositories(input, snyk ? "Snyk" : "Endor");
    const sourceRepositories =
      header ??
      (snyk && hasNoExternalRecords(findings)
        ? emptySnykReportRepositories(input)
        : findings.findings.flatMap((row) =>
            localFindingRepositories(provider, row),
          ));
    return { findings, sourceRepositories };
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
  if (provider === "inspector" || provider === "continuum") {
    const url = options.sourceRepositoryUrl ?? "";
    const mapping =
      options.inspectorProjectMap && new Map(options.inspectorProjectMap);
    const input = await readScannerJson(path);
    const normalize =
      provider === "inspector"
        ? normalizeInspectorFindings
        : normalizeContinuumFindings;
    const previous =
      provider === "inspector"
        ? normalizePreviousInspectorFindings
        : normalizePreviousContinuumFindings;
    // Both projections describe the same captured file, including rows admitted
    // by just one reader. Detail arrays are new to Continuum.
    const wasSupported = provider === "inspector" || !Array.isArray(input);
    return {
      findings: normalize(input, url, target, mapping),
      previousFindings:
        target === "cloud" && wasSupported
          ? () => previous(input, url, target, mapping)
          : undefined,
      sourceRepositories: [{ url }],
    };
  }
  if (
    provider === "checkmarx" ||
    provider === "blackduck" ||
    provider === "veracode"
  ) {
    const url = options.sourceRepositoryUrl ?? "";
    const read = {
      checkmarx: readCheckmarxFindings,
      blackduck: readBlackDuckFindings,
      veracode: readVeracodeFindings,
    }[provider];
    return {
      findings: await read(path, url, target),
      sourceRepositories: [{ url }],
    };
  }
  // A new reader must choose its parser before reaching the Wiz replay path.
  provider satisfies "wiz";
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
