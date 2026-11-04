import type {
  ExternalFinding,
  ExternalFindings,
  ExternalPublicationInput,
  ExternalSourceRepository,
} from "./external-findings.js";
import { hasNoExternalRecords } from "./external-findings.js";
import { readScannerJson, sarifRunRepositories } from "./scanner-import.js";
import type { Provider } from "./external-import-models.js";
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
import { readOpenGrepFindings } from "./opengrep-findings.js";
import {
  normalizeEndorFindings,
  endorRepositoryUrls,
} from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readSonarFindings } from "./sonar-findings.js";
import { readVeracodeFindings } from "./veracode-findings.js";
import { readBlackDuckFindings } from "./blackduck-findings.js";
import { readContinuumFindings } from "./continuum-findings.js";
import { readInspectorFindings } from "./inspector-findings.js";
import { isRecord } from "./record.js";
import {
  readLocalWizFindings,
  readVendorFindingsForPublication,
  wizFindingRepository,
} from "./wiz-findings.js";

/** File reader names mapped to their stored and Cloud source provider. */
export const EXTERNAL_FINDINGS_PROVIDERS = {
  wiz: "wiz",
  snyk: "snyk",
  semgrep: "semgrep",
  // OpenGrep uses the existing SAST contract; evidence retains its scanner origin.
  opengrep: "semgrep",
  endor: "endor",
  github: "github",
  inspector: "inspector",
  blackduck: "blackduck",
  veracode: "veracode",
  sonar: "sonar",
  continuum: "continuum",
} as const satisfies Record<string, Provider>;

export type ExternalFindingsReader = keyof typeof EXTERNAL_FINDINGS_PROVIDERS;

export const EXTERNAL_FINDINGS_READERS = Object.keys(
  EXTERNAL_FINDINGS_PROVIDERS,
) as ExternalFindingsReader[];

/** File readers available in this SDK, shared by local and Cloud imports. */
export interface ExternalFindingsReaderOptions {
  provider: ExternalFindingsReader;
  sourceRepositoryUrl?: string;
  inspectorProjectMap?: ReadonlyMap<string, string>;
}

/** @internal Shared parser output, including immutable Cloud retry projections. */
export interface ReadExternalFindings {
  findings: ExternalFindings;
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

/** A run can name a repository even when none of its results produce a row. */
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
  if (options.provider === "sonar") {
    const url = options.sourceRepositoryUrl;
    const findings = await readSonarFindings(path, url ?? "", target);
    const binding = findings.report?.["repositoryUrl"];
    return {
      findings,
      sourceRepositories: typeof binding === "string" ? [{ url: binding }] : [],
    };
  }
  if (options.provider === "opengrep") {
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
  if (options.provider === "snyk") {
    const input = await readSnykReport(path);
    const findings = await normalizeSnykFile(input, target, references);
    let sourceRepositories = sarifFileRepositories(input, "Snyk");
    if (!sourceRepositories && hasNoExternalRecords(findings))
      sourceRepositories = emptySnykReportRepositories(input);
    return {
      findings,
      sourceRepositories:
        sourceRepositories ??
        findings.findings.flatMap((row) =>
          localFindingRepositories("snyk", row),
        ),
    };
  }
  if (options.provider === "endor") {
    const input = await readScannerJson(path);
    const findings = normalizeEndorFindings(input, target);
    return {
      findings,
      sourceRepositories:
        sarifFileRepositories(input, "Endor") ??
        findings.findings.flatMap((row) =>
          localFindingRepositories("endor", row),
        ),
    };
  }
  if (options.provider === "semgrep") {
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
    return {
      findings,
      sourceRepositories:
        sarifFileRepositories(input, "Semgrep") ??
        findings.findings.flatMap((row) => semgrepSarifRepositories(row)),
    };
  }
  if (options.provider === "github")
    return { findings: await readGitHubFindings(path, target) };
  if (
    options.provider === "inspector" ||
    options.provider === "continuum" ||
    options.provider === "blackduck" ||
    options.provider === "veracode"
  ) {
    const url = options.sourceRepositoryUrl ?? "";
    const read = {
      inspector: readInspectorFindings,
      continuum: readContinuumFindings,
      blackduck: readBlackDuckFindings,
      veracode: readVeracodeFindings,
    }[options.provider];
    return {
      findings: await read(path, url, target, options.inspectorProjectMap),
      sourceRepositories: [{ url }],
    };
  }
  // A new reader must choose its parser before reaching the Wiz replay path.
  options.provider satisfies "wiz";
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
