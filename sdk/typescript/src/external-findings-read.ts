import type {
  ExternalFinding,
  ExternalFindings,
  ExternalPublicationInput,
  ExternalSourceRepository,
} from "./external-findings.js";
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
import {
  normalizeTrivyFindings,
  needsPreviousTrivyProjection,
  normalizePreviousTrivyFindings,
} from "./trivy-findings.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import {
  normalizeEndorFindings,
  needsPreviousEndorProjection,
  normalizePreviousEndorFindings,
  endorRepositoryUrls,
} from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readSonarFindings } from "./sonar-findings.js";
import {
  needsPreviousVeracodeProjection,
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
  if (provider === "trivy") {
    const input = await readScannerJson(path);
    const findings = normalizeTrivyFindings(
      input,
      target,
      options.trivyScanRoot,
    );
    return {
      findings,
      previousFindings:
        target === "cloud" && needsPreviousTrivyProjection(findings)
          ? () =>
              normalizePreviousTrivyFindings(
                input,
                target,
                options.trivyScanRoot,
              )
          : undefined,
    };
  }
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
    const sourceRepositories = snyk
      ? snykFileRepositories(input)
      : (sarifFileRepositories(input, "Endor") ??
        findings.findings.flatMap((row) =>
          localFindingRepositories(provider, row),
        ));
    return {
      findings,
      sourceRepositories,
      previousFindings:
        !snyk && target === "cloud" && needsPreviousEndorProjection(findings)
          ? () => normalizePreviousEndorFindings(input, target)
          : undefined,
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
  if (provider === "checkmarx") {
    const url = options.sourceRepositoryUrl ?? "";
    return {
      findings: await readCheckmarxFindings(path, url, target),
      sourceRepositories: [{ url }],
    };
  }
  if (
    provider === "inspector" ||
    provider === "continuum" ||
    provider === "blackduck" ||
    provider === "veracode"
  ) {
    const url = options.sourceRepositoryUrl ?? "";
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
          needsPreviousVeracodeProjection,
        ],
      } as const
    )[provider];
    // Each version must see the same captured rows, including excluded ones.
    // The earlier Continuum reader did not accept detail arrays.
    const findings = normalize(input, url, target, mapping);
    return {
      findings,
      previousFindings:
        target === "cloud" && couldDiffer(findings)
          ? () => previous(input, url, target, mapping)
          : undefined,
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
