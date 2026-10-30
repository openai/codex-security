import {
  HOSTED_FINDINGS_FORMATS,
  type HostedExternalFindings,
  type ExternalPublicationInput,
  type ExternalSourceRepository,
} from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  hostedRepositoryUrlKey,
  isVerifiedGitHubRepository,
} from "./external-import-contract.js";
import { wizCsvRepositoryUrl } from "./wiz-csv.js";
import { snykRestReportRepository } from "./snyk-rest-findings.js";
import { readSnykFindings, snykRepositoryClaims } from "./snyk-findings.js";
import { hostedRepositoryUrl } from "./hosted-scanner-http.js";
import {
  normalizeSemgrepReport,
  semgrepSarifSourceRepositories,
} from "./semgrep-findings.js";
import { readScannerJson } from "./scanner-import.js";
import { readTrivyFindings } from "./trivy-findings.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import { readEndorFindings, endorRepositoryUrls } from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readInspectorFindings } from "./inspector-findings.js";
import { isGitHubCloudHost } from "./git-remote.js";
import { isRecord } from "./record.js";
import { readVendorFindingsForPublication } from "./wiz-findings.js";

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
  findings: HostedExternalFindings;
  /** Preserve previous Wiz projections when resuming immutable Cloud requests. */
  publication?: ExternalPublicationInput;
  sourceRepositories?: ExternalSourceRepository[];
}

/** @internal Read vendor evidence for the local and Cloud import entrypoints. */
export async function readExternalFindings(
  path: string,
  options: ExternalFindingsReaderOptions,
  target: ExternalImportTarget = "cloud",
  references?: readonly ExternalSourceRepository[],
): Promise<ReadExternalFindings> {
  if (options.provider === "trivy") {
    if (options.sourceRepositoryUrl !== undefined)
      throw new Error(
        "Trivy reads repository provenance from the report; do not supply --source-repository-url.",
      );
    return {
      findings: await readTrivyFindings(path, target, options.trivyScanRoot),
    };
  }
  if (options.trivyScanRoot !== undefined)
    throw new Error("--trivy-scan-root applies only to --provider trivy.");
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
    const findings = await readSnykFindings(path, target);
    if (
      findings.sourceRepositoryUrl &&
      options.sourceRepositoryUrl !== undefined
    ) {
      const declared = hostedRepositoryUrl(
        options.sourceRepositoryUrl,
        "Snyk source repository URL",
      );
      const github =
        findings.sourceRepositoryPlatform === "github" ||
        (findings.sourceRepositoryPlatform === undefined &&
          (target === "cloud" ||
            isVerifiedGitHubRepository(
              findings.sourceRepositoryUrl,
              references,
            )));
      // A hosted file comes from a single validated project.
      const gitlab = findings.findings.length
        ? snykRepositoryClaims(findings.findings[0]!.evidence.source_data).some(
            (source) => source.gitlab,
          )
        : snykRestReportRepository(findings.snykRestContext)?.gitlab;
      const key = (url: string) => hostedRepositoryUrlKey(url, github, gitlab);
      if (key(findings.sourceRepositoryUrl) !== key(declared))
        throw new Error(
          "Snyk REST source repository does not match the declared source repository URL.",
        );
    }
    return { findings };
  }
  if (options.provider === "semgrep") {
    // Cloud checks retained URLs against its connected destination before publication.
    const findings = normalizeSemgrepReport(
      await readScannerJson(path, HOSTED_FINDINGS_FORMATS.semgrep),
      { sourceRepositoryUrl: options.sourceRepositoryUrl },
      target,
      (url) =>
        target === "cloud" || isVerifiedGitHubRepository(url, references),
    );
    if (findings.sourceRepositoryUrl) return { findings };
    const sourceRepositories = findings.findings.flatMap(({ evidence }) =>
      semgrepSarifSourceRepositories(evidence.source_data),
    );
    return { findings, sourceRepositories };
  }
  if (options.provider === "endor") {
    const parsed = await readEndorFindings(path, target);
    return {
      findings: parsed,
      sourceRepositories: parsed.findings.flatMap((finding) =>
        endorRepositoryUrls(finding.evidence.source_data).map((url) => ({
          url,
        })),
      ),
    };
  }
  if (options.provider === "github")
    return { findings: await readGitHubFindings(path, target) };
  if (options.provider === "inspector") {
    const url = options.sourceRepositoryUrl ?? "";
    return {
      findings: await readInspectorFindings(
        path,
        url,
        target,
        options.inspectorProjectMap,
      ),
      sourceRepositories: [{ url }],
    };
  }
  const publication = await readVendorFindingsForPublication(path, target);
  // Raw package exports keep repository-branch URLs in retained source data.
  const sourceRepositories = publication.current.findings.flatMap(
    ({ evidence }) => {
      const csvUrl = wizCsvRepositoryUrl(evidence);
      if (csvUrl) return [{ url: csvUrl, platform: "github" as const }];
      const asset = evidence.source_data?.["vulnerableAsset"];
      if (!isRecord(asset) || typeof asset["cloudProviderURL"] !== "string")
        return [];
      const url = URL.parse(asset["cloudProviderURL"]);
      if (!url) return [];
      const github =
        asset["nativeType"] === "github#repositoryBranch" ||
        (asset["type"] === "REPOSITORY_BRANCH" &&
          isGitHubCloudHost(url.hostname));
      if (!github)
        return asset["type"] === "REPOSITORY_BRANCH"
          ? [{ url: asset["cloudProviderURL"] }]
          : [];
      const [, owner, repository] = url.pathname.split("/");
      return owner && repository
        ? [
            {
              url: `${url.origin}/${owner}/${repository}`,
              platform: "github" as const,
            },
          ]
        : [];
    },
  );
  return {
    findings: publication.current,
    publication,
    sourceRepositories: [
      ...publication.sourceRepositories,
      ...sourceRepositories,
    ],
  };
}
