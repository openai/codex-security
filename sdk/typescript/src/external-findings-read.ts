import type {
  ExternalFindings,
  ExternalPublicationInput,
  ExternalSourceRepository,
} from "./external-findings.js";
import { hasNoExternalRecords } from "./external-findings.js";
import { readScannerJson, sarifRepositoryUrls } from "./scanner-import.js";
import type { Provider } from "./external-import-models.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import { wizCsvRepositoryUrl } from "./wiz-csv.js";
import { normalizeSnykFindings, snykRepositoryUrls } from "./snyk-findings.js";
import { normalizeSemgrepFindings } from "./semgrep-findings.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import {
  normalizeEndorFindings,
  endorRepositoryUrls,
} from "./endor-findings.js";
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
}

/** @internal Shared parser output, including immutable Cloud retry projections. */
export interface ReadExternalFindings {
  findings: ExternalFindings;
  /** Preserve previous Wiz projections when resuming immutable Cloud requests. */
  publication?: ExternalPublicationInput;
  sourceRepositories?: ExternalSourceRepository[];
}

/** @internal Read vendor evidence for the local and Cloud import entrypoints. */
export async function readExternalFindings(
  path: string,
  options: ExternalFindingsReaderOptions,
  target: ExternalImportTarget = "cloud",
): Promise<ReadExternalFindings> {
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
  if (
    options.provider === "snyk" ||
    options.provider === "semgrep" ||
    options.provider === "endor"
  ) {
    const input = await readScannerJson(path);
    let findings: ExternalFindings;
    let repositoryUrls: string[];
    if (options.provider === "snyk") {
      findings = normalizeSnykFindings(input, target);
      repositoryUrls = findings.findings.flatMap(({ evidence }) =>
        snykRepositoryUrls(evidence.source_data, {
          normalizeGitRemote: false,
        }),
      );
    } else if (options.provider === "endor") {
      findings = normalizeEndorFindings(input, target);
      repositoryUrls = findings.findings.flatMap(({ evidence }) =>
        endorRepositoryUrls(evidence.source_data),
      );
    } else {
      findings = normalizeSemgrepFindings(
        input,
        { sourceRepositoryUrl: options.sourceRepositoryUrl ?? "" },
        target,
      );
      repositoryUrls = findings.findings.flatMap(({ evidence }) =>
        sarifRepositoryUrls(evidence.source_data?.["runContext"], "Semgrep"),
      );
    }
    if (
      target === "local" &&
      hasNoExternalRecords(findings) &&
      isRecord(input)
    ) {
      if (
        options.provider === "snyk" &&
        input["format"] === "snyk-findings-export/v1"
      )
        repositoryUrls = snykRepositoryUrls(input, {
          normalizeGitRemote: false,
        });
      else if (input["version"] === "2.1.0" && Array.isArray(input["runs"])) {
        const producer = (
          { endor: "Endor", snyk: "Snyk", semgrep: "Semgrep" } as const
        )[options.provider];
        repositoryUrls = input["runs"].flatMap((run) =>
          sarifRepositoryUrls(run, producer),
        );
      }
    }
    return {
      findings,
      sourceRepositories: repositoryUrls.map((url) => ({ url })),
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
