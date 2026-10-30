import {
  HOSTED_FINDINGS_FORMATS,
  type ExternalFinding,
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
import { snykRestReportRepository } from "./snyk-rest-findings.js";
import { readSnykFindings, snykRepositoryClaims } from "./snyk-findings.js";
import { hostedRepositoryUrl } from "./hosted-scanner-http.js";
import {
  normalizeSemgrepReport,
  semgrepSarifSourceRepositories,
} from "./semgrep-findings.js";
import { readScannerJson } from "./scanner-import.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import { readEndorFindings, endorRepositoryUrls } from "./endor-findings.js";
import { dependabotRepository } from "./github-dependabot-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readVeracodeFindings } from "./veracode-findings.js";
import { readBlackDuckFindings } from "./blackduck-findings.js";
import { readInspectorFindings } from "./inspector-findings.js";
import {
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
  findings: HostedExternalFindings;
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
    return snykRepositoryClaims(evidence.source_data).flatMap(
      ({ url, nativeUrl, platform }) =>
        [url, ...(nativeUrl ? [nativeUrl] : [])].map((url) => ({
          url,
          ...(platform === "github" ? { platform: "github" as const } : {}),
        })),
    );
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

/** @internal Read vendor evidence for the local and Cloud import entrypoints. */
export async function readExternalFindings(
  path: string,
  options: ExternalFindingsReaderOptions,
  target: ExternalImportTarget = "cloud",
  references?: readonly ExternalSourceRepository[],
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
    return {
      findings,
      sourceRepositories: findings.findings.flatMap((finding) =>
        localFindingRepositories("snyk", finding),
      ),
    };
  }
  if (options.provider === "endor") {
    const findings = await readEndorFindings(path, target);
    return {
      findings,
      sourceRepositories: findings.findings.flatMap((finding) =>
        localFindingRepositories("endor", finding),
      ),
    };
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
  if (options.provider === "github")
    return { findings: await readGitHubFindings(path, target) };
  if (
    options.provider === "inspector" ||
    options.provider === "blackduck" ||
    options.provider === "veracode"
  ) {
    const url = options.sourceRepositoryUrl ?? "";
    const read = {
      inspector: readInspectorFindings,
      blackduck: readBlackDuckFindings,
      veracode: readVeracodeFindings,
    }[options.provider];
    return {
      findings: await read(path, url, target, options.inspectorProjectMap),
      sourceRepositories: [{ url }],
    };
  }
  const publication = await readVendorFindingsForPublication(path, target);
  const sourceRepositories = publication.current.findings.flatMap((finding) =>
    localFindingRepositories("wiz", finding),
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
