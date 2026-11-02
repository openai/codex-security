import type {
  ExternalFinding,
  ExternalFindings,
  ExternalPublicationInput,
  ExternalSourceRepository,
} from "./external-findings.js";
import { hasNoExternalRecords } from "./external-findings.js";
import { readScannerJson, sarifRepositoryUrls } from "./scanner-import.js";
import type { Provider } from "./external-import-models.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import { dependabotRepository } from "./github-dependabot-findings.js";
import { normalizeSnykFindings, snykRepositoryUrls } from "./snyk-findings.js";
import { normalizeSemgrepFindings } from "./semgrep-findings.js";
import { readOpenGrepFindings } from "./opengrep-findings.js";
import {
  normalizeEndorFindings,
  endorRepositoryUrls,
} from "./endor-findings.js";
import { readGitHubFindings } from "./github-findings.js";
import { readSonarFindings } from "./sonar-findings.js";
import { readVeracodeFindings } from "./veracode-findings.js";
import { readBlackDuckFindings } from "./blackduck-findings.js";
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

/** @internal Read vendor evidence for the local and Cloud import entrypoints. */
export async function readExternalFindings(
  path: string,
  options: ExternalFindingsReaderOptions,
  target: ExternalImportTarget = "cloud",
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
  if (
    options.provider === "snyk" ||
    options.provider === "semgrep" ||
    options.provider === "endor"
  ) {
    const input = await readScannerJson(path);
    let findings: ExternalFindings;
    let sourceRepositories: ExternalSourceRepository[];
    if (options.provider === "snyk") {
      findings = normalizeSnykFindings(input, target);
      sourceRepositories = findings.findings.flatMap((finding) =>
        localFindingRepositories("snyk", finding),
      );
    } else if (options.provider === "endor") {
      findings = normalizeEndorFindings(input, target);
      sourceRepositories = findings.findings.flatMap((finding) =>
        localFindingRepositories("endor", finding),
      );
    } else {
      findings = normalizeSemgrepFindings(
        input,
        { sourceRepositoryUrl: options.sourceRepositoryUrl ?? "" },
        target,
      );
      sourceRepositories = findings.findings.flatMap(({ evidence }) =>
        sarifRepositoryUrls(
          evidence.source_data?.["runContext"],
          "Semgrep",
        ).map((url) => ({ url })),
      );
    }
    if (isRecord(input)) {
      if (
        hasNoExternalRecords(findings) &&
        options.provider === "snyk" &&
        input["format"] === "snyk-findings-export/v1"
      )
        sourceRepositories = snykRepositoryUrls(input, {
          normalizeGitRemote: false,
        }).map((url) => ({ url }));
      else if (input["version"] === "2.1.0" && Array.isArray(input["runs"])) {
        const producer = (
          { endor: "Endor", snyk: "Snyk", semgrep: "Semgrep" } as const
        )[options.provider];
        const urls = new Set(sourceRepositories.map(({ url }) => url));
        for (const run of input["runs"])
          for (const url of sarifRepositoryUrls(run, producer)) urls.add(url);
        sourceRepositories = [...urls].map((url) => ({ url }));
      }
    }
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
