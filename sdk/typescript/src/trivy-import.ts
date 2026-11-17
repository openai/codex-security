import { resolve } from "node:path";
import { CodexSecurityError } from "./errors.js";
import type {
  ExternalFinding,
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import type { LocalFindingProvider } from "./external-findings-read.js";
import { readHostedGitRemotes } from "./hosted-git-remotes.js";
import { hasGitMetadata } from "./local-git-metadata.js";
import { isRecord } from "./record.js";
import { canonicalConfigPath, sameFile } from "./runtime.js";
import { abortable, gitOutput } from "./targets.js";
import { ambiguousHostedHttpPath } from "./hosted-git-repository.js";
import {
  trivyHeaderFields,
  trivyRemoteKey,
  trivyRemoteOmitsSshUser,
  trivyReportRemotes,
} from "./trivy-findings.js";
import { isWizOccurrence } from "./wiz-findings.js";

export function validateTrivyRepositoryUrl(value: string): void {
  if (
    /[\x00-\x20\x7f]/u.test(value) &&
    (/^https?:\/\//iu.test(value) ||
      /^https?:$/u.test(URL.parse(value)?.protocol ?? ""))
  )
    throw new CodexSecurityError(
      "HTTP(S) repository URLs must percent-encode spaces and control characters.",
    );
  if (ambiguousHostedHttpPath(value))
    throw new CodexSecurityError(
      "The repository URL has an HTTP path that does not match its Git path.",
    );
}

/** A canonical occurrence ID can identify a projected native repository declaration. */
export function retainedTrivyReport({
  source_finding_id: id,
  evidence,
}: ExternalFinding): unknown {
  const report = evidence.source_data?.["report"];
  if (
    !isRecord(report) ||
    report["SchemaVersion"] !== undefined ||
    !/^trivy:[a-f0-9]{64}$/u.test(id)
  )
    return report;
  const metadata = report["Metadata"];
  return isRecord(metadata) && typeof metadata["RepoURL"] === "string"
    ? { ...report, SchemaVersion: 2 }
    : report;
}

function identifiesTrivyReport(report: unknown): boolean {
  if (!isRecord(report) || report["SchemaVersion"] !== 2) return false;
  const scanner = report["Trivy"];
  const metadata = report["Metadata"];
  return (
    (isRecord(scanner) && typeof scanner["Version"] === "string") ||
    ((report["ArtifactType"] === "repository" ||
      report["ArtifactType"] === "filesystem") &&
      isRecord(metadata) &&
      typeof metadata["RepoURL"] === "string")
  );
}

/** Each selected finding must retain the repository asserted by a native batch header. */
export function trivyBatchSourceUrls(
  input: ExternalFindings,
  bind: boolean,
): string[] {
  const batch = trivyReportRemotes(input.report);
  if (bind) requireTrivyBinding(batch);
  for (const finding of input.findings) {
    const typedUrl = finding.evidence.details?.repository?.url;
    const row = trivyReportRemotes(retainedTrivyReport(finding));
    if (typedUrl && (bind || batch.urls.length || row.urls.length))
      validateTrivyRepositoryUrl(typedUrl);
    if (bind) requireTrivyBinding(row);
    if (batch.urls.length && !typedUrl && !row.urls.length)
      throw new Error(
        "For a repository-bound Trivy report, retain the source repository in each finding's source_data.report or details.repository.url.",
      );
  }
  return batch.urls;
}

/** A native header supplies provenance for the selected rows, not independent run metadata. */
export function isTrivyReportHeader(report: Record<string, unknown>): boolean {
  return (
    report["SchemaVersion"] === 2 &&
    (report["ArtifactType"] === "repository" ||
      report["ArtifactType"] === "filesystem") &&
    Object.keys(report).every(
      (field) =>
        trivyHeaderFields.includes(field) ||
        ["ArtifactName", "Trivy", "Metadata", "Results"].includes(field),
    )
  );
}

function requireTrivyBinding({
  urls,
  uncorroboratedTarget,
}: ReturnType<typeof trivyReportRemotes>): void {
  if (urls.some(trivyRemoteOmitsSshUser))
    throw new Error(
      "Trivy omitted the SSH user, so this report cannot identify its source repository. Verify the recorded remote’s SSH account, host, port and path, or use a verified HTTPS remote, then regenerate the report.",
    );
  if (
    uncorroboratedTarget &&
    /^https?:\/\//iu.test(uncorroboratedTarget) &&
    !/^https?:\/\//u.test(uncorroboratedTarget)
  )
    throw new Error(
      "Trivy's mixed-case HTTP target cannot identify the Git transport. Verify the source remote and regenerate the report.",
    );
}

function isRetainedTrivyFinding(finding: ExternalFinding) {
  const data = finding.evidence.source_data;
  if (!data) return false;
  const report = retainedTrivyReport(finding);
  if (identifiesTrivyReport(report)) return true;
  const metadata = isRecord(report) ? report["Metadata"] : undefined;
  const nativeReport =
    isRecord(report) &&
    report["SchemaVersion"] === 2 &&
    (isTrivyReportHeader(report) ||
      (isRecord(metadata) && typeof metadata["RepoURL"] === "string"));
  const result = data["result"];
  const vulnerability = data["vulnerability"];
  const nativeRow =
    isRecord(result) &&
    result["Class"] === "lang-pkgs" &&
    isRecord(vulnerability) &&
    typeof vulnerability["VulnerabilityID"] === "string" &&
    typeof vulnerability["PkgName"] === "string";
  return (
    (nativeReport && finding.source_finding_id.startsWith("trivy:")) ||
    (nativeRow && (nativeReport || typeof data["scanRoot"] === "string"))
  );
}

/** Retained rows keep their scanner identity even if the report header is projected out. */
export function checkRetainedTrivyProvider(
  provider: LocalFindingProvider,
  finding: ExternalFinding,
  target: ExternalImportTarget = "cloud",
): void {
  if (
    provider !== "trivy" &&
    isRetainedTrivyFinding(finding) &&
    !(provider === "wiz" && isWizOccurrence(finding, target))
  )
    throw new CodexSecurityError(
      "Retained Trivy evidence requires the trivy provider.",
    );
}

export function checkTrivyReportProvider(
  provider: LocalFindingProvider,
  report: unknown,
): void {
  if (provider !== "trivy" && identifiesTrivyReport(report))
    throw new CodexSecurityError(
      "Retained Trivy evidence requires the trivy provider.",
    );
}

// Typed web links and explicit curl helper arguments use a case-insensitive URL scheme.
function trivyUrlArgument(url: string) {
  return url.replace(/^(?:https?|ftps?):\/\//iu, (scheme) =>
    scheme.toLowerCase(),
  );
}

function localTrivySources(
  input: ExternalFindings,
  references: readonly ExternalSourceRepository[],
) {
  const urls = new Set(trivyBatchSourceUrls(input, false));
  for (const finding of input.findings) {
    const typedUrl = finding.evidence.details?.repository?.url;
    if (typedUrl) urls.add(trivyUrlArgument(typedUrl));
    for (const url of trivyReportRemotes(retainedTrivyReport(finding)).urls)
      urls.add(url);
  }
  for (const { platform, url } of references)
    urls.add(platform === "github" ? trivyUrlArgument(url) : url);
  return [...urls];
}

export async function matchTrivyCheckout(
  repository: string,
  trivy: ExternalFindings,
  references: readonly ExternalSourceRepository[],
  {
    protectedRoot,
    environment,
    signal,
  }: {
    protectedRoot: string[];
    environment: NodeJS.ProcessEnv;
    signal?: AbortSignal | undefined;
  },
): Promise<boolean> {
  const sources = localTrivySources(trivy, references);
  const trivyKeys = new Set(sources.map((url) => trivyRemoteKey(url)));
  let remotes: string[] | undefined;
  if (await hasGitMetadata(repository, signal)) {
    const gitProtectedRoots = [
      ...protectedRoot,
      await abortable(() => canonicalConfigPath(process.cwd()), signal),
    ];
    const root = resolve(
      await abortable(
        () =>
          gitOutput(
            repository,
            ["rev-parse", "--show-toplevel"],
            signal,
            { LC_ALL: "C" },
            undefined,
            "utf8",
            gitProtectedRoots,
            environment,
          ),
        signal,
      ),
    );
    if (
      root !== repository &&
      !(await abortable(() => sameFile(root, repository), signal))
    )
      throw new CodexSecurityError(
        `Trivy finding paths are checkout-relative. Git found the checkout at ${JSON.stringify(root)}. Select it with --repository and set --trivy-scan-root relative to it.`,
      );
    if (sources.length)
      remotes = await readHostedGitRemotes(
        repository,
        gitProtectedRoots,
        environment,
        signal,
        trivyKeys,
      );
  }
  if (remotes) trivyBatchSourceUrls(trivy, true);
  if (trivyKeys.size > 1)
    throw new CodexSecurityError(
      "Trivy source URLs identify different repositories.",
    );
  if (
    remotes &&
    !remotes.some(
      (url) =>
        !/^(?:https?|ftps?):\/\/[^/?#@]*@[^/?#@]*@/iu.test(url) &&
        trivyKeys.has(trivyRemoteKey(url, undefined, true)),
    )
  )
    throw new CodexSecurityError(
      `Imported repository ${JSON.stringify(sources[0])} does not match a configured remote of ${repository}. Select the matching local repository.`,
    );
  return remotes !== undefined;
}
