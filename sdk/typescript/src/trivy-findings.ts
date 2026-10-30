import { posix, sep } from "node:path";
import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  hostedRepositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import {
  isGitHubCloudHost,
  normalizeGitRepositoryUrl,
  parseGitRemote,
} from "./git-remote.js";
import { validateHostedRepositoryUrl } from "./hosted-scanner-http.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

type NativeRecord = Record<string, unknown>;

const urlScheme = /^[a-z][a-z\d+.-]*:\/\//iu;
const javaArchiveAncestor = /\.(?:jar|war|ear|par)\//iu;

const sshProtocols = new Set(["ssh:", "git+ssh:", "ssh+git:"]);

const curlUrlPrefix = /^(?:(?:https?|ftps?)::)?(?:https?|ftps?):\/{1,3}/iu;
const unsafeRepositoryUrl =
  "Use a Trivy repository URL without credentials, a query, or a fragment.";

function hasHttpUserinfo(
  value: string | null,
  allowImplicitHttps: boolean,
): boolean {
  if (!value) return false;
  const prefix = curlUrlPrefix.exec(value)?.[0];
  if (!prefix && (!allowImplicitHttps || /^[a-z]:[\\/]/iu.test(value)))
    return false;
  // Git's HTTP transport treats backslashes before @ as part of userinfo.
  const authority = value.slice(prefix?.length ?? 0).split(/[/?#]/u, 1)[0]!;
  const at = authority.lastIndexOf("@");
  const colon = authority.indexOf(":");
  const scp = colon > authority.indexOf("@");
  // A bare user@host:path is Git's SSH form. Trivy reads user@host/path as HTTPS.
  return at > 0 && (!!prefix || (!scp && !authority.includes("\\", at + 1)));
}

function networkRepository(value: unknown): string | null {
  const source = text(value);
  if (!source || /^(?:[a-z]:|[./\\])/iu.test(source)) return null;
  const remote = parseGitRemote(source);
  if (!remote) return null;
  const { url } = remote;
  const ssh = sshProtocols.has(url.protocol);
  if (url.password || (!ssh && url.username) || /[?#\t\r\n]/u.test(source))
    throw new Error(unsafeRepositoryUrl);
  if (url.protocol === "file:") return null;
  if (
    !url.hostname ||
    !remote.path ||
    (!ssh &&
      !["http:", "https:", "git:", "ftp:", "ftps:"].includes(url.protocol))
  )
    throw new Error("Unsupported Trivy repository URL.");
  return source;
}

function comparableGitHubRemote(
  remote: string,
  cloudRepositoryUrl?: string,
): string | undefined {
  if (/[?#\t\r\n]/u.test(remote)) return undefined;
  let parsed;
  try {
    parsed = parseGitRemote(remote);
  } catch {
    // A checkout can have unrelated remotes with no comparable URL.
    return undefined;
  }
  if (!parsed) return undefined;
  const prefix = `${parsed.url.protocol}//`;
  // Git dispatches mixed-case schemes to distinct remote helpers.
  if (!parsed.scpStyle && !remote.startsWith(prefix)) return undefined;
  const host = parsed.url.hostname.toLowerCase();
  const githubUrl =
    cloudRepositoryUrl ??
    (isGitHubCloudHost(host) ? `https://${host}` : undefined);
  const normalized = normalizeGitRepositoryUrl(remote, githubUrl);
  if (!/^https?:\/\//iu.test(normalized)) return undefined;
  if (
    !isGitHubCloudHost(new URL(normalized).hostname) &&
    (!cloudRepositoryUrl || new URL(cloudRepositoryUrl).hostname !== host)
  )
    return undefined;
  return normalized;
}

export function trivyRemoteKey(
  remote: string,
  cloudRepositoryUrl?: string,
  checkout = false,
): string {
  const normalized = comparableGitHubRemote(remote, cloudRepositoryUrl);
  if (!normalized) return remote;
  // GitHub identifies an HTTPS repository by host and path. Other Git servers
  // may use the HTTP username to select the repository.
  const url = checkout
    ? normalized.replace(/^(https?:\/\/)[^/\\?#]*@/iu, "$1")
    : normalized;
  return hostedRepositoryUrlKey(url, true);
}

const sshScheme = /^(?:ssh|git\+ssh|ssh\+git):\/\//u;

function userlessSsh(url: string): boolean {
  return sshScheme.test(url) && !new URL(url).username;
}

function requireUnambiguousHttpTarget(url: string): void {
  if (/^https?:\/\//iu.test(url) && !/^https?:\/\//u.test(url))
    throw new Error(
      "Trivy's mixed-case HTTP target cannot identify the Git transport. Verify the source remote and regenerate the report.",
    );
}

function requireTrivySshUsers(urls: readonly string[]): void {
  if (urls.some(userlessSsh))
    throw new Error(
      "Trivy omitted the SSH user, so this report cannot identify its source repository. Verify the recorded remote’s SSH account, host, port and path, or use a verified HTTPS remote, then regenerate the report.",
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

export function identifiesTrivyReport(report: unknown): boolean {
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
      validateHostedRepositoryUrl(typedUrl);
    if (bind) requireTrivyBinding(row);
    if (batch.urls.length && !typedUrl && !row.urls.length)
      throw new Error(
        "For a repository-bound Trivy report, retain the source repository in each finding's source_data.report or details.repository.url.",
      );
  }
  return batch.urls;
}

const headerFields = [
  "SchemaVersion",
  "ArtifactType",
  "ArtifactID",
  "ReportID",
  "CreatedAt",
];

/** A native header supplies provenance for the selected rows, not independent run metadata. */
export function isTrivyReportHeader(report: NativeRecord): boolean {
  return (
    report["SchemaVersion"] === 2 &&
    (report["ArtifactType"] === "repository" ||
      report["ArtifactType"] === "filesystem") &&
    Object.keys(report).every(
      (field) =>
        headerFields.includes(field) ||
        ["ArtifactName", "Trivy", "Metadata", "Results"].includes(field),
    )
  );
}

// Go may rewrite escaped separators or unreserved bytes in mixed Unicode paths.
// Only escape spaces and non-ASCII bytes when existing escapes are unambiguous.
function escapedHttpTarget(target: string): string {
  return target.replace(
    /^(https?:\/\/[^/]+)(\/(?:[^%]|%(?:2[05]|[89A-F][\dA-F]))*)$/u,
    (_, authority: string, path: string) =>
      authority + path.replace(/[ \P{ASCII}]+/gu, encodeURIComponent),
  );
}

export function trivyReportRemotes(report: unknown) {
  if (!isRecord(report)) return { urls: [] };
  const metadata = report["Metadata"];
  const repoUrl = text(isRecord(metadata) && metadata["RepoURL"]);
  const name = text(report["ArtifactName"]);
  if (
    hasHttpUserinfo(repoUrl, true) ||
    hasHttpUserinfo(name, report["ArtifactType"] !== "filesystem")
  )
    throw new Error(unsafeRepositoryUrl);
  const repository = networkRepository(repoUrl);
  let artifact = name && urlScheme.test(name) ? networkRepository(name) : null;
  if (report["SchemaVersion"] !== 2) return { urls: [] };
  // A filesystem display label is validated but never identifies the repository.
  if (report["ArtifactType"] === "filesystem")
    return { urls: repository ? [repository] : [] };
  // Trivy accepts scheme-less HTTPS targets and relative checkout paths.
  // A scheme-less name identifies a remote only when Git metadata corroborates it.
  const target =
    artifact ??
    (name && /^[^./:\\][^/:\\]*\//u.test(name) ? `https://${name}` : null);
  if (
    target &&
    repository &&
    report["ArtifactType"] === "repository" &&
    (target === repository || escapedHttpTarget(target) === repository)
  )
    artifact = repository;
  // A checkout-supplied label cannot restore an omitted SSH user. Keep any
  // other difference visible when validating the report's repository claims.
  if (
    repository &&
    userlessSsh(repository) &&
    artifact?.replace(/^([^:]+:\/\/)[^/@]+@/u, "$1") === repository
  )
    return { urls: [repository] };
  return {
    urls: [repository, artifact].filter((url) => url !== null),
    uncorroboratedTarget: repository ? null : artifact,
  };
}

export function requireTrivyBinding({
  urls,
  uncorroboratedTarget,
}: ReturnType<typeof trivyReportRemotes>): void {
  requireTrivySshUsers(urls);
  if (uncorroboratedTarget) requireUnambiguousHttpTarget(uncorroboratedTarget);
}

function matchingTrivyRemotes(
  [repository, artifact]: readonly string[],
  githubUrl?: string,
): boolean {
  return (
    !!repository &&
    !!artifact &&
    trivyRemoteKey(repository, githubUrl) ===
      trivyRemoteKey(artifact, githubUrl)
  );
}

/** Compare the report's claims using the authenticated host when available. */
export function trivyRepositoryUrl(
  report: unknown,
  cloudRepositoryUrl?: string,
): string | null {
  const { urls } = trivyReportRemotes(report);
  if (urls.length > 1 && !matchingTrivyRemotes(urls, cloudRepositoryUrl))
    throw new Error("Trivy source URLs identify different repositories.");
  const remote = urls[0];
  return remote && cloudRepositoryUrl
    ? (comparableGitHubRemote(remote, cloudRepositoryUrl) ?? remote)
    : (remote ?? null);
}

function repositoryPath(value: unknown, directory = false): string | null {
  const raw = text(value);
  if (!raw || !relativePath(raw)) return null;
  // Check the emitted spelling across platforms while retaining literal POSIX backslashes.
  const path = posix.normalize(raw);
  const portable = posix.normalize(path.replaceAll("\\", "/"));
  const firstComponent = portable.split("/", 1)[0]!;
  const at = firstComponent.indexOf("@", 1);
  const scpStyle = at !== -1 && firstComponent.indexOf(":", at + 2) !== -1;
  return relativePath(portable) &&
    (directory || (portable !== "." && !portable.endsWith("/"))) &&
    !scpStyle &&
    !/^[a-z][a-z\d+.-]*:\//iu.test(portable)
    ? path
    : null;
}

const aggregateTargets = new Map([
  ["python-pkg", "Python"],
  ["conda-pkg", "Conda"],
  ["gemspec", "Ruby"],
  ["node-pkg", "Node.js"],
  ["jar", "Java"],
  ["kubernetes", "Kubernetes"],
]);
const nonManifestTypes = new Set([
  "gobinary",
  "rustbinary",
  "jar",
  "javascript",
]);

function resolveScanRoot(
  scanRoot: string | undefined,
  remoteRepository: boolean,
): string {
  if (scanRoot === undefined) {
    if (remoteRepository) return ".";
    throw new Error(
      "Specify --trivy-scan-root relative to the repository; use . for a whole-checkout scan.",
    );
  }
  const root = repositoryPath(scanRoot.split(sep).join("/"), true)?.replace(
    /\/$/u,
    "",
  );
  if (!root)
    throw new Error(
      "--trivy-scan-root must be a repository-relative directory without traversal.",
    );
  if (remoteRepository && root !== ".")
    throw new Error(
      "A remote Trivy repository scan starts at the checkout root; --trivy-scan-root must be .",
    );
  return root;
}

function scopedPath(root: string, value: unknown): string | null {
  const path = repositoryPath(value);
  return path === null ? null : posix.join(root, path);
}

function pick(source: NativeRecord, fields: string[]): NativeRecord {
  return Object.fromEntries(
    fields
      .filter((field) => Object.hasOwn(source, field))
      .map((field) => [field, source[field]]),
  );
}

function packageKeys(
  id: unknown,
  identifier: unknown,
  name: unknown,
  version: unknown,
  path: unknown,
) {
  const file = repositoryPath(path) ?? text(path);
  const key = (kind: string, value: unknown) =>
    text(value) && JSON.stringify([kind, value, file]);
  const native = isRecord(identifier) ? identifier : {};
  return {
    id: key("id", id),
    uid: key("uid", native["UID"]),
    purl: key("purl", native["PURL"]),
    bomRef: key("bomRef", native["BOMRef"]),
    nameVersion:
      text(name) &&
      text(version) &&
      JSON.stringify(["name-version", name, version, file]),
  };
}

type PackageIndex = Map<
  string,
  { pkg: NativeRecord; keys: ReturnType<typeof packageKeys> } | null
>;

function indexPackages(packages: unknown): PackageIndex {
  const index: PackageIndex = new Map();
  for (const value of array(packages ?? [], "Trivy Packages")) {
    const pkg = record(value, "Trivy package");
    const keys = packageKeys(
      pkg["ID"],
      pkg["Identifier"],
      pkg["Name"],
      pkg["Version"],
      pkg["FilePath"],
    );
    const match = { pkg, keys };
    for (const key of Object.values(keys))
      if (key) index.set(key, index.has(key) ? null : match);
  }
  return index;
}

function matchingPackage(vulnerability: NativeRecord, index: PackageIndex) {
  const keys = packageKeys(
    vulnerability["PkgID"],
    vulnerability["PkgIdentifier"],
    vulnerability["PkgName"],
    vulnerability["InstalledVersion"],
    vulnerability["PkgPath"],
  );
  const supplied = (["uid", "id", "purl", "bomRef"] as const).filter(
    (field) => keys[field],
  );
  for (const field of supplied.length ? supplied : (["nameVersion"] as const)) {
    const key = keys[field];
    const match = key && index.get(key);
    if (
      match &&
      agreesWhenPresent(vulnerability["PkgName"], match.pkg["Name"]) &&
      agreesWhenPresent(
        vulnerability["InstalledVersion"],
        match.pkg["Version"],
      ) &&
      supplied.every((id) => !match.keys[id] || keys[id] === match.keys[id])
    )
      return match.pkg;
  }
  return null;
}

function agreesWhenPresent(detected: unknown, inventoried: unknown): boolean {
  return !text(detected) || !text(inventoried) || detected === inventoried;
}

interface Entry {
  result: { Target?: string; Type: string; Class: string };
  packages: PackageIndex;
  value: unknown;
}

function occurrence(entry: Entry | string, root: string) {
  if (typeof entry === "string") throw new Error(entry);
  const vulnerability = record(entry.value, "Trivy vulnerability");
  const { Target, Type } = entry.result;
  return {
    ...entry,
    vulnerability,
    advisory: requiredText(
      vulnerability["VulnerabilityID"],
      "Trivy VulnerabilityID",
    ),
    name: requiredText(vulnerability["PkgName"], "Trivy PkgName"),
    pkgPath: text(vulnerability["PkgPath"]),
    targetPath:
      aggregateTargets.get(Type) === Target ? null : scopedPath(root, Target),
    packagePath: scopedPath(root, vulnerability["PkgPath"]),
  };
}

/** Import native Trivy dependency occurrences. Local scans require their checkout-relative
 * scan root. The package ecosystem is the PURL type when supplied, otherwise the analyzer. */
export function normalizeTrivyFindings(
  input: unknown,
  target: ExternalImportTarget = "cloud",
  scanRoot?: string,
): ExternalFindings {
  const document = record(input, "Trivy report");
  if (document["SchemaVersion"] !== 2)
    throw new Error(
      "Expected a native Trivy JSON report with SchemaVersion 2.",
    );
  if (
    document["ArtifactType"] !== "repository" &&
    document["ArtifactType"] !== "filesystem"
  )
    throw new Error(
      "Only Trivy repository and filesystem reports are supported.",
    );
  const metadata = record(document["Metadata"] ?? {}, "Trivy Metadata");
  const { urls } = trivyReportRemotes(document);
  const report = {
    ...pick(document, headerFields),
    ...(isRecord(document["Trivy"])
      ? { Trivy: pick(document["Trivy"], ["Version"]) }
      : {}),
    ...(typeof document["ArtifactName"] === "string"
      ? { ArtifactName: document["ArtifactName"] }
      : {}),
    Metadata: pick(metadata, ["RepoURL", "Branch", "Commit"]),
  };
  // A scan root requires corroboration. Explicit-root readers can inspect a report
  // whose declarations still have to agree with the destination at import.
  const root = resolveScanRoot(scanRoot, matchingTrivyRemotes(urls));

  const entries: (Entry | string)[] = [];
  for (const group of array(document["Results"] ?? [], "Trivy Results")) {
    const result = record(group, "Trivy result");
    if (result["Class"] !== "lang-pkgs") {
      entries.push(
        `Unsupported Trivy result class: ${text(result["Class"]) ?? "(missing)"}. Only lang-pkgs vulnerabilities are imported.`,
      );
      continue;
    }
    for (const field of [
      "Misconfigurations",
      "Secrets",
      "Licenses",
      "CryptoAssets",
      "CustomResources",
      "ExperimentalModifiedFindings",
    ])
      if (array(result[field] ?? [], `Trivy ${field}`).length)
        entries.push(`Unsupported Trivy ${field} in lang-pkgs result.`);

    const vulnerabilities = array(
      result["Vulnerabilities"] ?? [],
      "Trivy Vulnerabilities",
    );
    if (!vulnerabilities.length) continue;
    const reportedTarget = result["Target"];
    if (reportedTarget != null && typeof reportedTarget !== "string")
      throw new Error("Trivy result Target must be text.");
    const context = {
      ...(reportedTarget == null ? {} : { Target: reportedTarget }),
      Type: requiredText(result["Type"], "Trivy result Type"),
      Class: result["Class"],
    };
    const packages = indexPackages(result["Packages"]);
    for (const value of vulnerabilities)
      entries.push({ result: context, packages, value });
  }

  const findings = normalizeRecords(
    entries,
    (entry) => {
      const {
        result,
        packages,
        vulnerability,
        advisory,
        name,
        targetPath,
        pkgPath,
        packagePath,
      } = occurrence(entry, root);
      const identifier = vulnerability["PkgIdentifier"];
      const purl = isRecord(identifier) ? text(identifier["PURL"]) : null;
      const ecosystem =
        purl?.match(/^pkg:([a-z][a-z\d.+-]*)\//iu)?.[1]?.toLowerCase() ??
        result.Type;
      const pkg = matchingPackage(vulnerability, packages);
      const manifest = nonManifestTypes.has(result.Type) ? null : targetPath;
      // Trivy uses the same spelling for archive members and files in exploded archives.
      let declaration = pkgPath ? packagePath : manifest;
      if (
        result.Type === "jar" &&
        pkgPath !== null &&
        javaArchiveAncestor.test(pkgPath) &&
        /\.(?:jar|ear|war)$/u.test(pkgPath)
      )
        declaration = null;
      const locations: { path: string; line: number | null }[] = [];
      if (targetPath && targetPath !== declaration)
        locations.push({ path: targetPath, line: null });
      if (declaration) {
        const lines = new Set<number>();
        for (const range of array(
          pkg?.["Locations"] ?? [],
          "Trivy package Locations",
        )) {
          const start = isRecord(range) && range["StartLine"];
          if (
            typeof start === "number" &&
            Number.isSafeInteger(start) &&
            start > 0
          )
            lines.add(start);
        }
        if (!lines.size) locations.push({ path: declaration, line: null });
        for (const line of lines) locations.push({ path: declaration, line });
      }
      const severity = text(vulnerability["Severity"])?.toLowerCase();
      return validateExternalEvidence(
        {
          title: text(vulnerability["Title"]) ?? `${advisory} in ${name}`,
          severity:
            severity && ["critical", "high", "medium", "low"].includes(severity)
              ? severity
              : "unknown",
          description: text(vulnerability["Description"]),
          url: text(vulnerability["PrimaryURL"]),
          advisory_ids: [
            ...new Set([advisory, ...strings(vulnerability["VendorIDs"])]),
          ],
          packages: [
            {
              name,
              ecosystem,
              manifest_path: manifest,
              installed_version: text(vulnerability["InstalledVersion"]),
              fixed_versions:
                text(vulnerability["FixedVersion"])
                  ?.split(",")
                  .map((version) => version.trim())
                  .filter(Boolean) ?? [],
            },
          ],
          locations,
          branch: text(metadata["Branch"]),
          source_scan_id: text(document["ReportID"]),
          source_data: structuredClone({
            scanRoot: root,
            report,
            result,
            vulnerability,
            ...(pkg
              ? {
                  package: pick(pkg, [
                    "ID",
                    "Name",
                    "Version",
                    "Identifier",
                    "FilePath",
                    "Relationship",
                    "Locations",
                  ]),
                }
              : {}),
          }),
        },
        target,
      );
    },
    (entry) => {
      const { result, advisory, name, pkgPath, targetPath, packagePath } =
        occurrence(entry, root);
      const manifest = targetPath ?? text(result.Target);
      const concretePath = packagePath ?? pkgPath;
      return stableId("trivy", [
        result.Type,
        manifest,
        advisory,
        name,
        concretePath === manifest ? null : concretePath,
        ...(!targetPath && !packagePath && root !== "." ? [root] : []),
      ]);
    },
    target,
  );
  if (!findings.findings.length) findings.report = report;
  return findings;
}

export async function readTrivyFindings(
  path: string,
  target: ExternalImportTarget = "cloud",
  scanRoot?: string,
): Promise<ExternalFindings> {
  return normalizeTrivyFindings(await readScannerJson(path), target, scanRoot);
}
