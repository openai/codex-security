import {
  snapshotSourceRepositories,
  type ExternalSourceRepository,
} from "./external-findings.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  hostedScannerToken,
  hostedRepositoryUrl,
  hostedScannerHttp,
  type HostedScannerHttpOptions,
} from "./hosted-scanner-http.js";
import {
  checkSemgrepPlatformRow,
  projectAliases,
  responseRecord,
  semgrepPlatformFormat,
  selectionRepository,
  semgrepNativeProjectUrl,
  semgrepPlatformId,
  semgrepPlatformIdOrUndefined,
  SEMGREP_PLATFORM_PRODUCTS,
  type SemgrepPlatformProduct,
  type SemgrepPlatformScope,
} from "./semgrep-platform-findings.js";
import { array, requiredText, stableId, text } from "./scanner-import.js";

export { SEMGREP_PLATFORM_PRODUCTS };

export interface SemgrepPlatformOptions {
  deployment: string;
  project: string;
  ref: string;
  product?: SemgrepPlatformProduct;
  sourceRepositoryUrl?: string;
  sourceRepositories?: readonly ExternalSourceRepository[];
  token?: string;
  signal?: AbortSignal;
}

export interface SemgrepPlatformReport extends SemgrepPlatformScope {
  format: typeof semgrepPlatformFormat;
  findingCount: number;
  findings: string[];
  repositoryAliases: string[];
}

export async function collectSemgrepPlatformFindings(
  options: SemgrepPlatformOptions,
  dependencies: HostedScannerHttpOptions = {},
): Promise<SemgrepPlatformReport> {
  const environment = dependencies.environment ?? process.env;
  requireExternalImports(environment);
  const token = requiredText(
    hostedScannerToken(
      environment,
      "SEMGREP_APP_TOKEN",
      options.token,
      "https://semgrep.dev",
      "SEMGREP_URL",
      "SEMGREP_APP_URL",
    ),
    "Semgrep Web API token (SEMGREP_APP_TOKEN)",
  );
  const { getJson, signal } = hostedScannerHttp(dependencies, options.signal);
  const deployment = requiredText(options.deployment, "Semgrep deployment");
  const name = requiredText(options.project, "Semgrep project name");
  if (
    deployment.includes("/") ||
    [deployment, name].some((part) => part === "." || part === "..")
  )
    throw new Error("Invalid Semgrep deployment slug or project name.");
  const ref = requiredText(options.ref, "Semgrep ref");
  const { sourceRepositoryUrl } = options;
  const sourceRepositories = snapshotSourceRepositories(
    options.sourceRepositories,
  );
  const product = options.product ?? "sast";
  if (!SEMGREP_PLATFORM_PRODUCTS.includes(product))
    throw new Error("Select a Semgrep Platform product: sast, sca or ai_sast.");

  const base = `https://semgrep.dev/api/v1/deployments/${encodeURIComponent(deployment)}`;
  const get = async (url: URL) =>
    responseRecord(
      await getJson(url, `Bearer ${token}`),
      "Semgrep API response",
    );
  const lookup = await get(
    new URL(`${base}/projects/${encodeURIComponent(name)}`),
  );
  const native = responseRecord(lookup["project"], "Semgrep project");
  if (native["name"] !== name)
    throw new Error("Semgrep returned a different project than requested.");
  const nativeUrl = semgrepNativeProjectUrl(native["url"], sourceRepositories);
  const mappedUrl = hostedRepositoryUrl(
    sourceRepositoryUrl ?? nativeUrl,
    "Semgrep project repository",
  );
  const url = nativeUrl ?? mappedUrl;
  const source = selectionRepository(url, sourceRepositories);
  if (source.key(mappedUrl) !== source.key(url))
    throw new Error(
      "Semgrep project does not match the selected source repository URL.",
    );
  const project = { id: semgrepPlatformId(native["id"]), name, url };
  const scope = { deployment, project, ref, product };
  const endpoint = new URL(`${base}/findings`);
  const pageSize = 3000;
  endpoint.search = new URLSearchParams({
    repository_ids: project.id,
    issue_type: product,
    ref,
    dedup: "false",
    page_size: String(pageSize),
  }).toString();
  const names = projectAliases(name, url, sourceRepositories);
  const witnessed = new Set<string>();
  const verified = {
    has: (label: string) => names.has(label) || witnessed.has(label),
  };
  const observed = new Set<string>();
  async function readPage(page: number, collecting = true) {
    endpoint.searchParams.set("page", String(page));
    const document = await get(new URL(endpoint));
    return array(document["findings"], "Semgrep findings").map((entry) => {
      const finding = responseRecord(entry, "Semgrep finding");
      const repository = responseRecord(
        finding["repository"] ?? {},
        "Semgrep finding repository",
      );
      const label = text(repository["name"]);
      if (collecting && label) observed.add(label);
      checkSemgrepPlatformRow(
        finding,
        scope,
        collecting ? observed : verified,
        source,
      );
      if (
        collecting &&
        label &&
        (repository["id"] != null || text(repository["url"]))
      )
        witnessed.add(label);
      const raw = JSON.stringify(finding);
      return { key: semgrepPlatformIdOrUndefined(finding["id"]) ?? raw, raw };
    });
  }

  const pageId = (batch: Awaited<ReturnType<typeof readPage>>) =>
    stableId("page", batch.map((row) => row.key).sort());
  const findings: string[] = [];
  const previousKeys = new Set<string>();
  let firstPage: string | undefined;
  for (let page = 0; ; page++) {
    const batch = await readPage(page);
    // Compare only with prior pages; same-page ambiguities are reported per finding on import.
    if (batch.some((row) => previousKeys.has(row.key)))
      throw new Error(
        "Semgrep Platform repeated findings across pages; retry the collection.",
      );
    for (const row of batch) findings.push(row.raw);
    if (batch.length < pageSize) break;
    for (const row of batch) previousKeys.add(row.key);
    if (page === 0) firstPage = pageId(batch);
  }
  // A name-only finding can precede the row that binds this label to the project.
  for (const label of observed) {
    if (!verified.has(label))
      throw new Error(
        `Semgrep finding repository name "${label}" has no matching project name, repository ID or URL.`,
      );
  }
  // Offset pagination can skip a row if the first page changes between reads.
  if (firstPage && firstPage !== pageId(await readPage(0, false)))
    throw new Error(
      "Semgrep Platform findings changed across pages; retry the collection.",
    );
  signal?.throwIfAborted();
  return {
    format: semgrepPlatformFormat,
    ...scope,
    repositoryAliases: [...observed].sort(),
    findingCount: findings.length,
    findings,
  };
}
