import { hash } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import { collectSonarIssues } from "./sonar-collector.js";
import { normalizeSonarFindings, parseSonarCapture } from "./sonar-findings.js";
import { requireExternalImports } from "./external-imports-feature.js";
import { prepareLocalImport } from "./external-findings-local.js";
import {
  ExternalPublicationError,
  prepareNormalizedExternalPublication,
  writeAtomicJson,
  type ExternalPublicationDependencies,
  type ExternalPublicationPreview,
  type PreparedExternalPublication,
} from "./external-findings-publish.js";
import { readScannerJson, stableId } from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import {
  canonicalConfigPath,
  codexSecurityStateDirectory,
  preparePersistentOutputRoot,
  requireOutputOutsideRepositories,
} from "./runtime.js";
import {
  gitMarkerRoot,
  gitProtectionRoots,
  normalizeRepository,
} from "./targets.js";
import { errorMessage } from "./errors.js";
import { canonicalJson } from "./record.js";

interface SonarImportOptions {
  cwd: string;
  capture?: string | undefined;
  project?: string | undefined;
  branch?: string | undefined;
  pullRequest?: string | undefined;
  issueKeys: string[];
  sourceRepositoryUrl?: string | undefined;
  to: "local" | "cloud";
  dryRun: boolean;
  yes: boolean;
}

function cloudReviewDigest(
  preview: ExternalPublicationPreview,
  checkout: string,
) {
  return hash(
    "sha256",
    canonicalJson({
      checkout,
      api: preview.cloudApiUrl,
      account: preview.accountId,
      repository: preview.destination.id,
      connector: preview.destination.repo_connector_id,
      url: preview.destination.url,
      reset: preview.destination.reset_marker,
      source: preview.source,
      items: preview.requests.flatMap((request) =>
        request.items.map((item) => [
          item.source_finding_id,
          request.repository.environment_id,
          item.evidence,
        ]),
      ),
    }),
  );
}

export async function prepareSonarImport(
  options: SonarImportOptions,
  dependencies: ExternalPublicationDependencies & {
    collect?: typeof collectSonarIssues;
    onCapture?: (path: string) => void;
  },
) {
  const { signal, environment = process.env } = dependencies;
  requireExternalImports(environment);
  signal?.throwIfAborted();
  if (
    options.capture &&
    (options.project ||
      options.branch ||
      options.pullRequest ||
      options.issueKeys.length)
  )
    throw new Error(
      "A saved capture already identifies the selected Sonar project, ref and issues. Omit the live selection options.",
    );
  const repository =
    (await gitMarkerRoot(options.cwd, signal, "nearest")) ??
    (await normalizeRepository(options.cwd, signal));
  const input = options.capture && resolve(options.cwd, options.capture);
  const report = parseSonarCapture(
    input
      ? await readScannerJson(input)
      : await (dependencies.collect ?? collectSonarIssues)({
          cwd: options.cwd,
          project: options.project,
          branch: options.branch,
          pullRequest: options.pullRequest,
          issueKeys: options.issueKeys,
          environment,
          signal,
        }),
  );
  const state = await canonicalConfigPath(
    codexSecurityStateDirectory(environment),
  );
  requireOutputOutsideRepositories(
    [repository, ...(await gitProtectionRoots(options.cwd, signal))],
    state,
    "runtime",
  );
  const root = await preparePersistentOutputRoot(state, "imports", "sonar");
  const retained =
    input && dirname(input) === root
      ? /^([a-f0-9]{64})(?:\.([a-f0-9]{64}))?\.json$/u.exec(basename(input))
      : undefined;
  let evidenceDigest = hash("sha256", JSON.stringify(report));
  if (retained && evidenceDigest !== retained[1])
    throw new Error(
      "The saved Sonar capture has changed. Preview a fresh copy of the Sonar evidence.",
    );
  if (!report.repositoryUrl && options.sourceRepositoryUrl) {
    report.repositoryUrl = declaredScannerRepositoryUrl(
      options.sourceRepositoryUrl,
      "Sonar",
      "local",
    );
    evidenceDigest = hash("sha256", JSON.stringify(report));
  }
  let capture =
    input && retained?.[1] === evidenceDigest
      ? input
      : join(root, evidenceDigest + ".json");
  if (capture !== input) await writeAtomicJson(capture, report);
  const repositoryUrl = report.repositoryUrl ?? options.sourceRepositoryUrl;
  if (!repositoryUrl) {
    dependencies.onCapture?.(capture);
    throw new Error(
      "Sonar did not supply a repository binding. Verify the project's repository and rerun with the saved capture and --source-repository-url.",
    );
  }
  const sourceKey = stableId("sonar", [
    report.server,
    report.organization,
    report.project,
    report.branch ?? null,
    report.pullRequest ?? null,
  ]);
  const source = { provider: "sonar", sourceKey } as const;
  const local = await prepareLocalImport(
    normalizeSonarFindings(report, options.sourceRepositoryUrl ?? "", "local"),
    { repository, ...source },
    { environment, signal },
    [{ url: repositoryUrl }],
  );
  let cloud: PreparedExternalPublication | undefined;
  let cloudError: string | undefined;
  if (options.to === "cloud" && local.preview.read > 0) {
    try {
      const confirmedRepository =
        local.matchesRepositoryRemote || options.sourceRepositoryUrl;
      const bindingError =
        "This checkout has no matching Git remote. Verify the Sonar project's repository and pass --source-repository-url to preview Cloud publication.";
      if (!confirmedRepository && !retained?.[2]) throw new Error(bindingError);
      const reviewError =
        "Cloud publication requires the reviewed capture for this checkout, account, repository and environment. Run import sonar with this capture and --to cloud --dry-run, then pass the returned capture path with --to cloud --yes.";
      if (options.yes && !options.dryRun && !retained?.[2])
        throw new Error(reviewError);
      const prepared = await prepareNormalizedExternalPublication(
        normalizeSonarFindings(
          report,
          options.sourceRepositoryUrl ?? "",
          "cloud",
        ),
        { repository: repositoryUrl, ...source },
        dependencies,
      );
      const review = cloudReviewDigest(prepared.preview, repository);
      const reviewedCapture = join(root, `${evidenceDigest}.${review}.json`);
      if (input !== reviewedCapture) {
        if (!confirmedRepository) throw new Error(bindingError);
        if (options.yes && !options.dryRun) throw new Error(reviewError);
        await writeAtomicJson(reviewedCapture, report);
      }
      capture = reviewedCapture;
      cloud = prepared;
    } catch (error) {
      signal?.throwIfAborted();
      cloudError = errorMessage(error);
    }
  }
  dependencies.onCapture?.(capture);
  const info = {
    capture,
    repository,
    repositoryUrl,
    sourceKey,
    server: report.server,
    organization: report.organization,
    project: report.project,
    branch: report.branch,
    pullRequest: report.pullRequest,
  };
  return {
    info,
    local: local.preview,
    cloud: cloud?.preview,
    cloudError,
    async import() {
      signal?.throwIfAborted();
      const { counts, ready, excluded } = await local.import();
      const saved = { ...info, local: { counts, ready, excluded } };
      if (!cloud) return { ...saved, cloudError, cloud: undefined };
      try {
        return {
          ...saved,
          cloud: await cloud.publish(),
          cloudError: undefined,
        };
      } catch (error) {
        return {
          ...saved,
          cloudError: errorMessage(error),
          cloud:
            error instanceof ExternalPublicationError
              ? error.result
              : undefined,
        };
      }
    },
  };
}
