import { hash } from "node:crypto";
import { lstat } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { resolveConfigPath } from "./config-path.js";
import { collectSonarIssues } from "./sonar-collector.js";
import { normalizeSonarFindings, parseSonarCapture } from "./sonar-findings.js";
import { requireExternalImports } from "./external-imports-feature.js";
import {
  localGitProtectionRoots,
  prepareLocalImport,
} from "./external-findings-local.js";
import {
  ExternalPublicationError,
  externalPublicationStateDirectory,
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
  requirePrivateDirectory,
  requireSecureOutputAncestry,
  requireOutputOutsideRepositories,
} from "./runtime.js";
import { gitMarkerRoot, normalizeRepository } from "./targets.js";
import { errorMessage } from "./errors.js";
import { canonicalJson } from "./record.js";
import { validateExternalReport } from "./external-import-contract.js";
import { notify } from "./value.js";

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
          item.expected_version,
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
  const input =
    options.capture && resolveConfigPath(options.cwd, options.capture);
  const raw = input
    ? await readScannerJson(input)
    : await (dependencies.collect ?? collectSonarIssues)({
        cwd: options.cwd,
        project: options.project,
        sourceRepositoryUrl: options.sourceRepositoryUrl,
        branch: options.branch,
        pullRequest: options.pullRequest,
        issueKeys: options.issueKeys.length ? options.issueKeys : undefined,
        environment,
        signal,
      });
  let report = parseSonarCapture(raw);
  validateExternalReport(report);
  const configuredState = codexSecurityStateDirectory(environment);
  const protectedRoots = [
    repository,
    ...(await localGitProtectionRoots(options.cwd, environment, signal)),
    ...(await localGitProtectionRoots(process.cwd(), environment, signal)),
  ];
  requireOutputOutsideRepositories(protectedRoots, configuredState, "runtime");
  const state = await canonicalConfigPath(configuredState);
  const destination = await canonicalConfigPath(
    join(state, "imports", "sonar"),
  );
  requireOutputOutsideRepositories(protectedRoots, state, "runtime");
  requireOutputOutsideRepositories(protectedRoots, destination, "runtime");
  await requireSecureOutputAncestry(destination);
  const root = await preparePersistentOutputRoot(state, "imports", "sonar");
  await requirePrivateDirectory(
    await lstat(root),
    root,
    "Sonar capture directory",
  );
  const retained =
    input && dirname(input) === root
      ? /^([a-f0-9]{64})(?:\.([a-f0-9]{64})(?:\.([a-f0-9]{64}))?)?\.json$/u.exec(
          basename(input),
        )
      : undefined;
  if (retained && hash("sha256", JSON.stringify(raw)) !== retained[1])
    throw new Error(
      "The saved Sonar capture has changed. Preview a fresh copy of the Sonar evidence.",
    );
  if (!report.repositoryUrl && options.sourceRepositoryUrl) {
    report = parseSonarCapture({
      ...report,
      repositoryUrl: declaredScannerRepositoryUrl(
        options.sourceRepositoryUrl,
        "Sonar",
        "local",
      ),
    });
  }
  const evidenceDigest = hash("sha256", JSON.stringify(report));
  const checkout = hash("sha256", repository);
  const localCapture = join(root, `${evidenceDigest}.${checkout}.json`);
  if (
    options.to === "local" &&
    options.yes &&
    !options.dryRun &&
    retained &&
    retained[2] !== checkout
  ) {
    throw new Error(
      "This Sonar capture has not been reviewed for this checkout. Run import sonar with this capture and --dry-run here, then confirm the returned capture.",
    );
  }
  let capture =
    options.to === "cloud" &&
    input &&
    retained?.[1] === evidenceDigest &&
    retained?.[2] === checkout
      ? input
      : localCapture;
  if (capture !== input) await writeAtomicJson(capture, report);
  try {
    const repositoryUrl = report.repositoryUrl ?? options.sourceRepositoryUrl;
    if (!repositoryUrl) {
      throw new Error(
        "Sonar did not supply a repository binding. Verify the project's repository and rerun with the saved capture and --source-repository-url.",
      );
    }
    const findings = normalizeSonarFindings(
      report,
      options.sourceRepositoryUrl ?? "",
      "local",
    );
    const { branch, pullRequest } = findings.report;
    const sourceKey = stableId("sonar", [
      report.server,
      report.organization,
      report.project,
      branch ?? null,
      pullRequest ?? null,
    ]);
    const source = { provider: "sonar", sourceKey } as const;
    const local = await prepareLocalImport(
      findings,
      { repository, ...source },
      { environment, signal },
      [{ url: repositoryUrl }],
    );
    let cloud: PreparedExternalPublication | undefined;
    let cloudError: string | undefined;
    if (options.to === "cloud" && local.preview.read > 0) {
      const reviewedCheckout =
        retained?.[2] === checkout && Boolean(retained?.[3]);
      const reviewError =
        "Cloud publication requires the reviewed capture for this checkout, account, repository and environment. Run import sonar with this capture and --to cloud --dry-run, then pass the returned capture path with --to cloud --yes.";
      if (options.yes && !options.dryRun && !reviewedCheckout)
        throw new Error(reviewError);
      try {
        requireOutputOutsideRepositories(
          protectedRoots,
          await canonicalConfigPath(
            externalPublicationStateDirectory(environment),
          ),
          "runtime",
        );
        const confirmedRepository =
          local.matchesRepositoryRemote || options.sourceRepositoryUrl;
        const bindingError =
          "This checkout has no matching Git remote. Verify the Sonar project's repository and pass --source-repository-url to preview Cloud publication.";
        if (!confirmedRepository && !reviewedCheckout)
          throw new Error(bindingError);
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
        const reviewedCapture = join(
          root,
          `${evidenceDigest}.${checkout}.${review}.json`,
        );
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
    const info = {
      capture,
      repository,
      repositoryUrl,
      sourceKey,
      server: report.server,
      organization: report.organization,
      project: report.project,
      branch,
      pullRequest,
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
  } finally {
    notify(() => dependencies.onCapture?.(capture));
  }
}
