import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";
import { assertExpectedGitHead } from "./package-provenance.mjs";

const packageName = "@openai/codex-security";
const stableVersion = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const provenancePredicate = "https://slsa.dev/provenance/v1";
const publicNpmRegistry = "https://registry.npmjs.org/";
const githubActionsOidcIssuer = "https://token.actions.githubusercontent.com";
const fulcioExtensionPrefix = Buffer.from("2b0601040183bf3001", "hex");
const releaseSummaryStart = "<!-- codex-security-release-summary:start -->";
const releaseSummaryEnd = "<!-- codex-security-release-summary:end -->";

function stableReleaseTagVersion(tag) {
  if (typeof tag !== "string" || !tag.startsWith("npm-v")) {
    throw new Error("Release tags must identify a stable npm-vX.Y.Z version.");
  }

  const version = tag.slice("npm-v".length);
  if (!stableVersion.test(version)) {
    throw new Error("Release tags must identify a stable npm-vX.Y.Z version.");
  }
  return version;
}

export function assertStableVersion(version) {
  if (typeof version !== "string" || !stableVersion.test(version)) {
    throw new Error("Release package must have a stable X.Y.Z version.");
  }
  return version;
}

export function releaseVersion(packageJson) {
  if (packageJson?.name !== packageName) {
    throw new Error("Release package must be @openai/codex-security.");
  }
  return assertStableVersion(packageJson.version);
}

function hasReviewedText(value) {
  return !value.includes("\0") && /\S/u.test(value);
}

export function parseReviewedReleaseNotes(version, notes) {
  const expectedHeader = `<!-- release-version: ${version} -->`;
  const normalized =
    typeof notes === "string" ? notes.replace(/\n+$/u, "") : "";
  const firstNewline = normalized.indexOf("\n");
  const summary = normalized.slice(firstNewline + 1);
  if (
    firstNewline === -1 ||
    normalized.slice(0, firstNewline) !== expectedHeader ||
    !hasReviewedText(summary)
  ) {
    throw new Error(
      `Release notes must start with ${expectedHeader} and include a reviewed summary.`,
    );
  }
  return summary;
}

export function extractHistoricalReleaseSummary(notes) {
  if (typeof notes !== "string") {
    throw new Error("Existing release notes must be a string.");
  }

  const markers = [...notes.matchAll(/^[^\r\n]+$/gmu)].filter(
    ([line]) => line === releaseSummaryStart || line === releaseSummaryEnd,
  );
  if (markers.length === 0 || markers[0]?.index !== 0) return null;

  const [startMarker, endMarker] = markers;
  if (
    markers.length !== 2 ||
    startMarker?.[0] !== releaseSummaryStart ||
    endMarker?.[0] !== releaseSummaryEnd
  ) {
    throw new Error("Existing release summary markers are malformed.");
  }

  const remainder = notes.slice(endMarker.index + endMarker[0].length);
  if (remainder !== "" && !/^(?:\r?\n){2}/u.test(remainder)) {
    throw new Error("Existing release summary markers are malformed.");
  }

  const summary = notes
    .slice(startMarker.index + startMarker[0].length, endMarker.index)
    .replace(/^\r?\n/u, "")
    .replace(/\r?\n$/u, "");
  if (!hasReviewedText(summary)) {
    throw new Error("Existing release summary is empty.");
  }
  return summary;
}

export function resolveReleaseSummary(version, taggedNotes, existingNotes) {
  if (taggedNotes !== undefined) {
    return parseReviewedReleaseNotes(version, taggedNotes);
  }
  if (existingNotes === undefined || existingNotes.length === 0) {
    return null;
  }
  return extractHistoricalReleaseSummary(existingNotes);
}

export function composeReleaseNotes(generatedNotes, releaseSummary) {
  if (releaseSummary === null || releaseSummary === "") {
    return generatedNotes;
  }
  return [
    releaseSummaryStart,
    releaseSummary,
    releaseSummaryEnd,
    "",
    generatedNotes,
  ].join("\n");
}

function releaseNoteFileArguments(args) {
  const files = {};
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const file = args[index + 1];
    if (
      file === undefined ||
      (option !== "--tagged-notes-file" &&
        option !== "--existing-notes-file") ||
      files[option] !== undefined
    ) {
      throw new Error("Invalid release note file arguments.");
    }
    files[option] = file;
  }
  return files;
}

export function releaseTagVersion(refType, ref, refName, packageJson) {
  if (refType !== "tag" || ref !== `refs/tags/${refName}`) {
    throw new Error("npm releases must be dispatched from a real Git tag.");
  }

  const tagVersion = stableReleaseTagVersion(refName);
  const packageVersion = releaseVersion(packageJson);
  if (tagVersion !== packageVersion) {
    throw new Error("npm release tag must match the stable package version.");
  }

  return packageVersion;
}

export function compareReleaseVersions(left, right) {
  if (!stableVersion.test(left) || !stableVersion.test(right)) {
    throw new Error("Release versions must use stable X.Y.Z versions.");
  }

  const leftParts = left.split(".").map(BigInt);
  const rightParts = right.split(".").map(BigInt);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] > rightParts[index]) return 1;
    if (leftParts[index] < rightParts[index]) return -1;
  }
  return 0;
}

export function requireReleaseIncrease(version, previousVersion) {
  if (compareReleaseVersions(version, previousVersion) <= 0) {
    throw new Error(
      "Release version must be greater than the previous stable version.",
    );
  }
  return version;
}

export function initialPublishedVersions(version, registryError) {
  releaseVersion({ name: packageName, version });
  if (version !== "0.1.0" || registryError?.error?.code !== "E404") {
    throw new Error("Unable to verify published npm release history.");
  }
  return [];
}

export function publishedReleaseMode(version, publishedVersions) {
  releaseVersion({ name: packageName, version });
  if (!Array.isArray(publishedVersions)) {
    throw new Error("Published npm release versions must be an array.");
  }

  let mode = "publish";
  for (const publishedVersion of publishedVersions) {
    if (
      typeof publishedVersion === "string" &&
      stableVersion.test(publishedVersion)
    ) {
      const comparison = compareReleaseVersions(version, publishedVersion);
      if (comparison < 0) {
        throw new Error(
          "Release version must be greater than every published stable version.",
        );
      }
      if (comparison === 0) mode = "recover";
    }
  }

  return mode;
}

export function requirePublishedReleaseIncrease(version, publishedVersions) {
  if (publishedReleaseMode(version, publishedVersions) !== "publish") {
    throw new Error(
      "Release version must be greater than every published stable version.",
    );
  }

  return version;
}

function invalidSigningCertificate() {
  return new Error("The verified Fulcio signing certificate is invalid.");
}

function derElement(bytes, offset, limit = bytes.length) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + 2 > limit) {
    throw invalidSigningCertificate();
  }

  let cursor = offset;
  const tag = bytes[cursor++];
  if ((tag & 0x1f) === 0x1f) {
    throw invalidSigningCertificate();
  }

  let length = bytes[cursor++];
  if ((length & 0x80) !== 0) {
    const count = length & 0x7f;
    if (
      count === 0 ||
      count > 4 ||
      cursor + count > limit ||
      bytes[cursor] === 0
    ) {
      throw invalidSigningCertificate();
    }

    length = 0;
    for (let index = 0; index < count; index += 1) {
      length = length * 256 + bytes[cursor++];
    }
    if (length < 128) {
      throw invalidSigningCertificate();
    }
  }

  if (length > limit - cursor) {
    throw invalidSigningCertificate();
  }

  return { tag, start: cursor, end: cursor + length };
}

function derChildren(bytes, element) {
  const children = [];
  let cursor = element.start;
  while (cursor < element.end) {
    const child = derElement(bytes, cursor, element.end);
    children.push(child);
    cursor = child.end;
  }
  return children;
}

function fulcioCertificateExtensions(bytes) {
  const root = derElement(bytes, 0);
  if (root.tag !== 0x30 || root.end !== bytes.length) {
    throw invalidSigningCertificate();
  }

  const [tbsCertificate] = derChildren(bytes, root);
  if (tbsCertificate?.tag !== 0x30) {
    throw invalidSigningCertificate();
  }

  const wrappers = derChildren(bytes, tbsCertificate).filter(
    (element) => element.tag === 0xa3,
  );
  if (wrappers.length !== 1) {
    throw invalidSigningCertificate();
  }

  const [extensionSequence, unexpected] = derChildren(bytes, wrappers[0]);
  if (extensionSequence?.tag !== 0x30 || unexpected !== undefined) {
    throw invalidSigningCertificate();
  }

  const extensions = new Map();
  for (const extension of derChildren(bytes, extensionSequence)) {
    if (extension.tag !== 0x30) {
      throw invalidSigningCertificate();
    }

    const fields = derChildren(bytes, extension);
    if (
      (fields.length !== 2 && fields.length !== 3) ||
      fields[0].tag !== 0x06 ||
      (fields.length === 3 && fields[1].tag !== 0x01) ||
      fields.at(-1).tag !== 0x04
    ) {
      throw invalidSigningCertificate();
    }

    const oid = bytes.subarray(fields[0].start, fields[0].end);
    if (
      oid.length !== fulcioExtensionPrefix.length + 1 ||
      !oid
        .subarray(0, fulcioExtensionPrefix.length)
        .equals(fulcioExtensionPrefix)
    ) {
      continue;
    }

    const identifier = oid.at(-1);
    if (extensions.has(identifier)) {
      throw invalidSigningCertificate();
    }

    const field = fields.at(-1);
    const value = bytes.subarray(field.start, field.end);
    if (identifier >= 8) {
      const text = derElement(value, 0);
      if (text.tag !== 0x0c || text.end !== value.length) {
        throw invalidSigningCertificate();
      }
      extensions.set(
        identifier,
        value.subarray(text.start, text.end).toString("utf8"),
      );
    } else {
      extensions.set(identifier, value.toString("utf8"));
    }
  }

  return extensions;
}

function verifySigningCertificate(bundle, expected) {
  const material = bundle?.verificationMaterial;
  const encoded =
    material?.certificate?.rawBytes ??
    material?.x509CertificateChain?.certificates?.[0]?.rawBytes;

  let certificate;
  let extensions;
  try {
    if (typeof encoded !== "string" || encoded.length === 0) {
      throw invalidSigningCertificate();
    }
    const raw = Buffer.from(encoded, "base64");
    if (raw.toString("base64") !== encoded) {
      throw invalidSigningCertificate();
    }
    certificate = new X509Certificate(raw);
    extensions = fulcioCertificateExtensions(certificate.raw);
  } catch {
    throw invalidSigningCertificate();
  }

  const issuerV1 = extensions.get(1);
  const issuerV2 = extensions.get(8);
  if (
    (issuerV1 === undefined && issuerV2 === undefined) ||
    (issuerV1 !== undefined && issuerV1 !== githubActionsOidcIssuer) ||
    (issuerV2 !== undefined && issuerV2 !== githubActionsOidcIssuer)
  ) {
    throw new Error(
      "The Fulcio certificate must use the GitHub Actions OIDC issuer.",
    );
  }

  const workflowIdentity =
    `${expected.repository}/.github/workflows/node-release.yml@` +
    expected.releaseRef;
  if (
    certificate.subjectAltName !== `URI:${workflowIdentity}` ||
    extensions.get(9) !== workflowIdentity ||
    extensions.get(18) !== workflowIdentity ||
    extensions.get(12) !== expected.repository ||
    extensions.get(14) !== expected.releaseRef
  ) {
    throw new Error(
      "The Fulcio certificate must identify the protected release workflow.",
    );
  }

  if (
    extensions.get(10) !== expected.gitHead ||
    extensions.get(13) !== expected.gitHead ||
    extensions.get(19) !== expected.gitHead
  ) {
    throw new Error(
      "The Fulcio certificate must identify the exact release commit.",
    );
  }

  if (extensions.get(11) !== "github-hosted") {
    throw new Error(
      "The Fulcio certificate must identify a GitHub-hosted release runner.",
    );
  }

  const runPrefix = `${expected.repository}/actions/runs/${expected.runId}/attempts/`;
  const certificateRun = extensions.get(21);
  if (
    typeof certificateRun !== "string" ||
    !certificateRun.startsWith(runPrefix) ||
    !/^[1-9][0-9]*$/u.test(certificateRun.slice(runPrefix.length))
  ) {
    throw new Error(
      "The Fulcio certificate must identify the exact release run.",
    );
  }

  if (
    extensions.get(23) !== "npm" ||
    extensions.get(24) !==
      `repo:${expected.repository.slice("https://github.com/".length)}:environment:npm`
  ) {
    throw new Error(
      "The Fulcio certificate must identify the protected npm environment.",
    );
  }
}

export function releaseHistory(tag, history) {
  const version = stableReleaseTagVersion(tag);
  if (
    !Array.isArray(history?.registryVersions) ||
    !Array.isArray(history.githubReleaseTags) ||
    !Array.isArray(history.reachableTags)
  ) {
    throw new Error(
      "Release history must contain published and reachable tags.",
    );
  }

  const publishedVersions = new Set(
    history.registryVersions.filter(
      (candidate) =>
        typeof candidate === "string" && stableVersion.test(candidate),
    ),
  );
  const publishedGitHubTags = new Set(
    history.githubReleaseTags.filter(
      (candidate) =>
        typeof candidate === "string" &&
        candidate.startsWith("npm-v") &&
        stableVersion.test(candidate.slice("npm-v".length)),
    ),
  );

  let previousTag = null;
  for (const candidate of history.reachableTags) {
    if (
      typeof candidate !== "string" ||
      !candidate.startsWith("npm-v") ||
      !stableVersion.test(candidate.slice("npm-v".length))
    ) {
      continue;
    }

    const candidateVersion = candidate.slice("npm-v".length);
    if (
      compareReleaseVersions(candidateVersion, version) >= 0 ||
      (!publishedVersions.has(candidateVersion) &&
        !publishedGitHubTags.has(candidate))
    ) {
      continue;
    }

    if (
      previousTag === null ||
      compareReleaseVersions(
        candidateVersion,
        previousTag.slice("npm-v".length),
      ) > 0
    ) {
      previousTag = candidate;
    }
  }

  const makeLatest =
    Array.from(publishedVersions).every(
      (candidate) => compareReleaseVersions(version, candidate) >= 0,
    ) &&
    Array.from(publishedGitHubTags).every(
      (candidate) =>
        compareReleaseVersions(version, candidate.slice("npm-v".length)) >= 0,
    );

  return { previousTag, makeLatest };
}

export function verifyPublishedRelease(metadata, archive, expected) {
  const version = releaseVersion(metadata);
  if (version !== expected.version) {
    throw new Error("Published npm package must match the release version.");
  }

  assertExpectedGitHead(metadata, expected.gitHead);

  const integrity = metadata["dist.integrity"] ?? metadata.dist?.integrity;
  const expectedIntegrity =
    "sha512-" + createHash("sha512").update(archive).digest("base64");
  if (integrity !== expectedIntegrity) {
    throw new Error(
      "Published npm integrity must match the verified release artifact.",
    );
  }

  const attestations =
    metadata["dist.attestations"] ?? metadata.dist?.attestations;
  if (attestations?.provenance?.predicateType !== provenancePredicate) {
    throw new Error("Published npm package must have SLSA v1 provenance.");
  }

  return {
    version,
    gitHead: expected.gitHead,
    integrity: expectedIntegrity,
    sha256: createHash("sha256").update(archive).digest("hex"),
  };
}

export function verifyGitHubPublishedRelease(
  metadata,
  archive,
  expected,
  provenance,
) {
  const version = releaseVersion(metadata);
  const sha512 = createHash("sha512").update(archive).digest("hex");
  if (
    provenance?.version !== version ||
    provenance.gitHead !== expected.gitHead ||
    provenance.repository !== expected.repository ||
    provenance.runId !== String(expected.runId) ||
    provenance.sha512 !== sha512
  ) {
    throw new Error(
      "Verified signed npm provenance must match the GitHub release.",
    );
  }

  if (metadata.gitHead === undefined) {
    if (version !== "0.1.0" && version !== "0.1.1") {
      throw new Error("Only npm releases 0.1.0 and 0.1.1 may omit gitHead.");
    }
    metadata = { ...metadata, gitHead: provenance.gitHead };
  }

  return verifyPublishedRelease(metadata, archive, expected);
}

export function verifySignatureAudit(report, archive, expected) {
  if (
    !Array.isArray(report?.invalid) ||
    !Array.isArray(report.missing) ||
    !Array.isArray(report.verified) ||
    report.invalid.length !== 0 ||
    report.missing.length !== 0
  ) {
    throw new Error("npm registry signatures and attestations must verify.");
  }

  const version = releaseVersion({
    name: packageName,
    version: expected.version,
  });
  const verified = report.verified.find(
    (candidate) =>
      candidate?.name === packageName && candidate.version === version,
  );
  if (verified === undefined) {
    throw new Error(
      "The published package must have a cryptographically verified attestation.",
    );
  }

  let registry;
  try {
    registry = new URL(verified.registry).href;
  } catch {
    throw new Error(
      "Verified provenance must come from the public npm registry.",
    );
  }
  if (registry !== publicNpmRegistry) {
    throw new Error(
      "Verified provenance must come from the public npm registry.",
    );
  }

  if (
    verified.attestations?.provenance?.predicateType !== provenancePredicate
  ) {
    throw new Error("The verified npm package must have SLSA v1 provenance.");
  }

  const provenance = Array.isArray(verified.attestationBundles)
    ? verified.attestationBundles.find(
        (candidate) => candidate?.predicateType === provenancePredicate,
      )
    : undefined;
  const encodedStatement = provenance?.bundle?.dsseEnvelope?.payload;
  if (typeof encodedStatement !== "string") {
    throw new Error("The verified SLSA provenance bundle is missing.");
  }

  let statement;
  try {
    statement = JSON.parse(
      Buffer.from(encodedStatement, "base64").toString("utf8"),
    );
  } catch {
    throw new Error("The verified SLSA provenance statement is invalid.");
  }
  if (
    statement?._type !== "https://in-toto.io/Statement/v1" ||
    statement.predicateType !== provenancePredicate
  ) {
    throw new Error("The verified SLSA provenance statement is invalid.");
  }

  const sha512 = createHash("sha512").update(archive).digest("hex");
  const expectedSubject = `pkg:npm/%40openai/codex-security@${version}`;
  if (
    !Array.isArray(statement.subject) ||
    !statement.subject.some(
      (subject) =>
        subject?.name === expectedSubject && subject.digest?.sha512 === sha512,
    )
  ) {
    throw new Error(
      "Verified SLSA provenance must identify the exact published tarball.",
    );
  }

  if (
    typeof expected.repository !== "string" ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(expected.repository)
  ) {
    throw new Error("Verified provenance requires an exact GitHub repository.");
  }
  const repository = `https://github.com/${expected.repository}`;
  const releaseRef = `refs/tags/npm-v${version}`;
  const build = statement.predicate?.buildDefinition;
  const workflow = build?.externalParameters?.workflow;
  if (
    workflow?.repository !== repository ||
    workflow.ref !== releaseRef ||
    workflow.path !== ".github/workflows/node-release.yml"
  ) {
    throw new Error(
      "Verified SLSA provenance must identify the protected release workflow.",
    );
  }

  const sourceUri = `git+${repository}@${releaseRef}`;
  const source = build.resolvedDependencies?.find(
    (dependency) => dependency?.uri === sourceUri,
  );
  if (source === undefined) {
    throw new Error(
      "Verified SLSA provenance must identify the exact release source.",
    );
  }
  assertExpectedGitHead(
    { gitHead: source.digest?.gitCommit },
    expected.gitHead,
  );

  const runId = String(expected.runId);
  if (!/^[1-9][0-9]*$/u.test(runId)) {
    throw new Error(
      "Verified provenance requires a valid release workflow run.",
    );
  }
  const invocation = statement.predicate?.runDetails?.metadata?.invocationId;
  const invocationPrefix = `${repository}/actions/runs/${runId}/attempts/`;
  if (
    typeof invocation !== "string" ||
    !invocation.startsWith(invocationPrefix) ||
    !/^[1-9][0-9]*$/u.test(invocation.slice(invocationPrefix.length))
  ) {
    throw new Error(
      "Verified SLSA provenance must identify the successful release run.",
    );
  }

  if (
    statement.predicate?.runDetails?.builder?.id !==
    "https://github.com/actions/runner/github-hosted"
  ) {
    throw new Error(
      "Verified SLSA provenance must use a GitHub-hosted release runner.",
    );
  }

  verifySigningCertificate(provenance.bundle, {
    repository,
    releaseRef,
    gitHead: expected.gitHead,
    runId,
  });

  return {
    version,
    gitHead: expected.gitHead,
    repository: expected.repository,
    runId,
    sha512,
  };
}

export function verifyRecoveredSignatureAudit(report, archive, expected) {
  const version = releaseVersion({
    name: packageName,
    version: expected.version,
  });
  if (
    typeof expected.repository !== "string" ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(expected.repository)
  ) {
    throw new Error("Verified provenance requires an exact GitHub repository.");
  }

  const verified = Array.isArray(report?.verified)
    ? report.verified.find(
        (candidate) =>
          candidate?.name === packageName && candidate.version === version,
      )
    : undefined;
  if (verified === undefined) {
    throw new Error(
      "The published package must have a cryptographically verified attestation.",
    );
  }

  const provenance = Array.isArray(verified.attestationBundles)
    ? verified.attestationBundles.find(
        (candidate) => candidate?.predicateType === provenancePredicate,
      )
    : undefined;
  const encodedStatement = provenance?.bundle?.dsseEnvelope?.payload;
  if (typeof encodedStatement !== "string") {
    throw new Error("The verified SLSA provenance bundle is missing.");
  }

  let statement;
  try {
    statement = JSON.parse(
      Buffer.from(encodedStatement, "base64").toString("utf8"),
    );
  } catch {
    throw new Error("The verified SLSA provenance statement is invalid.");
  }

  const prefix = `https://github.com/${expected.repository}/actions/runs/`;
  const invocation = statement?.predicate?.runDetails?.metadata?.invocationId;
  if (typeof invocation !== "string" || !invocation.startsWith(prefix)) {
    throw new Error(
      "Verified SLSA provenance must identify the protected release run.",
    );
  }
  const match = /^([1-9][0-9]*)\/attempts\/([1-9][0-9]*)$/u.exec(
    invocation.slice(prefix.length),
  );
  if (match === null) {
    throw new Error(
      "Verified SLSA provenance must identify the protected release run.",
    );
  }

  return verifySignatureAudit(report, archive, {
    ...expected,
    version,
    runId: match[1],
  });
}

export function verifyGitHubRelease(
  release,
  archive,
  expectedTag,
  assetName,
  downloadedArchive,
) {
  if (release?.tag_name !== expectedTag) {
    throw new Error("Existing GitHub Release must match the release tag.");
  }
  if (release.draft !== false || release.prerelease !== false) {
    throw new Error("Existing GitHub Release must be published and stable.");
  }

  const expectedDigest =
    "sha256:" + createHash("sha256").update(archive).digest("hex");
  const asset = Array.isArray(release.assets)
    ? release.assets.find((candidate) => candidate?.name === assetName)
    : undefined;
  const publishedDigest = asset?.digest;
  const downloadedDigest =
    downloadedArchive === undefined
      ? undefined
      : "sha256:" +
        createHash("sha256").update(downloadedArchive).digest("hex");
  if (
    asset === undefined ||
    (publishedDigest != null && publishedDigest !== expectedDigest) ||
    (downloadedArchive === undefined && publishedDigest !== expectedDigest) ||
    (downloadedArchive !== undefined && downloadedDigest !== expectedDigest)
  ) {
    throw new Error(
      "Existing GitHub Release asset must match the verified npm artifact.",
    );
  }

  return {
    tag: expectedTag,
    asset: assetName,
    digest: expectedDigest,
  };
}

function main() {
  const command = process.argv[2];

  if (command === "version" && process.argv.length === 4) {
    const packageJson = JSON.parse(readFileSync(process.argv[3], "utf8"));
    console.log(releaseVersion(packageJson));
    return;
  }

  if (command === "release-tag" && process.argv.length === 7) {
    const packageJson = JSON.parse(readFileSync(process.argv[6], "utf8"));
    console.log(
      releaseTagVersion(
        process.argv[3],
        process.argv[4],
        process.argv[5],
        packageJson,
      ),
    );
    return;
  }

  if (command === "require-increase" && process.argv.length === 5) {
    console.log(requireReleaseIncrease(process.argv[3], process.argv[4]));
    return;
  }

  if (command === "initial-published-versions" && process.argv.length === 4) {
    const registryError = JSON.parse(readFileSync(0, "utf8"));
    console.log(
      JSON.stringify(initialPublishedVersions(process.argv[3], registryError)),
    );
    return;
  }

  if (command === "require-published-increase" && process.argv.length === 4) {
    const publishedVersions = JSON.parse(readFileSync(0, "utf8"));
    console.log(
      requirePublishedReleaseIncrease(process.argv[3], publishedVersions),
    );
    return;
  }

  if (command === "release-mode" && process.argv.length === 4) {
    const publishedVersions = JSON.parse(readFileSync(0, "utf8"));
    console.log(publishedReleaseMode(process.argv[3], publishedVersions));
    return;
  }

  if (command === "validate-release-notes" && process.argv.length === 5) {
    const notes = readFileSync(process.argv[4], "utf8");
    process.stdout.write(parseReviewedReleaseNotes(process.argv[3], notes));
    return;
  }

  if (command === "compose-release-notes" && process.argv.length >= 5) {
    const version = process.argv[3];
    const generatedNotes = readFileSync(process.argv[4], "utf8");
    const normalizedGeneratedNotes = generatedNotes.replace(/(?:\r?\n)+$/u, "");
    if (normalizedGeneratedNotes.length === 0) {
      throw new Error("Generated GitHub release notes must not be empty.");
    }
    const files = releaseNoteFileArguments(process.argv.slice(5));
    const taggedNotes =
      files["--tagged-notes-file"] === undefined
        ? undefined
        : readFileSync(files["--tagged-notes-file"], "utf8");
    const existingNotes =
      files["--existing-notes-file"] === undefined
        ? undefined
        : readFileSync(files["--existing-notes-file"], "utf8");
    const summary = resolveReleaseSummary(version, taggedNotes, existingNotes);
    process.stdout.write(
      composeReleaseNotes(normalizedGeneratedNotes, summary),
    );
    return;
  }

  if (command === "release-history" && process.argv.length === 4) {
    const registryVersions = JSON.parse(
      process.env.CODEX_SECURITY_PUBLISHED_NPM_VERSIONS ?? "[]",
    );
    const githubReleaseTags = (
      process.env.CODEX_SECURITY_PUBLISHED_GITHUB_TAGS ?? ""
    )
      .split("\n")
      .filter(Boolean);
    const reachableTags = (
      process.env.CODEX_SECURITY_REACHABLE_RELEASE_TAGS ?? ""
    )
      .split("\n")
      .filter(Boolean);
    console.log(
      JSON.stringify(
        releaseHistory(process.argv[3], {
          registryVersions,
          githubReleaseTags,
          reachableTags,
        }),
      ),
    );
    return;
  }

  if (command === "verify-publication" && process.argv.length === 6) {
    const metadata = JSON.parse(readFileSync(0, "utf8"));
    const archive = readFileSync(process.argv[3]);
    const verified = verifyPublishedRelease(metadata, archive, {
      version: process.argv[4],
      gitHead: process.argv[5],
    });
    console.log(JSON.stringify(verified));
    return;
  }

  if (command === "verify-github-publication" && process.argv.length === 8) {
    const metadata = JSON.parse(readFileSync(0, "utf8"));
    const archive = readFileSync(process.argv[3]);
    const provenance = JSON.parse(
      process.env.CODEX_SECURITY_VERIFIED_PROVENANCE ?? "null",
    );
    const verified = verifyGitHubPublishedRelease(
      metadata,
      archive,
      {
        version: process.argv[4],
        gitHead: process.argv[5],
        repository: process.argv[6],
        runId: process.argv[7],
      },
      provenance,
    );
    console.log(JSON.stringify(verified));
    return;
  }

  if (command === "verify-provenance" && process.argv.length === 8) {
    const report = JSON.parse(readFileSync(0, "utf8"));
    const archive = readFileSync(process.argv[3]);
    const verified = verifySignatureAudit(report, archive, {
      version: process.argv[4],
      gitHead: process.argv[5],
      repository: process.argv[6],
      runId: process.argv[7],
    });
    console.log(JSON.stringify(verified));
    return;
  }

  if (command === "verify-recovered-provenance" && process.argv.length === 7) {
    const report = JSON.parse(readFileSync(0, "utf8"));
    const archive = readFileSync(process.argv[3]);
    const verified = verifyRecoveredSignatureAudit(report, archive, {
      version: process.argv[4],
      gitHead: process.argv[5],
      repository: process.argv[6],
    });
    console.log(JSON.stringify(verified));
    return;
  }

  if (
    command === "verify-github-release" &&
    (process.argv.length === 5 || process.argv.length === 6)
  ) {
    const release = JSON.parse(readFileSync(0, "utf8"));
    const archivePath = process.argv[3];
    const archive = readFileSync(archivePath);
    const verified = verifyGitHubRelease(
      release,
      archive,
      process.argv[4],
      basename(archivePath),
      process.argv[5] === undefined ? undefined : readFileSync(process.argv[5]),
    );
    console.log(JSON.stringify(verified));
    return;
  }

  throw new Error(
    "Usage: release-automation.mjs version <package.json>, " +
      "release-tag <ref-type> <ref> <ref-name> <package.json>, " +
      "require-increase <version> <previous-version>, " +
      "initial-published-versions <version> " +
      "(npm registry error JSON from stdin), " +
      "require-published-increase <version> " +
      "(published npm versions JSON from stdin), " +
      "release-mode <version> (published npm versions JSON from stdin), " +
      "validate-release-notes <version> <release-notes-file>, " +
      "compose-release-notes <version> <generated-notes-file> " +
      "[--tagged-notes-file <file>] " +
      "[--existing-notes-file <file>], " +
      "release-history <tag>, " +
      "verify-publication <archive> <version> <git-head> " +
      "(package metadata JSON from stdin), " +
      "verify-github-publication <archive> <version> <git-head> " +
      "<repository> <run-id> (package metadata JSON from stdin and " +
      "verified provenance from CODEX_SECURITY_VERIFIED_PROVENANCE), " +
      "verify-provenance <archive> <version> <git-head> <repository> <run-id> " +
      "(signature audit JSON from stdin), " +
      "verify-recovered-provenance <archive> <version> <git-head> " +
      "<repository> (signature audit JSON from stdin), or " +
      "verify-github-release <archive> <tag> [downloaded-asset] " +
      "(GitHub release JSON from stdin).",
  );
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main();
}
