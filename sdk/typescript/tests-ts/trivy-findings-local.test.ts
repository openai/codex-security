import { expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import {
  listLocalExternalFindings,
  normalizeTrivyFindings,
  prepareLocalExternalImport,
  prepareNormalizedLocalImport,
} from "../src/index.js";
import type { ExternalFindings } from "../src/external-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { git } from "./git-fixture.js";
import {
  trivyReport,
  trivyRepositoryHeader,
} from "./support/trivy-import-fixtures.js";

const checkoutUrl = "https://github.com/example/project";
const foreignUrl = "https://github.com/example/other";
const enterpriseUrl = "https://git.example.test/Example/Project";
const enterpriseHttp = enterpriseUrl.replace("https:", "http:");
const singleSuffix = `${enterpriseUrl.toLowerCase()}.git`;
const doubleSuffix = `${singleSuffix}.git`;
const enterpriseSsh = "git@git.example.test:example/project.git";
const mismatch = "does not match a configured remote";
const ambiguousSsh = /Trivy omitted the SSH user/u;

function repositoryClaims(artifactName: string, repoUrl: string) {
  return { ArtifactName: artifactName, Metadata: { RepoURL: repoUrl } };
}

async function trivyCheckout(remote?: string, githubSource?: string) {
  const fixture = await localFindingsFixture({ remote });
  const options = {
    provider: "trivy" as const,
    repository: fixture.repository,
    sourceKey: "example/project/main",
  };
  const deps = {
    environment: fixture.environment,
    sourceRepositories: githubSource
      ? [{ url: githubSource, platform: "github" as const }]
      : [],
  };
  const file = join(fixture.root, "trivy.json");
  const prepare = (input: ExternalFindings, repository = fixture.repository) =>
    prepareNormalizedLocalImport(input, { ...options, repository }, deps);
  return {
    [Symbol.asyncDispose]: fixture.dispose,
    repository: fixture.repository,
    prepare,
    async fromFile(report: unknown) {
      await writeFile(file, JSON.stringify(report));
      return prepareLocalExternalImport(
        file,
        { ...options, trivyScanRoot: "." },
        deps,
      );
    },
    async fromNormalized(report: unknown) {
      return prepare(normalizeTrivyFindings(report, "local", "."));
    },
    list: () => listLocalExternalFindings(options, deps),
  };
}

test("normalized Trivy headers reject credentials before local or Cloud preparation", async () => {
  const input = normalizeTrivyFindings(trivyReport(), "local", ".");
  const options = {
    provider: "trivy" as const,
    repository: "repo-example",
    sourceKey: "example/project/main",
  };
  await expect(
    prepareNormalizedLocalImport(input, {
      ...options,
      sourceRepositoryUrl: foreignUrl,
    }),
  ).rejects.toThrow("--source-repository-url");
  input.report = trivyRepositoryHeader(
    "https://scanner:fixture@github.com/example/other",
  );
  const error = "without credentials";
  await using local = await trivyCheckout(checkoutUrl);
  await expect(local.prepare(input)).rejects.toThrow(error);
  await expect(
    prepareNormalizedExternalPublication(input, options, {
      credentials: async () => {
        throw new Error("Unexpected Cloud authentication");
      },
    }),
  ).rejects.toThrow(error);
});

const mixedScheme = checkoutUrl.replace("https:", "HTTPS:");
const localMirror = "file:///synthetic/mirror";
const differentRepositories = "identify different repositories";
const excludedGroups = [{ Class: "os-pkgs" }];
const artifactOnly = (ArtifactName: string) => ({ ArtifactName, Metadata: {} });

test.each([
  [{}, foreignUrl, mismatch],
  [{ Results: excludedGroups }, foreignUrl, mismatch],
  [repositoryClaims(".", mixedScheme), mixedScheme, null],
  [artifactOnly(mixedScheme), mixedScheme, "mixed-case HTTP target"],
  [artifactOnly(foreignUrl), checkoutUrl, mismatch],
  [{ ArtifactName: foreignUrl }, localMirror, differentRepositories],
  [
    repositoryClaims(enterpriseUrl.toLowerCase(), enterpriseSsh),
    undefined,
    differentRepositories,
  ],
  [
    repositoryClaims(enterpriseUrl, enterpriseUrl.toLowerCase()),
    enterpriseUrl,
    differentRepositories,
  ],
  [
    repositoryClaims(enterpriseHttp, enterpriseHttp.toLowerCase() + ".git"),
    undefined,
    differentRepositories,
  ],
  [
    {
      ...repositoryClaims(
        ".",
        "ssh://git@ssh.github.com:443/example/project.git",
      ),
      Results: excludedGroups,
    },
    checkoutUrl,
    null,
  ],
  [artifactOnly(checkoutUrl), checkoutUrl, null],
  [
    { ...artifactOnly(foreignUrl), ArtifactType: "filesystem" },
    checkoutUrl,
    null,
  ],
  [repositoryClaims("C:\\ci\\checkout", "D:mirror.git"), checkoutUrl, null],
  [{ Metadata: {} }, foreignUrl, null],
  [{}, localMirror, null],
] as const)(
  "checks report header %j against remote %s even with no accepted findings",
  async (overrides, remote, error) => {
    await using checkout = await trivyCheckout(remote);
    const report = { ...trivyReport(), Results: [], ...overrides };
    for (const prepare of [checkout.fromFile, checkout.fromNormalized]) {
      const pending = prepare(report);
      if (error) await expect(pending).rejects.toThrow(error);
      else {
        const { preview } = await pending;
        expect(preview.findings).toEqual([]);
        expect(preview.excluded).toHaveLength(report.Results.length);
      }
    }
  },
);

test.each([
  [singleSuffix, enterpriseUrl, "different repositories"],
  [
    singleSuffix.replace("https:", "http:"),
    enterpriseHttp,
    "different repositories",
  ],
  [
    "ssh://git.example.test/example/project",
    "ssh://git@git.example.test/example/project",
    ambiguousSsh,
  ],
  [
    "ssh://git.example.test/example/other",
    "ssh://git@git.example.test/example/other",
    ambiguousSsh,
  ],
  [
    "ssh://git.example.test/example/project",
    "ssh://other@git.example.test/example/project",
    ambiguousSsh,
  ],
] as const)(
  "a local GitHub source hint rejects conflicting report %s and artifact %s",
  async (remote, artifact, error) => {
    const scheme = remote.startsWith("http:") ? "http" : "https";
    const url = `${scheme}://git.example.test/example/project`;
    await using checkout = await trivyCheckout(url, url);
    const report = { ...trivyReport(), ...repositoryClaims(artifact, remote) };
    for (const prepare of [checkout.fromNormalized, checkout.fromFile])
      await expect(prepare(report)).rejects.toThrow(error);
  },
);

test("a reader's GitHub web hint cannot change the meaning of the raw Trivy transport", async () => {
  const web = "HTTPS://github.com/example/project";
  await using checkout = await trivyCheckout(checkoutUrl, web);
  for (const raw of [checkoutUrl, web]) {
    const { findings, read, excluded } = normalizeTrivyFindings(
      { ...trivyReport(), ArtifactName: ".", Metadata: { RepoURL: raw } },
      "local",
      ".",
    );
    findings[0]!.evidence.details = { kind: "sast", repository: { url: web } };
    const pending = checkout.prepare({ findings, read, excluded });
    if (raw === checkoutUrl)
      expect((await pending).preview.findings).toHaveLength(1);
    else await expect(pending).rejects.toThrow("different repositories");
  }
});

test("an unbound local Trivy import keeps a standalone typed repository link", async () => {
  await using checkout = await trivyCheckout();
  const report = { ...trivyReport(), ...repositoryClaims(".", "") };
  const input = normalizeTrivyFindings(report, "local", ".");
  const finding = input.findings[0]!;
  finding.evidence.details = {
    kind: "sast",
    repository: { url: "https://example.test/team/archive/../project" },
  };
  expect((await checkout.prepare(input)).preview.findings).toEqual([finding]);
});

test("Trivy treats an explicit curl helper argument as a URL", async () => {
  await using checkout = await trivyCheckout("https::" + mixedScheme);
  expect(
    (await checkout.fromNormalized(trivyReport())).preview.findings,
  ).toHaveLength(1);
  const report = trivyReport();
  report.Metadata.RepoURL = mixedScheme;
  await expect(checkout.fromNormalized(report)).rejects.toThrow(mismatch);
});

test("Trivy can match a checkout with an unrelated malformed remote", async () => {
  await using checkout = await trivyCheckout(checkoutUrl);
  git(checkout.repository, "remote", "add", "broken", "https://[invalid");
  const prepared = await checkout.fromNormalized(trivyReport());
  expect(prepared.preview.findings).toHaveLength(1);
});

test("Trivy preserves Unicode path bytes in GitHub report and typed repository claims", async () => {
  const ascii = "https://github.com/example/Kit";
  const unicode = "https://github.com/example/Kit";
  const encoded = "https://github.com/example/%E2%84%AAit";
  const report = {
    ...trivyReport(),
    ArtifactName: ".",
    Metadata: { RepoURL: unicode },
  };
  await using different = await trivyCheckout(ascii);
  await expect(different.fromFile(report)).rejects.toThrow(mismatch);
  const input = normalizeTrivyFindings(report, "local", ".");
  const finding = input.findings[0]!;
  finding.evidence.details = { kind: "sast", repository: { url: ascii } };
  await expect(different.prepare(input)).rejects.toThrow(
    "different repositories",
  );
  finding.evidence.details.repository = { url: encoded };
  await using same = await trivyCheckout(encoded);
  expect((await same.prepare(input)).preview.findings).toHaveLength(1);
});

test("a reader-declared Trivy source must agree with the finding even when both are checkout remotes", async () => {
  await using checkout = await trivyCheckout(checkoutUrl, foreignUrl);
  git(checkout.repository, "remote", "add", "upstream", foreignUrl);
  await expect(checkout.fromNormalized(trivyReport())).rejects.toThrow(
    "different repositories",
  );
});

test("selected and stored Trivy findings retain their artifact-only checkout binding", async () => {
  await using source = await trivyCheckout(checkoutUrl);
  await using other = await trivyCheckout(foreignUrl);
  const artifact = "ssh://git@github.com/example/project.git";
  const report = trivyReport();
  report.Results.push({
    ...report.Results[0]!,
    Target: "nested/package-lock.json",
  });
  const input = normalizeTrivyFindings(
    { ...report, ArtifactName: artifact, Metadata: {} },
    "local",
    ".",
  );
  const prepared = await source.prepare(input);
  const reloaded = JSON.parse(JSON.stringify(prepared.preview));
  await prepared.import();
  const stored = await source.list();
  expect(stored).toHaveLength(2);
  const record = stored[0]!;
  expect(record.evidence.source_data).toMatchObject({
    report: { ArtifactName: artifact },
  });
  const storedFinding = {
    source_finding_id: record.sourceFindingId,
    evidence: record.evidence,
  };
  for (const selected of [
    reloaded,
    { read: 1, findings: [input.findings[0]!], excluded: [] },
    { read: 1, findings: [storedFinding], excluded: [] },
  ])
    await expect(source.prepare(selected, other.repository)).rejects.toThrow(
      mismatch,
    );
});

test("Trivy import preserves the occurrence across revisions without assessing it", async () => {
  await using checkout = await trivyCheckout(
    "git@github.com:example/project.git",
  );
  const report = trivyReport();
  const prepare = () => checkout.fromFile(report);
  const preview = await prepare();
  expect(preview.preview.excluded).toEqual([]);
  expect(await checkout.list()).toEqual([]);
  expect((await preview.import()).counts.created).toBe(1);
  expect((await (await prepare()).import()).counts.unchanged).toBe(1);

  const updatedCommit = "b".repeat(40);
  report.Metadata.Commit = updatedCommit;
  expect((await (await prepare()).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 0,
  });
  const stored = await checkout.list();
  expect(stored).toHaveLength(1);
  expect(stored[0]).toMatchObject({
    provider: "trivy",
    sourceFindingId: preview.preview.findings[0]!.source_finding_id,
    version: 2,
    evidence: {
      code_revision: null,
      source_data: { report: { Metadata: { Commit: updatedCommit } } },
    },
    assessment: { state: "not_assessed" },
  });
});

test("local Trivy paths use the checkout root even without a report remote", async () => {
  await using checkout = await trivyCheckout();
  const nested = join(checkout.repository, "apps", "web");
  await mkdir(nested, { recursive: true });
  const findings = normalizeTrivyFindings(
    { ...trivyReport(), Metadata: {} },
    "local",
    "apps/web",
  );
  await expect(checkout.prepare(findings, nested)).rejects.toThrow(
    `Git found the checkout at ${JSON.stringify(checkout.repository)}.`,
  );
  await expect(
    checkout.prepare(findings, join(checkout.repository, ".git", "objects")),
  ).rejects.toThrow("must be run in a work tree");
  const { preview } = await checkout.prepare(findings);
  expect(
    join(preview.repository, preview.findings[0]!.evidence.locations![0]!.path),
  ).toBe(join(nested, "package-lock.json"));
});

test("Trivy distinguishes a differently cased checkout alias from a separate directory", async () => {
  await using checkout = await trivyCheckout();
  const alternate = join(dirname(checkout.repository), "REPOSITORY");
  const created = await mkdir(alternate, { recursive: true });
  git(checkout.repository, "config", "core.worktree", alternate);
  const prepared = checkout.fromNormalized(trivyReport());
  if (created)
    await expect(prepared).rejects.toThrow(
      "Trivy finding paths are checkout-relative",
    );
  else expect((await prepared).preview.findings).toHaveLength(1);
});

test.each([
  [foreignUrl, checkoutUrl, undefined, "."],
  [enterpriseUrl, enterpriseSsh, enterpriseUrl, "."],
  [doubleSuffix, singleSuffix, doubleSuffix, doubleSuffix],
  [singleSuffix, singleSuffix, doubleSuffix, "."],
] as const)(
  "normalized Trivy report %s, finding %s and reader hint %s must agree",
  async (reportUrl, findingUrl, githubSource, artifact) => {
    await using checkout = await trivyCheckout(undefined, githubSource);
    const plainDirectory = join(dirname(checkout.repository), "unpacked");
    await mkdir(plainDirectory);
    const input = normalizeTrivyFindings(
      { ...trivyReport(), ...repositoryClaims(artifact, findingUrl) },
      "local",
      ".",
    );
    input.report = trivyRepositoryHeader(reportUrl);
    const reject = (repository: string) =>
      expect(checkout.prepare(input, repository)).rejects.toThrow(
        "different repositories",
      );
    await reject(plainDirectory);
    await reject(checkout.repository);
    const origin = githubSource ?? reportUrl;
    git(checkout.repository, "remote", "add", "origin", origin);
    git(checkout.repository, "remote", "add", "upstream", findingUrl);
    await reject(checkout.repository);
  },
);

const aliasWeb = "https://work/team/project";
const aliasScp = "git@work:team/project.git";
const aliasSsh = "ssh://git@work/team/project.git";
const githubScp = "git@github.com:example/project.git";
const noUser = "ssh://github.com/example/project";
const hostedTenant = "ssh://tenant.ghe.com/team/project";
const isWindows = process.platform === "win32";
const loginEnterprise =
  "https://checkout-user@git.example.test/Example/Project";
const sshAlias = "ssh://git@github.com/example/project";
const httpsLogin = "https://user@github.com/example/";

test.each([
  // Each remote must agree with the source, including when the reader supplies a GitHub hint.
  [checkoutUrl, foreignUrl, true, mismatch],
  [checkoutUrl, githubScp, true, null],
  [aliasScp, aliasWeb, true, mismatch],
  [aliasWeb, aliasScp, true, mismatch],
  [aliasWeb, aliasSsh, true, mismatch],
  [aliasScp, aliasScp, true, null],
  [aliasSsh, aliasSsh, true, null],
  [aliasWeb, aliasWeb, true, null],
  [enterpriseHttp, enterpriseHttp, true, null],
  [doubleSuffix, doubleSuffix, true, null],
  [enterpriseUrl, loginEnterprise, true, mismatch],
  [enterpriseUrl, loginEnterprise, false, mismatch],
  [enterpriseUrl, enterpriseUrl.toLowerCase(), true, mismatch],
  [enterpriseUrl, enterpriseUrl.toLowerCase(), false, mismatch],
  ["git@host:/org/repo", "git@host:org/repo", false, mismatch],
  ["alice@host:project", "bob@host:project", true, mismatch],
  ["alice@host:repo.git", "alice@host:repo", true, mismatch],
  [githubScp, sshAlias + "?", true, mismatch],
  [checkoutUrl, "g:team/two", false, isWindows ? null : mismatch],
  [checkoutUrl, "g:/srv/other.git", false, isWindows ? null : mismatch],
  [
    "ssh://g/srv/project.git",
    "g:/srv/other.git",
    false,
    isWindows ? null : ambiguousSsh,
  ],
  ["user@g:team/one", "user@g:team/two", false, mismatch],
  [noUser, githubScp, false, ambiguousSsh],
  [
    hostedTenant,
    "ssh://tenant@tenant.ghe.com/team/project",
    false,
    ambiguousSsh,
  ],
  [
    hostedTenant,
    "ssh://other@tenant.ghe.com/team/project",
    false,
    ambiguousSsh,
  ],
  [checkoutUrl, httpsLogin + "project.git", false, null],
  [checkoutUrl, httpsLogin + "other.git", false, mismatch],
  [checkoutUrl, "https://a@b@github.com/example/project.git", false, mismatch],
  [checkoutUrl, noUser, false, mismatch],
  [checkoutUrl, sshAlias, false, null],
  [checkoutUrl, "SSH://github.com/example/project", false, mismatch],
  [checkoutUrl, mixedScheme, false, mismatch],
  [checkoutUrl, "git+" + sshAlias + ".git", false, null],
  [checkoutUrl, sshAlias.replace("ssh:", "ssh+git:") + ".git", false, null],
] as const)(
  "checks source %s against checkout %s (GitHub hint %j)",
  async (source, remote, githubHint, error) => {
    await using checkout = await trivyCheckout(
      remote,
      githubHint ? source : undefined,
    );
    const report = { ...trivyReport(), ...repositoryClaims(".", source) };
    const prepared = checkout.fromFile(report);
    if (error) await expect(prepared).rejects.toThrow(error);
    else expect((await prepared).preview.findings).toHaveLength(1);
  },
);

test.each([
  { ArtifactName: checkoutUrl.replace("https:", "HTTPS:"), Metadata: {} },
  {
    ArtifactName: ".",
    Metadata: { RepoURL: "ssh://github.com/example/project" },
  },
  repositoryClaims(
    "ssh://alice@source.example/team/project",
    "ssh://source.example/team/project",
  ),
])(
  "unresolved Git transport can be retained in an unverified local import",
  async (source) => {
    await using checkout = await trivyCheckout("file:///local/fixture.git");
    const unpacked = join(dirname(checkout.repository), "unpacked");
    await mkdir(unpacked);
    const report = { ...trivyReport(), ...source };
    const { findings, read, excluded } = normalizeTrivyFindings(
      report,
      "local",
      ".",
    );
    const stored = await checkout.prepare(
      { findings, read, excluded },
      unpacked,
    );
    expect(stored.preview.findings).toEqual(findings);
    expect((await checkout.fromFile(report)).preview.findings).toEqual(
      findings,
    );
  },
);

test.each([
  "ssh://alice@elsewhere.example/team/unrelated",
  "ssh://alice@source.example/team/unrelated",
])(
  "an omitted SSH user cannot explain the conflicting Trivy target %s",
  async (artifact) => {
    await using checkout = await trivyCheckout();
    const report = {
      ...trivyReport(),
      ...repositoryClaims(artifact, "ssh://source.example/team/project"),
    };
    expect(() => normalizeTrivyFindings(report)).toThrow("--trivy-scan-root");
    const { read, excluded, findings } = normalizeTrivyFindings(
      report,
      "local",
      ".",
    );
    for (const prepare of [
      () => checkout.fromFile(report),
      () => checkout.prepare({ read, excluded, findings }),
    ])
      await expect(prepare()).rejects.toThrow("different repositories");
  },
);
