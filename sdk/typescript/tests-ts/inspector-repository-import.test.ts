import { expect, test } from "bun:test";
import { mkdtemp, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { gzipSync } from "node:zlib";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import type { ExternalFinding } from "../src/external-findings.js";
import { normalizeInspectorFindings } from "../src/inspector-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  inspectorPackageFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

async function checkout(
  remote = inspectorRepositoryUrl,
  source = inspectorRepositoryUrl,
) {
  const { root, repository, environment, git, dispose } =
    await localFindingsFixture({ remote });
  return {
    path: join(root, "inspector.json.gz"),
    options: {
      provider: "inspector" as const,
      sourceKey: "inspector/project",
      repository,
      sourceRepositoryUrl: source,
    },
    deps: { environment },
    git,
    [Symbol.asyncDispose]: dispose,
  };
}

function normalized(findings: ExternalFinding[]) {
  return { read: findings.length, excluded: [], findings };
}

test("Enterprise GitHub scope applies to raw and replayed rows with and without a provider", async () => {
  const url = "https://git.example.test/Example/Project";
  await using f = await checkout(
    "git@git.example.test:EXAMPLE/Project.git",
    url,
  );
  const known = inspectorPackageFinding();
  known.resources[0]!.details.codeRepository.projectName = url;
  const unknown = structuredClone(known);
  unknown.findingArn = unknown.findingArn.replace(/a$/u, "b");
  Reflect.deleteProperty(
    unknown.resources[0]!.details.codeRepository,
    "providerType",
  );
  await writeFile(
    f.path,
    gzipSync(JSON.stringify({ findings: [unknown, known] })),
  );
  const raw = await prepareLocalExternalImport(f.path, f.options, f.deps);
  const rows = raw.preview.findings;
  expect(rows).toHaveLength(2);
  rows[1]!.evidence.source_data!["sourceRepositoryUrl"] = url.toLowerCase();
  rows.push(typedRow("ssh://git@git.example.test/Example/Project.git"));
  const replay = () =>
    prepareNormalizedLocalImport(normalized(rows), f.options, f.deps);
  expect((await replay()).preview.findings).toHaveLength(3);

  unknown.resources[0]!.details.codeRepository.providerType =
    "GITLAB_SELF_MANAGED";
  rows[0] = normalizeInspectorFindings(
    { findings: [unknown] },
    url,
    "local",
  ).findings[0]!;
  await expect(replay()).rejects.toThrow(/project|provider|integration/i);
});

function typedRow(url: string): ExternalFinding {
  return {
    source_finding_id: "sdk-id",
    evidence: {
      title: "Alert",
      severity: "unknown",
      details: { kind: "sast", repository: { url } },
    },
  };
}

const home = "host.test/~/project";
const ssh = "ssh://git@github.com/example/project";
const bindings: [string, string, string?][] = [
  [
    "https://trusted.test\\@other.test/../team/repo",
    "https://trusted.test/team/repo",
  ],
  ["https://host.test/x/%2e%2e/team/repo", "https://host.test/team/repo"],
  [
    "https://host.test/previous/../team/./repo",
    "https://host.test/team/other",
    "https://host.test/team/repo",
  ],
  [" ssh://host.test/team/repo", "https://host.test/team/repo"],
  ["ssh://bad@host.test:invalid/team/repo", "https://host.test/team/repo"],
  ["ssh://other.test%2Fx@github.com/team/repo", "https://github.com/team/repo"],
  [
    "git@host.test:/srv/team/repo.git",
    "ssh://git@host.test/team/repo",
    "ssh://git@host.test/srv/team/repo.git",
  ],
  [
    "git@host.test:~/team/repo%20data",
    "ssh://git@host.test/~/team/repo%20data",
    "ssh://git@host.test/~/team/repo%2520data",
  ],
  [inspectorRepositoryUrl + "?repo=other", inspectorRepositoryUrl],
  [inspectorRepositoryUrl + "?", inspectorRepositoryUrl],
  [inspectorRepositoryUrl + "#", inspectorRepositoryUrl],
  [ssh + "?other", ssh + "?Other"],
  [ssh + "#blue", ssh + ".git#blue", ssh + "#blue.git"],
  ["git://github.com/example/project?other", inspectorRepositoryUrl],
  ["ssh://git@github.com/~/../example/project", inspectorRepositoryUrl],
  ["alice@host.test:team/project#other", "bob@host.test:team/project#other"],
  [
    "alice@host.test:team/project#demo",
    "ssh://alice@host.test/team/project#demo",
  ],
  [
    "git@github.com:example/project.git",
    "ssh://git@github.com/example/other",
    "ssh://git@ssh.github.com:443/example/project.git",
  ],
  [
    "example@example.ghe.com:team/project",
    "ssh://other@example.ghe.com/team/project",
    "ssh://example@example.ghe.com/team/project",
  ],
  ["alice@host.test:team/project", "ssh://bob@host.test/team/project"],
  [
    "ssh://alice@host.test/team/project",
    "ssh://bob@host.test/team/other",
    "ssh://bob@host.test/team/project",
  ],
  ["alice@host.test:D:/shared/project", "bob@host.test:D:/shared/project"],
  ["alice@host.test:/~/repo", "bob@host.test:/~/repo"],
  [`ssh://alice@${home}`, `ssh://bob@${home}`, `ssh://${home}`],
  ["ssh://alice@host.test/%7E%2F../repo", "ssh://bob@host.test/%7E%2F../repo"],
  [
    "café@host.test:~/repo",
    "caf%C3%A9@host.test:~/repo",
    "ssh://caf%C3%A9@host.test/~/repo",
  ],
  [
    "ssh://team:one@host.test/~/repo",
    "ssh://team:two@host.test/~/repo",
    "ssh://team%3Aone@host.test/~/repo",
  ],
  [
    "ssh://u%00%23v@host.test/~/repo#x",
    "ssh://u@host.test/~/repo#v%00%23x",
    "ssh://u%2500%23v@host.test/~/repo#x",
  ],
];
test.each(
  bindings.map(
    ([remote, other, equivalent = remote]) =>
      [remote, other, equivalent] as const,
  ),
)(
  "normalized Inspector repository binding for %s",
  async (remote, other, equivalent) => {
    await using f = await checkout(remote);
    const prepare = (url: string) =>
      prepareNormalizedLocalImport(
        normalized([typedRow(url)]),
        f.options,
        f.deps,
      );
    await expect(prepare(other)).rejects.toThrow(
      "does not match a configured remote",
    );
    expect((await prepare(equivalent)).preview.findings).toHaveLength(1);
  },
);

test("mapped local imports preserve their SQLite history and verify replay provenance", async () => {
  await using f = await checkout();
  const input = inspectorPackageFinding();
  const project = input.resources[0]!;
  project.details.codeRepository.projectName = "example/project";
  const options = {
    ...f.options,
    inspectorProjectMap: new Map([[project.id, inspectorRepositoryUrl]]),
  };
  const store = async (findings: unknown[]) => {
    await writeFile(f.path, gzipSync(JSON.stringify({ findings })));
    return (await prepareLocalExternalImport(f.path, options, f.deps)).import();
  };
  expect((await store([input])).counts.created).toBe(1);
  expect(
    (await store([{ ...input, status: "SUPPRESSED" }])).counts.updated,
  ).toBe(1);
  expect((await store([])).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 0,
  });
  const records = await listLocalExternalFindings(options, f.deps);
  expect(records).toHaveLength(1);
  const saved = records[0]!;
  expect(saved).toMatchObject({
    provider: "inspector",
    sourceFindingId: input.findingArn,
    version: 2,
    assessment: { state: "not_assessed" },
  });
  const row = {
    source_finding_id: saved.sourceFindingId,
    evidence: saved.evidence,
  };
  const replay = await prepareNormalizedLocalImport(
    normalized([row]),
    options,
    f.deps,
  );
  expect((await replay.import()).counts.unchanged).toBe(1);

  await expect(
    prepareNormalizedLocalImport(
      normalized([{ ...row, source_finding_id: "wrong" }]),
      options,
      f.deps,
    ),
  ).rejects.toThrow(/ARN|identity|source finding/i);
  const other = "https://other.example.test/example/project";
  row.evidence.details = { kind: "sast", repository: { url: other } };
  await expect(
    prepareNormalizedLocalImport(normalized([row]), options, f.deps),
  ).rejects.toThrow(/retained scanner repository/i);
  // Both copies of the retained URL now match the other checkout. The trusted map still disagrees.
  row.evidence.source_data!["sourceRepositoryUrl"] = other;
  await using fork = await checkout(other);
  await expect(
    prepareNormalizedLocalImport(
      normalized([row]),
      { ...options, repository: fork.options.repository },
      fork.deps,
    ),
  ).rejects.toThrow(/project|repository/i);
});

test("a mapped custom host keeps its path casing across reader hints and caller mutations", async () => {
  const trusted = "https://scm.example.test/Team/Project";
  await using f = await checkout(trusted.toLowerCase(), trusted);
  const input = inspectorPackageFinding();
  const project = input.resources[0]!;
  project.details.codeRepository.projectName = trusted;
  const report = { findings: [input] };
  const map = new Map([[project.id, trusted]]);
  const data = normalizeInspectorFindings(report, trusted, "local", map);
  await writeFile(f.path, gzipSync(JSON.stringify(report)));
  for (const raw of [false, true]) {
    const options = { ...f.options, inspectorProjectMap: new Map(map) };
    const pending = raw
      ? prepareLocalExternalImport(f.path, options, f.deps)
      : prepareNormalizedLocalImport(data, options, {
          ...f.deps,
          sourceRepositories: [{ url: trusted, platform: "github" }],
        });
    options.inspectorProjectMap.clear();
    await expect(pending).rejects.toThrow("does not match a configured remote");
  }
});

test("normalized imports bind mixed projects, native evidence and maps to their provider", async () => {
  await using f = await checkout();
  const native = inspectorPackageFinding();
  const row = normalizeInspectorFindings(
    { findings: [native] },
    inspectorRepositoryUrl,
    "local",
  ).findings[0]!;
  const fork = structuredClone(native);
  fork.findingArn = fork.findingArn.replace(/a$/u, "b");
  const project = fork.resources[0]!;
  project.id = project.id.replace("22222222", "33333333");
  project.details.codeRepository.projectName =
    "https://github.com/fork/project";
  const others = normalizeInspectorFindings(
    { findings: [fork] },
    project.details.codeRepository.projectName,
    "local",
  ).findings;
  await expect(
    prepareNormalizedLocalImport(
      normalized([row, ...others]),
      f.options,
      f.deps,
    ),
  ).rejects.toThrow("more than one repository project");

  const forkUrl = project.details.codeRepository.projectName;
  f.git("remote", "add", "fork", forkUrl);
  const plain = await mkdtemp(join(dirname(f.path), "plain-"));
  for (const repository of [plain, f.options.repository]) {
    await expect(
      prepareNormalizedLocalImport(
        normalized([row, typedRow(forkUrl)]),
        { ...f.options, repository },
        f.deps,
      ),
    ).rejects.toThrow("does not match the retained Inspector repository");
  }
  row.evidence.source_data = {
    ...native,
    resources: [{ type: "AWS_EC2_INSTANCE", id: "i-example" }],
  };
  await expect(
    prepareNormalizedLocalImport(
      normalized([{ ...row, source_finding_id: "CVE-2099-1234" }]),
      f.options,
      f.deps,
    ),
  ).rejects.toThrow("retained Inspector");
  row.evidence.source_data = {};
  const wiz = { ...f.options, provider: "wiz" as const };
  await expect(
    prepareNormalizedLocalImport(
      normalized([row]),
      { ...wiz, inspectorProjectMap: new Map() },
      f.deps,
    ),
  ).rejects.toThrow("map requires the inspector provider");
  const otherProvider = await prepareNormalizedLocalImport(
    normalized([row]),
    wiz,
    f.deps,
  );
  expect(otherProvider.preview.findings[0]!.source_finding_id).toBe(
    native.findingArn,
  );
});
