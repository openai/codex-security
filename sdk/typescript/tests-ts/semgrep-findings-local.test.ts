import { access, readFile, rm, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { expect, test } from "bun:test";
import type { HostedExternalFindings } from "../src/external-findings.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import {
  normalizeSemgrepFindings,
  normalizeSemgrepSarif,
  readSemgrepFindings,
} from "../src/semgrep-findings.js";
import { normalizeSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import {
  localFindingsFixture,
  localReportFixture,
} from "./external-findings-local-helpers.js";
import {
  platformFinding,
  platformProject,
  collectProject,
  platformReport,
} from "./support/semgrep-platform-fixtures.js";
import {
  semgrepJson,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const repositoryUrl = "https://github.com/example/project";
const formats = ["JSON", "SARIF"] as const;

async function platformCheckout(remote: string, sourceKey = "platform") {
  const fixture = await localReportFixture(
    "semgrep.json",
    { provider: "semgrep", sourceKey },
    { remote },
  );
  return {
    ...fixture,
    prepareNormalized: (input: HostedExternalFindings) =>
      prepareNormalizedLocalImport(
        input,
        fixture.options,
        fixture.dependencies,
      ),
  };
}

test("a retained Platform row binds mixed SARIF provenance in either order", async () => {
  const url = "https://scm.example.test/Team/Project";
  await using fixture = await platformCheckout(url);
  const { findings: platform } = normalizeSemgrepPlatformFindings({
    ...platformReport(),
    project: { ...platformProject, url },
    findings: [{ ...platformFinding(7), repository: { url } }],
  });
  const raw = semgrepSarif();
  const legacy = normalizeSemgrepSarif(
    {
      ...raw,
      runs: raw.runs.map((run) => ({
        ...run,
        versionControlProvenance: [{ repositoryUri: url.toLowerCase() }],
      })),
    },
    { sourceRepositoryUrl: url },
  );
  for (const findings of [
    [...legacy.findings, ...platform],
    [...platform, ...legacy.findings],
  ]) {
    const input = { read: findings.length, findings, excluded: [] };
    await expect(fixture.prepareNormalized(input)).rejects.toThrow(
      "does not match",
    );
    expect(
      (
        await prepareNormalizedLocalImport(input, fixture.options, {
          ...fixture.dependencies,
          sourceRepositories: [{ url, platform: "github" }],
        })
      ).preview.findings,
    ).toHaveLength(findings.length);
  }
});

test.each([
  ["gitlab.com", "scp"],
  ["gitlab.com", "ssh"],
  ["scm.example.test", "scp"],
] as const)(
  "mixed projected Semgrep reports preserve hosted alias scope on %s with %s provenance",
  async (host, transport) => {
    const url = `https://${host}/Group/repo`;
    await using fixture = await platformCheckout(url);
    const aliases = [
      `git@${host}:Group/repo.git`,
      `ssh://git@${host}/Group/repo.git`,
    ] as const;
    const [native, reader] =
      transport === "scp" ? aliases : ([aliases[1], aliases[0]] as const);
    const report = normalizeSemgrepSarif(semgrepSarif(), {
      sourceRepositoryUrl: url,
    });
    const input: HostedExternalFindings = {
      ...report,
      sourceRepositoryUrl: url,
      read: report.read + 1,
      findings: [
        {
          source_finding_id: "blackduck-bom:" + "a".repeat(64),
          evidence: {
            title: "Projected scanner finding",
            severity: "high",
            details: { kind: "sast", repository: { url } },
          },
        },
        ...report.findings.map((finding) => ({
          ...finding,
          evidence: {
            ...finding.evidence,
            source_data: {
              ...finding.evidence.source_data,
              runContext: {
                versionControlProvenance: [{ repositoryUri: native }],
              },
            },
          },
        })),
      ],
    };
    const prepare = (reference: string) =>
      prepareNormalizedLocalImport(input, fixture.options, {
        ...fixture.dependencies,
        sourceRepositories: [{ url: reference }],
      });
    if (host === "gitlab.com") {
      expect((await prepare(reader)).preview.findings).toEqual(input.findings);
      for (const reference of [
        reader.replace("git@", "other@"),
        reader.replace("Group/", "group/"),
        reader.replace("repo.git", "other.git"),
      ])
        await expect(prepare(reference)).rejects.toThrow(
          "does not match the hosted scanner project",
        );
    } else {
      await expect(prepare(reader)).rejects.toThrow(
        "does not match the hosted scanner project",
      );
    }
  },
);

test("a prepared Platform import retains its selected runner and signal", async () => {
  await using fixture = await platformCheckout(repositoryUrl);
  await fixture.writeJson(platformReport());
  const dependencies = {
    ...fixture.dependencies,
    signal: new AbortController().signal,
    runWorkbench: async () => {
      throw new Error("original runner");
    },
  };
  const prepared = await prepareLocalExternalImport(
    fixture.file,
    fixture.options,
    Object.create(dependencies),
  );
  dependencies.signal = AbortSignal.abort();
  dependencies.runWorkbench = async () => {
    throw new Error("replacement runner");
  };
  await expect(prepared.import()).rejects.toThrow("original runner");
});

test("a saved Platform collection replays and updates unassessed findings in SQLite", async () => {
  await using fixture = await platformCheckout(
    repositoryUrl,
    "example/project/main/platform",
  );
  const file = fixture.file + ".gz";
  const { options, dependencies } = fixture;
  const finding = platformFinding(17);
  for (const [index, status] of ["open", "open", "fixed"].entries()) {
    await writeFile(
      file,
      gzipSync(JSON.stringify(platformReport([{ ...finding, status }]))),
    );
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    const outcome = await prepared.import();
    expect(outcome.counts).toMatchObject({
      [["created", "unchanged", "updated"][index]!]: 1,
    });
  }
  const records = await fixture.read();
  expect(records).toHaveLength(1);
  expect(records[0]).toMatchObject({
    version: 2,
    assessment: { state: "not_assessed" },
    evidence: { details: { source_status: "fixed" } },
  });

  const recreated = platformReport([finding]);
  recreated.project = { ...recreated.project, id: recreated.project.id + 1 };
  const mapped = normalizeSemgrepPlatformFindings(recreated);
  const row = mapped.findings[0]!;
  expect(row.source_finding_id).not.toBe(records[0]!.sourceFindingId);
  row.source_finding_id = records[0]!.sourceFindingId;
  const migration = await fixture.prepareNormalized(mapped);
  const saved = await migration.import();
  expect(saved.counts.updated).toBe(1);
  expect(saved.findings[0]?.evidence.source_data?.["project"]).toEqual(
    recreated.project,
  );
});

test("replays numeric int64 Platform finding IDs from a file while preserving native JSON numbers", async () => {
  await using fixture = await platformCheckout(repositoryUrl);
  const ids = ["9007199254740992", "9007199254740993"];
  const ratio = "0.1234567890123456789";
  const { format, ...platform } = platformReport(
    ids.map((id) => ({ ...platformFinding(1), id, metadata: { ratio } })),
  );
  const report = { ...platform, format };
  const quoted = JSON.stringify(report).replace(/"(\d{16})"/gu, "$1");
  await writeFile(
    fixture.file,
    quoted.replace(`"ratio":"${ratio}"`, `"ratio":${ratio}`),
  );
  const expected = normalizeSemgrepPlatformFindings(report);
  expect(expected.findings).toHaveLength(2);
  const numeric = await readSemgrepFindings(fixture.file);
  expect(numeric).toMatchObject(expected);
  expect(
    numeric.findings.map((row) => row.evidence.source_data?.["numericFields"]),
  ).toEqual([
    { finding: { id: ids[0], metadata: { ratio } } },
    { finding: { id: ids[1] } },
  ]);
  const prepared = await fixture.prepare();
  expect((await prepared.import()).counts.created).toBe(2);
  // Changing one vendor fraction to the same quoted digits updates only that finding.
  await writeFile(fixture.file, quoted);
  const changed = await fixture.prepare();
  expect((await changed.import()).counts).toMatchObject({
    updated: 1,
    unchanged: 1,
  });

  // A rounded fractional token must not overwrite the genuine occurrence for ID 1.
  const small = JSON.stringify(platformReport([platformFinding(1)]));
  await writeFile(
    fixture.file,
    small.replace('"id":1,', '"id":1.00000000000000001,'),
  );
  expect((await readSemgrepFindings(fixture.file)).excluded).toHaveLength(1);

  for (const field of ["line", "end_line"]) {
    await writeFile(
      fixture.file,
      small.replace(
        new RegExp(`"${field}":\\d+`, "u"),
        `"${field}":1.00000000000000001`,
      ),
    );
    expect((await readSemgrepFindings(fixture.file)).excluded).toHaveLength(1);
  }
  await writeFile(
    fixture.file,
    small.replace('"findingCount":1', '"findingCount":0.99999999999999999'),
  );
  await expect(readSemgrepFindings(fixture.file)).rejects.toThrow(
    "Incomplete Semgrep Platform export",
  );

  const amount = "-9.007199254740993E+15";
  const exponential = platformReport([
    { ...platformFinding(1), measurements: [amount] },
  ]);
  await writeFile(
    fixture.file,
    JSON.stringify(exponential).replace(JSON.stringify(amount), amount),
  );
  const measured = await readSemgrepFindings(fixture.file);
  expect(measured).toMatchObject(normalizeSemgrepPlatformFindings(exponential));
  expect(measured.findings[0]!.evidence.source_data?.["numericFields"]).toEqual(
    {
      finding: { measurements: { 0: amount } },
    },
  );

  // Native imports ignore timing data, even when a JSON reviver would overflow.
  const timing = "[".repeat(12000) + "0" + "]".repeat(12000);
  const native = JSON.stringify({ ...semgrepJson(), time: "timing-data" })
    .replace('"timing-data"', timing)
    .replace('"offset":20', '"offset":9007199254740993');
  await writeFile(fixture.file, native);
  const options = { sourceRepositoryUrl: repositoryUrl };
  expect(await readSemgrepFindings(fixture.file, options)).toEqual(
    normalizeSemgrepFindings(JSON.parse(native), options),
  );
});

test("replays native SSH evidence and URL-less labels from the selected Semgrep project", async () => {
  await using fixture = await platformCheckout(repositoryUrl);
  const project = {
    ...platformProject,
    name: "billing-module",
    url: "ssh://git@github.com/example/project.git",
  };
  const alias = "local_scan/backend";
  const rows = [
    { ...platformFinding(8), repository: { name: alias } },
    {
      ...platformFinding(9),
      repository: { url: "git@github.com:example/project.git" },
    },
  ];
  const collected = await collectProject(project, rows, repositoryUrl);
  expect(collected).toMatchObject({
    project,
    sourceRepositoryUrl: repositoryUrl,
    repositoryAliases: [alias],
    findings: rows,
  });
  await fixture.writeJson(collected);
  const prepared = await fixture.prepare();
  expect((await prepared.import()).counts.created).toBe(2);
  const stored = await fixture.read();
  expect(stored.map((entry) => entry.evidence.source_data)).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        repositoryAliases: [alias],
        project,
        finding: rows[0],
      }),
      expect.objectContaining({
        project,
        repositoryAliases: [],
        finding: rows[1],
      }),
    ]),
  );
  expect(() =>
    normalizeSemgrepPlatformFindings({ ...collected, repositoryAliases: [] }),
  ).toThrow("matching source repository");
  const normalized = normalizeSemgrepPlatformFindings(collected);
  const evidence = normalized.findings[1]!.evidence.source_data!;
  evidence["finding"] = {
    ...rows[1],
    repository: { url: repositoryUrl, name: "other-module" },
  };
  await expect(fixture.prepareNormalized(normalized)).rejects.toThrow(
    "matching source repository",
  );
  // Historical normalized evidence without captured labels accepted a matching repository URL.
  delete evidence["repositoryAliases"];
  expect(
    (await fixture.prepareNormalized(normalized)).preview.findings,
  ).toHaveLength(2);
  for (const url of [
    "git@github.com:other/project.git",
    "ssh://deploy@github.com/example/project.git",
    "ssh://git@github.com:2222/example/project.git",
    "ssh://git@github.com?other/example/project.git",
    "ssh://git@github.com#other/example/project.git",
    "ssh://git@github.com%23other/example/project.git",
    "ssh://git@other.test%2Fextra@github.com/example/project.git",
    "git@scm.example.test:example/project.git",
  ]) {
    expect(() =>
      normalizeSemgrepPlatformFindings({
        ...collected,
        project: { ...project, url },
        sourceRepositoryUrl: url.includes("scm.example.test")
          ? "https://scm.example.test/example/project"
          : repositoryUrl,
      }),
    ).toThrow();
  }
});

test.each([
  ["github.com.", "git", "ssh://git@ssh.github.com.:443/team/project.git"],
  ["example.ghe.com.", "example", "example@example.ghe.com.:team/project.git"],
])(
  "replays native and checkout SSH aliases for the same %s authority",
  async (host, user, remote) => {
    const url = `https://${host}/team/project`;
    const project = {
      ...platformProject,
      url: `${user}@${host}:team/project.git`,
    };
    const finding = {
      ...platformFinding(9),
      repository: { url: `ssh://${user}@${host}/team/project.git` },
    };
    const report = await collectProject(project, [finding], url);
    await using fixture = await platformCheckout(remote);
    await fixture.writeJson(report);
    const prepared = await fixture.prepare();
    expect(prepared.preview.findings[0]?.evidence.source_data).toMatchObject({
      project,
      finding,
    });
    await expect(
      collectProject(project, [finding], url.replace("./", "/")),
    ).rejects.toThrow();
  },
);

test("local file and normalized imports retain the repository references selected at invocation", async () => {
  const url = "https://scm.example.test/Team/Project";
  await using fixture = await platformCheckout(url.toLowerCase());
  const report = {
    ...platformReport([]),
    project: { ...platformProject, url },
  };
  await fixture.writeJson(report);
  const reference = { url, platform: "github" as const };
  const dependencies = {
    ...fixture.dependencies,
    sourceRepositories: [reference],
  };
  const selected = {
    sourceRepositoryUrl: url.toLowerCase(),
    sourceRepositories: dependencies.sourceRepositories,
  };
  const read = readSemgrepFindings(fixture.file, selected);
  const expected = normalizeSemgrepPlatformFindings(report, selected);
  const prepared = Promise.all([
    prepareLocalExternalImport(fixture.file, fixture.options, dependencies),
    prepareNormalizedLocalImport(
      normalizeSemgrepPlatformFindings(report),
      fixture.options,
      dependencies,
    ),
  ]);
  selected.sourceRepositoryUrl += "-foreign";
  reference.url += "-foreign";
  dependencies.sourceRepositories.length = 0;
  expect(await read).toEqual(expected);
  expect((await prepared).map(({ preview }) => preview.findings)).toEqual([
    [],
    [],
  ]);
});

test("a saved Semgrep .git alias on a custom host retains the selected repository", async () => {
  const mapping = "https://scm.example.test/team/lib";
  const project = { ...platformProject, url: mapping + ".git" };
  const finding = { ...platformFinding(42), repository: { url: project.url } };
  const report = await collectProject(project, [finding], mapping);
  expect(report.sourceRepositoryUrl).toBe(mapping);
  await using fixture = await platformCheckout(project.url);
  await fixture.writeJson(report);
  for (const sourceRepositoryUrl of [undefined, mapping, project.url])
    await expect(
      readSemgrepFindings(fixture.file, { sourceRepositoryUrl }),
    ).rejects.toThrow("does not match");
  const sourceRepositories = [{ url: mapping, platform: "github" as const }];
  const expected = await readSemgrepFindings(fixture.file, {
    sourceRepositories,
  });
  expect(expected.sourceRepositoryUrl).toBe(mapping);
  expect(expected.findings[0]?.evidence.source_data).toMatchObject({
    project,
    sourceRepositoryUrl: mapping,
    finding,
  });
  await expect(fixture.prepareNormalized(expected)).rejects.toThrow(
    "does not match",
  );
  const prepared = await prepareLocalExternalImport(
    fixture.file,
    fixture.options,
    { ...fixture.dependencies, sourceRepositories },
  );
  expect(prepared.preview.findings).toEqual(expected.findings);

  // Older exports omitted equivalent mappings from per-finding evidence.
  const legacy = { ...report, sourceRepositoryUrl: undefined };
  const remapped = normalizeSemgrepPlatformFindings(legacy, {
    sourceRepositoryUrl: mapping,
    sourceRepositories,
  });
  expect(remapped.sourceRepositoryUrl).toBe(mapping);
  expect(remapped.findings).toEqual(
    normalizeSemgrepPlatformFindings(legacy).findings,
  );
  await expect(fixture.prepareNormalized(remapped)).rejects.toThrow(
    "does not match",
  );
});

test("hosted Semgrep honors an explicit Enterprise repository binding", async () => {
  const url = "https://scm.example.test/Team/Project";
  await using fixture = await platformCheckout(url.toLowerCase());
  const report = platformReport([]);
  const input = normalizeSemgrepPlatformFindings({
    ...report,
    project: { ...report.project, url },
  });
  const prepare = (source: { url: string; platform?: "github" }) =>
    prepareNormalizedLocalImport(input, fixture.options, {
      ...fixture.dependencies,
      sourceRepositories: [source],
    });
  await expect(prepare({ url: url.toLowerCase() })).rejects.toThrow(
    "does not match",
  );
  await expect(
    prepare({ url: url + "-other", platform: "github" }),
  ).rejects.toThrow("does not match");
  expect(
    (await prepare({ url: url.toLowerCase(), platform: "github" })).preview
      .findings,
  ).toEqual([]);
  input.sourceRepositoryPlatform = "other";
  await expect(
    prepare({ url: url.toLowerCase(), platform: "github" }),
  ).rejects.toThrow("does not match");

  const row = {
    ...platformFinding(7),
    repository: {
      name: "project",
      url: "git@scm.example.test:team/project.git",
    },
  };
  const collected = await collectProject(
    { ...report.project, url },
    [row],
    url.toLowerCase(),
  );
  expect(collected).toMatchObject({
    project: { url },
    sourceRepositoryUrl: url.toLowerCase(),
    findings: [row],
  });
  expect(() => normalizeSemgrepPlatformFindings(collected)).toThrow();
  await fixture.writeJson(collected);
  const prepareFile = (source?: { url: string; platform?: "github" }) =>
    prepareLocalExternalImport(
      fixture.file,
      { ...fixture.options, sourceRepositoryUrl: url.toLowerCase() },
      {
        ...fixture.dependencies,
        sourceRepositories: source ? [source] : [],
      },
    );
  await expect(prepareFile()).rejects.toThrow("does not match");
  await expect(
    prepareFile({ url: url + "-other", platform: "github" }),
  ).rejects.toThrow("does not match");
  expect(
    (await prepareFile({ url, platform: "github" })).preview.findings,
  ).toHaveLength(1);
  const ssh = "scm.example.test:team/project.git";
  expect(
    (await prepareFile({ url: "git@" + ssh, platform: "github" })).preview
      .findings,
  ).toHaveLength(1);
  await expect(
    prepareFile({ url: "other@" + ssh, platform: "github" }),
  ).rejects.toThrow("does not match");
});

test.each([
  "ssh://git@github.com/example/project.git?foreign",
  "ftp://github.com/example/project",
  " ssh://git@github.com/example/project.git",
  "https::https://github.com/example/foreign.git",
  "https::https://a@b@github.com/example/project.git",
  "ext::ssh git@github.com %S example/foreign.git",
  "example::file:///example/foreign.git",
  "example::foreign\nhttps://github.com/example/project",
  "https://github.com/example/project\r",
  "https://github.com/ex\tample/project",
  ...(process.platform === "win32" ? [] : ["a:/example/foreign.git"]),
  "git@[github.com]:elsewhere/project.git",
  "git@[github.com:2222]:example/project.git",
  "git@[github.com:invalid]:example/project.git",
  "git@github.com?foreign:example/project.git",
  "http::ftp://github.com/example/project",
  "ssh://git@github.com/example/other/../project.git",
  "https://github.com/example/other/%2e%2e/project.git",
  "https://github.com/example\\project.git",
  "https://github.com/example%2Fproject.git",
  "https://github.com/example/project.git?other",
  "https://github.com:8443/example/project.git",
  "other@github.com:example/project.git",
  "git+ssh://other@github.com/example/project",
  "ssh+git://git@github.com:2222/example/project",
  "git+ssh://git@github.com/elsewhere/%2e%2e/example/project",
  "ssh+git://git@github.com/example/project.git#foreign",
])(
  "an empty Platform report rejects a checkout whose remote is %s",
  async (remote) => {
    await using fixture = await platformCheckout(remote);
    await fixture.writeJson(platformReport([]));
    await expect(fixture.prepare()).rejects.toThrow("does not match");
    await expect(
      fixture.prepareNormalized(await readSemgrepFindings(fixture.file)),
    ).rejects.toThrow("does not match");
  },
);

test.each([
  [
    repositoryUrl,
    "https://git%40fixture@github.com:443/example/project.git",
    "https://github.com:443/example/project",
  ],
  ["https://github.com:443/example/project", repositoryUrl, repositoryUrl],
  [
    repositoryUrl,
    "git@[github.com]:example/project.git",
    "https://github.com:443/example/project",
  ],
  [
    repositoryUrl,
    "ssh://git@github.com%2Fexample%2Fproject.git",
    "https://github.com:443/example/project",
  ],
  [
    repositoryUrl,
    "ftps::https://github.com:443/example/project.git",
    "https://github.com:443/example/project",
  ],
  [
    "https://github.com:443/example/project",
    "git@github.com:example/project.git",
    repositoryUrl,
  ],
  [
    "https://github.com:443/example/archive.git.git",
    "git@github.com:example/archive.git.git",
    "https://github.com/example/archive.git.git",
  ],
  [
    "https://bitbucket.org/team/project",
    "git+ssh://git@bitbucket.org:22/team/project.git",
    "https://bitbucket.org:443/team/project",
  ],
  [
    "https://gitlab.com/Group/project",
    "ssh+git://git@gitlab.com/Group/project.git",
    "https://gitlab.com:443/Group/project",
  ],
])(
  "hosted %s matches the equivalent checkout %s while keeping explicit source ports distinct",
  async (url, remote, otherSource) => {
    await using fixture = await platformCheckout(remote);
    const report = platformReport([]);
    const input = normalizeSemgrepPlatformFindings({
      ...report,
      project: { ...report.project, url },
    });
    const { options, dependencies } = fixture;
    expect((await fixture.prepareNormalized(input)).preview.findings).toEqual(
      [],
    );
    await expect(
      prepareNormalizedLocalImport(input, options, {
        ...dependencies,
        sourceRepositories: [{ url: otherSource }],
      }),
    ).rejects.toThrow("does not match");
  },
);

test("checks scanner repository links independently of Git checkout URLs", async () => {
  const canonical = "https://scm.example.test/Team/repo";
  const ambiguous = "https://scm.example.test/Team/%2e%2e/../repo";
  await using checkout = await platformCheckout(canonical);
  const empty = { read: 0, findings: [], excluded: [] };
  const projected = normalizeSemgrepFindings(semgrepJson(), {
    sourceRepositoryUrl: ambiguous,
  });
  for (const report of [
    { ...empty, sourceRepositoryUrl: ambiguous },
    { ...projected, sourceRepositoryPlatform: "other" as const },
  ])
    await expect(checkout.prepareNormalized(report)).rejects.toThrow(
      /repository/i,
    );

  await using transport = await platformCheckout(ambiguous);
  const prepared = await transport.prepareNormalized({
    ...empty,
    sourceRepositoryUrl: canonical,
  });
  expect(prepared.preview.findings).toEqual([]);
});

const gitlabUrl = "https://gitlab.com/Group/My-Repo";
test.each([
  ["{1}", "{1}", false],
  ["{1}", "%7B1%7D", false],
  ["%7B1%7D", "%7B1%7D", true],
  ["/tmp{1}/../repo", "/repo", true],
  ["/repo", "/tmp{1}/../repo", true],
] as const)(
  "compares the Git checkout %s with the scanner link %s",
  async (checkout, source, matches) => {
    await using f = await platformCheckout(gitlabUrl + checkout);
    const prepared = f.prepareNormalized({
      read: 0,
      findings: [],
      excluded: [],
      sourceRepositoryUrl: gitlabUrl + source,
    });
    if (matches) expect((await prepared).preview.findings).toEqual([]);
    else await expect(prepared).rejects.toThrow("does not match");
  },
);

test("hosted HTTP sources reject raw control bytes and preserve percent escapes", async () => {
  const url = repositoryUrl + "\x01";
  await using f = await platformCheckout(repositoryUrl);
  const raw = platformReport([]);
  await f.writeJson({ ...raw, project: { ...raw.project, url } });
  await expect(f.prepare()).rejects.toThrow("percent-encode");
  const input = normalizeSemgrepPlatformFindings(raw);
  await expect(
    f.prepareNormalized({ ...input, sourceRepositoryUrl: url }),
  ).rejects.toThrow("percent-encode");
  const encoded = repositoryUrl + "%01";
  expect(
    normalizeSemgrepPlatformFindings({
      ...raw,
      project: { ...raw.project, url: encoded },
    }).sourceRepositoryUrl,
  ).toBe(encoded);
});

test("a local Git path may contain non-UTF-8 bytes unless it is a helper argument", async () => {
  await using f = await platformCheckout("/synthetic/mirror");
  const path = join(f.options.repository, ".git", "config");
  const base = await readFile(path);
  const input = normalizeSemgrepPlatformFindings(platformReport([]));
  for (const forced of [false, true]) {
    await writeFile(
      path,
      Buffer.concat([
        base,
        Buffer.from(
          `\n[remote "mirror"]\n${forced ? " vcs = example\n" : ""} url = /data/`,
        ),
        Buffer.from([0xff]),
        Buffer.from("mirror\n"),
      ]),
    );
    const prepared = f.prepareNormalized(input);
    if (forced)
      await expect(prepared).rejects.toThrow(
        "does not match a configured remote",
      );
    else expect((await prepared).preview.findings).toEqual([]);
  }
});

test("undecodable Git names and URLs cannot match a replacement character", async () => {
  await using f = await platformCheckout(repositoryUrl);
  const configPath = join(f.options.repository, ".git", "config");
  const base = await readFile(configPath);
  const prefix = "https://github.com/example/";
  const url = prefix + "%EF%BF%BD";
  const prepare = () =>
    f.prepareNormalized({
      read: 0,
      findings: [],
      excluded: [],
      sourceRepositoryUrl: url,
    });
  const section = (name: Buffer, path: Buffer) =>
    Buffer.concat([
      Buffer.from('\n[remote "'),
      name,
      Buffer.from(`"]\n  url = ${prefix}`),
      path,
      Buffer.from("\n"),
    ]);
  const invalid = Buffer.from([0xff]);
  const malformed = Buffer.concat([
    base,
    section(Buffer.from("bad-url"), invalid),
    section(invalid, Buffer.from("�")),
  ]);
  await writeFile(configPath, malformed);
  await expect(prepare()).rejects.toThrow("does not match a configured remote");
  for (const path of ["�", "%EF%BF%BD"]) {
    await writeFile(
      configPath,
      Buffer.concat([
        malformed,
        section(Buffer.from("upstream"), Buffer.from(path)),
      ]),
    );
    expect((await prepare()).preview.findings).toEqual([]);
  }
});

const escapedGitlabUrl = "https://gitlab.com/%47roup/My%2dRepo";
test.each([
  [escapedGitlabUrl, gitlabUrl],
  [gitlabUrl, escapedGitlabUrl],
  [escapedGitlabUrl, "ssh://git@gitlab.com/Group/My-Repo.git"],
])(
  "hosted source %s and checkout %s compare unreserved path escapes",
  async (source, remote) => {
    await using fixture = await platformCheckout(remote);
    const report = platformReport([
      { ...platformFinding(7), repository: { url: source } },
    ]);
    const input = normalizeSemgrepPlatformFindings({
      ...report,
      project: { ...report.project, url: source },
    });
    input.findings[0]!.evidence.details!.repository!.url = gitlabUrl;
    const prepare = (url: string) =>
      prepareNormalizedLocalImport(input, fixture.options, {
        ...fixture.dependencies,
        sourceRepositories: [{ url }],
      });
    expect((await prepare(gitlabUrl)).preview.findings).toHaveLength(1);
    await expect(prepare("https://gitlab.com/Group%2FMy-Repo")).rejects.toThrow(
      "does not match",
    );
    await expect(prepare("https://gitlab.com/group/My-Repo")).rejects.toThrow(
      "does not match",
    );
  },
);

function report(
  format: (typeof formats)[number],
  {
    line = 3,
    fingerprint = "synthetic-fingerprint",
    message = "Synthetic finding",
    sparse = false,
  } = {},
) {
  if (format === "JSON") {
    const input = semgrepJson();
    const result = input.results[0]!;
    result.start.line = line;
    result.end.line = line;
    result.extra.fingerprint = fingerprint;
    result.extra.message = message;
    if (sparse) {
      result.path = "../outside.ts";
      result.extra.severity = "EXPERIMENT";
      result.extra.lines = "requires login";
    }
    return input;
  }
  const input = semgrepSarif();
  const run = input.runs[0]!;
  const result = run.results[0]!;
  const region = result.locations[0]!.physicalLocation.region;
  region.startLine = line;
  region.endLine = line;
  result.fingerprints["matchBasedId/v1"] = fingerprint;
  result.message.text = message;
  if (sparse) {
    result.locations[0]!.physicalLocation.artifactLocation.uri =
      "../outside.ts";
    run.tool.driver.rules[0]!.defaultConfiguration.level = "none";
  }
  return input;
}

test("Semgrep file reader rejects malformed SARIF repository provenance", async () => {
  const directory = await temporaryDirectory("semgrep-reader-");
  try {
    const file = join(directory, "semgrep.sarif");
    const input = sarifWithRepositories(['http://""?\nX']);
    await writeFile(file, JSON.stringify(input));
    await expect(
      readSemgrepFindings(file, { sourceRepositoryUrl: repositoryUrl }),
    ).rejects.toThrow(
      "SARIF source repository does not match the declared source repository URL.",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

for (const suppliedFingerprint of [true, false]) {
  test.each(formats)(
    `Semgrep %s movement ${suppliedFingerprint ? "updates the supplied fingerprint" : "retains both fallback records"} in SQLite`,
    async (format) => {
      await using fixture = await localReportFixture(
        "semgrep.json",
        {
          provider: "semgrep",
          sourceKey: "example-project:main",
          sourceRepositoryUrl: repositoryUrl,
        },
        { remote: repositoryUrl },
      );
      const fingerprint = suppliedFingerprint
        ? "synthetic-fingerprint"
        : "requires login";
      async function prepareLine(line: number, message?: string) {
        await fixture.writeJson(report(format, { line, fingerprint, message }));
        return fixture.prepare();
      }

      const prepared = await prepareLine(3);
      expect(prepared.preview.findings).toHaveLength(1);
      expect(prepared.preview.excluded).toEqual([]);
      expect(prepared.preview.source).toEqual({
        provider: "semgrep",
        source_key: fixture.sourceKey,
      });
      expect((await prepared.import()).counts).toEqual({
        created: 1,
        updated: 0,
        unchanged: 0,
      });
      const [original] = await fixture.read();
      expect(original).toMatchObject({
        provider: "semgrep",
        sourceKey: fixture.sourceKey,
        sourceFindingId: prepared.preview.findings[0]!.source_finding_id,
        assessment: { state: "not_assessed" },
        version: 1,
      });
      expect(original!.evidence).toEqual(
        prepared.preview.findings[0]!.evidence,
      );
      expect(original!.evidence).not.toHaveProperty("confidence");
      expect(original!.evidence.locations).toEqual([
        { path: "src/example.ts", line: 3 },
      ]);

      const next = await prepareLine(9);
      expect((await next.import()).counts).toEqual(
        suppliedFingerprint
          ? { created: 0, updated: 1, unchanged: 0 }
          : { created: 1, updated: 0, unchanged: 0 },
      );
      const records = await fixture.read();
      const moved = records.find(
        (record) => record.evidence.locations?.[0]?.line === 9,
      );
      expect(moved).toBeDefined();
      expect(moved!.evidence.locations).toEqual([
        { path: "src/example.ts", line: 9 },
      ]);
      expect(moved!.evidence.source_data?.["result"]).toMatchObject(
        format === "JSON"
          ? { extra: { fingerprint } }
          : { fingerprints: { "matchBasedId/v1": fingerprint } },
      );
      expect(moved!.assessment).toEqual({ state: "not_assessed" });
      if (suppliedFingerprint) {
        expect(records).toHaveLength(1);
        expect(moved).toMatchObject({
          id: original!.id,
          sourceFindingId: original!.sourceFindingId,
          createdAt: original!.createdAt,
          version: 2,
        });
      } else {
        expect(records).toHaveLength(2);
        expect(records.find((record) => record.id === original!.id)).toEqual(
          original,
        );
        expect(moved!.sourceFindingId).not.toBe(original!.sourceFindingId);
        expect(moved!.version).toBe(1);
      }
      const repeated = await fixture.prepare();
      expect((await repeated.import()).counts).toEqual({
        created: 0,
        updated: 0,
        unchanged: 1,
      });
      expect(await fixture.read()).toEqual(records);

      if (suppliedFingerprint) {
        const edited = await prepareLine(9, "Updated scanner evidence");
        expect((await edited.import()).counts).toEqual({
          created: 0,
          updated: 1,
          unchanged: 0,
        });
        const updated = await fixture.read();
        expect(updated).toHaveLength(1);
        expect(updated[0]).toMatchObject({
          id: original!.id,
          sourceFindingId: original!.sourceFindingId,
          createdAt: original!.createdAt,
          assessment: { state: "not_assessed" },
          version: 3,
        });
        expect(updated[0]!.evidence).toEqual(
          edited.preview.findings[0]!.evidence,
        );
        expect(updated[0]!.evidence.description).toBe(
          "Updated scanner evidence",
        );
      }
    },
  );
}

test.each(formats)(
  "Semgrep %s preserves sparse evidence without inventing a repository location or assessment",
  async (format) => {
    await using fixture = await localReportFixture(
      "semgrep.json",
      {
        provider: "semgrep",
        sourceKey: "example-project:main",
        sourceRepositoryUrl: repositoryUrl,
      },
      { remote: repositoryUrl },
    );
    await fixture.writeJson(report(format, { message: "", sparse: true }));
    const prepared = await fixture.prepare();
    expect((await prepared.import()).counts.created).toBe(1);
    const [stored] = await fixture.read();
    expect(stored!.evidence).toEqual(prepared.preview.findings[0]!.evidence);
    expect(stored!.evidence).toMatchObject({
      description: null,
      severity: "unknown",
      locations: [],
      code_revision: null,
      details: { code: { end_line: null, snippet: null } },
    });
    expect(stored!.evidence.source_data).toHaveProperty("result");
    expect(stored!.evidence).not.toHaveProperty("confidence");
    expect(stored!.evidence).not.toHaveProperty("remediation");
    expect(stored!.assessment).toEqual({ state: "not_assessed" });
  },
);

test.each(formats)(
  "Semgrep %s rejects a source repository that conflicts with the selected checkout",
  async (format) => {
    await using fixture = await localReportFixture(
      "semgrep.json",
      {
        provider: "semgrep",
        sourceKey: "example-project:main",
        sourceRepositoryUrl: "https://github.com/other/project",
      },
      { remote: repositoryUrl },
    );
    await fixture.writeJson(report(format));
    await expect(fixture.prepare()).rejects.toThrow("does not match");
    expect(await fixture.read()).toEqual([]);
  },
);

function sarifWithRepositories(urls: string[]) {
  const input = semgrepSarif();
  return {
    ...input,
    runs: [
      {
        ...input.runs[0]!,
        versionControlProvenance: urls.map((repositoryUri) => ({
          repositoryUri,
        })),
      },
    ],
  };
}

test.each([
  ["unknown host", "git.example.test", "with remote"],
  ["GitHub", "github.com", "with remote"],
  ["known GitHub custom host", "git.example.test", "with remote"],
  ["GitHub", "github.com", "with uppercase remote"],
  ["known GitHub custom host", "git.example.test", "with uppercase remote"],
  ["unknown host", "git.example.test", "without remote"],
  ["GitHub", "github.com", "without remote"],
  ["known GitHub custom host", "git.example.test", "without remote"],
])(
  "Semgrep SARIF preserves original repository references on %s (%s, %s)",
  async (platform, host, checkout) => {
    const sourceRepositoryUrl = `https://${host}/team/project`;
    const originalUrl = `https://${host}/Team/Project`;
    await using fixture = await localFindingsFixture(
      checkout === "without remote"
        ? {}
        : {
            remote: `git@${host}:${checkout === "with uppercase remote" ? "Team/Project" : "team/project"}.git`,
          },
    );
    const file = join(fixture.root, "semgrep-report");
    const options = {
      repository: fixture.repository,
      provider: "semgrep" as const,
      sourceKey: "example-project:main",
      sourceRepositoryUrl,
    };
    const dependencies = {
      environment: fixture.environment,
      ...(platform === "known GitHub custom host"
        ? {
            sourceRepositories: [
              { url: originalUrl, platform: "github" as const },
            ],
          }
        : {}),
    };
    const database = join(fixture.stateDirectory, "workbench.sqlite3");
    async function writeReport(url: string, compressed = false) {
      // Keep both refs: checking only the first would miss the case-distinct one.
      const contents = JSON.stringify(
        sarifWithRepositories([sourceRepositoryUrl, url]),
      );
      await writeFile(file, compressed ? gzipSync(contents) : contents);
    }
    await writeReport(originalUrl, true);
    if (platform === "unknown host") {
      await expect(
        prepareLocalExternalImport(file, options, dependencies),
      ).rejects.toThrow("does not match");
      await expect(access(database)).rejects.toThrow();
      await writeReport(sourceRepositoryUrl);
    }
    const parsed = await readSemgrepFindings(file, { sourceRepositoryUrl });
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect(prepared.preview.findings).toEqual(parsed.findings);
    expect((await prepared.import()).counts).toEqual({
      created: 1,
      updated: 0,
      unchanged: 0,
    });
    const stored = await listLocalExternalFindings(options, dependencies);
    expect(stored[0]!.evidence).toEqual(parsed.findings[0]!.evidence);
    expect(stored[0]!.evidence.details?.repository?.url).toBe(
      sourceRepositoryUrl,
    );
    expect(stored[0]!.evidence.source_data?.["runContext"]).toMatchObject({
      versionControlProvenance: [
        { repositoryUri: sourceRepositoryUrl },
        {
          repositoryUri:
            platform === "unknown host" ? sourceRepositoryUrl : originalUrl,
        },
      ],
    });
    expect(
      (
        await (
          await prepareLocalExternalImport(file, options, dependencies)
        ).import()
      ).counts,
    ).toEqual({ created: 0, updated: 0, unchanged: 1 });
    const before = await readFile(database);
    await writeReport(
      platform === "unknown host"
        ? originalUrl
        : `https://${host}/other/project`,
    );
    await expect(
      prepareLocalExternalImport(file, options, dependencies),
    ).rejects.toThrow("does not match");
    expect(await readFile(database)).toEqual(before);
    expect(await listLocalExternalFindings(options, dependencies)).toEqual(
      stored,
    );
  },
);

test("normalized Semgrep SDK imports retain original SARIF repository metadata through the explicit dependency", async () => {
  const sourceRepositoryUrl = "https://git.example.test/team/project";
  const originalUrl = "https://git.example.test/Team/Project";
  await using fixture = await localFindingsFixture({
    remote: sourceRepositoryUrl,
  });
  const options = {
    repository: fixture.repository,
    provider: "semgrep" as const,
    sourceKey: "example-project:main",
  };
  const parsed = normalizeSemgrepSarif(sarifWithRepositories([originalUrl]), {
    sourceRepositoryUrl,
  });
  const saved = JSON.parse(JSON.stringify(parsed));
  await expect(
    prepareNormalizedLocalImport(saved, options, {
      environment: fixture.environment,
      sourceRepositories: [{ url: originalUrl }],
    }),
  ).rejects.toThrow("does not match");
  await expect(
    access(join(fixture.stateDirectory, "workbench.sqlite3")),
  ).rejects.toThrow();
  const dependencies = {
    environment: fixture.environment,
    sourceRepositories: [{ url: originalUrl, platform: "github" as const }],
  };
  const prepared = await prepareNormalizedLocalImport(
    saved,
    options,
    dependencies,
  );
  expect((await prepared.import()).counts.created).toBe(1);
  expect(
    (await listLocalExternalFindings(options, dependencies))[0]!.evidence,
  ).toEqual(parsed.findings[0]!.evidence);
});

test("Semgrep gzipped JSON uses the caller source URL without treating rule metadata as repository provenance", async () => {
  const sourceRepositoryUrl = "https://git.example.test/Team/Project";
  await using fixture = await localReportFixture(
    "semgrep-report",
    {
      provider: "semgrep",
      sourceKey: "example-project:main",
      sourceRepositoryUrl,
    },
    {
      remote: "git@git.example.test:Team/Project.git",
    },
  );
  const input = semgrepJson();
  const first = input.results[0]!;
  const report = {
    ...input,
    results: [
      {
        ...first,
        extra: {
          ...first.extra,
          metadata: {
            ...first.extra.metadata,
            source: "https://rules.example.test/Other/Repository",
          },
        },
      },
    ],
  };
  await writeFile(fixture.file, gzipSync(JSON.stringify(report)));
  const parsed = await readSemgrepFindings(fixture.file, {
    sourceRepositoryUrl,
  });
  const prepared = await fixture.prepare();
  expect((await prepared.import()).counts.created).toBe(1);
  const stored = await fixture.read();
  expect(stored[0]!.evidence).toEqual(parsed.findings[0]!.evidence);
  await expect(
    fixture.prepare({
      sourceRepositoryUrl: "https://git.example.test/team/project",
    }),
  ).rejects.toThrow("does not match");
  expect(await fixture.read()).toEqual(stored);
});
