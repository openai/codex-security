import { expect, mock, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { link, mkdir, stat, unlink, writeFile } from "node:fs/promises";
import type { ExternalSourceRepository } from "../src/external-findings.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import { normalizeSemgrepFindings } from "../src/semgrep-findings.js";
import { selectSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import { localReportFixture as reportFixture } from "./external-findings-local-helpers.js";

function localReportFixture(remote?: string) {
  return reportFixture("selected.json", platformSource, {
    remote,
    isolatedGit: true,
  });
}

const url = "https://github.com/example/project";
const ref = "refs/heads/release";
const rawFindingKey = "semgrepPlatformFindingJson";
const ids = ["9007199254740992", "9007199254740993"];
const project = { id: 77, name: "example/project", url };
const platformSource = {
  provider: "semgrep" as const,
  sourceKey: "example/project/release/platform",
};
const page = (
  id: string,
  options: { ref?: string; url?: string; name?: string } = {},
) =>
  `{"findings":[{"id":${id},"repository":${JSON.stringify({ name: options.name ?? project.name, url: options.url ?? url })},
    "ref":${JSON.stringify(options.ref ?? ref)},"rule":{"name":"sample.rule","message":"Example","cwe_names":["CWE-79: example"]},
    "location":{"file_path":"src/example.ts","line":2.0,"end_line":4},"severity":"medium","status":"reviewing","score":1.0000000000000000003}]}`;
const selection = (pages: string[], findingIds: readonly string[] = ids) =>
  selectSemgrepPlatformFindings({
    deployment: "example",
    ref,
    projectResponse: JSON.stringify({ project }),
    findingsResponses: pages,
    findingIds,
  });
const selectRow = (fields: Record<string, unknown>) =>
  selection(
    [
      JSON.stringify({
        findings: [{ id: 8, ref, repository: project, ...fields }],
      }),
    ],
    ["8"],
  );
const selectedRepository = (
  projectUrl: string,
  findingUrl: string,
  sourceRepositories: readonly ExternalSourceRepository[] = [],
  findingName = project.name,
) =>
  selectSemgrepPlatformFindings({
    deployment: "example",
    ref,
    projectResponse: JSON.stringify({
      project: { ...project, url: projectUrl },
    }),
    findingsResponses: [page("8", { url: findingUrl, name: findingName })],
    findingIds: ["8"],
    sourceRepositories,
  });

test("rechecks decimal native IDs when other evidence uses scientific notation", async () => {
  const findingId = "1000000000000000000001";
  const projectId = "1000000000000000000002";
  const report = selectSemgrepPlatformFindings({
    deployment: "example",
    ref,
    projectResponse: `{"project":{"url":"${url}","name":"example/project","id":${projectId}}}`,
    findingsResponses: `{"findings":[{"id":${findingId},"ref":"${ref}","repository":{"id":${projectId},"url":"${url}"},"size":1e40}]}`,
    findingIds: [findingId],
  });
  await using fixture = await localReportFixture(url);
  await fixture.writeJson(report);
  const first = await fixture.prepare();
  expect(first.preview.excluded).toEqual([]);
  expect((await first.import()).counts.created).toBe(1);
  expect((await (await fixture.prepare()).import()).counts.unchanged).toBe(1);
});

test("two selected Platform SAST IDs from separate pages replay unchanged in SQLite", async () => {
  const report = selection([
    page("8"),
    ...ids.map((id) => "\uFEFF" + page(id)),
  ]);
  const [left, right] = normalizeSemgrepFindings(
    report,
    { sourceRepositoryUrl: url },
    "local",
  ).findings;
  expect(left!.evidence.source_data!["project"]).not.toBe(
    right!.evidence.source_data!["project"],
  );
  await using fixture = await localReportFixture(url);
  await fixture.writeJson(report);
  const first = await fixture.prepare();
  expect(first.preview.excluded).toEqual([]);
  expect(first.preview.findings).toHaveLength(2);
  expect(first.preview.findings[0]?.evidence).toMatchObject({
    branch: ref,
    severity: "medium",
    locations: [{ path: "src/example.ts", line: 2 }],
    details: {
      rule: { id: "sample.rule" },
      source_status: "reviewing",
      weakness_ids: ["CWE-79"],
    },
  });
  expect(await fixture.read()).toEqual([]);
  expect((await first.import()).counts).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  const saved = await fixture.read();
  expect(new Set(saved.map((row) => row.sourceFindingId)).size).toBe(2);
  const originals = saved.map(
    (row) => row.evidence.source_data?.[rawFindingKey],
  );
  for (const id of ids)
    expect(
      originals.some(
        (raw) =>
          typeof raw === "string" &&
          raw.includes('"id":' + id) &&
          raw.includes('"score":1.0000000000000000003'),
      ),
    ).toBe(true);
  const reorderedPages = ids.map((id) =>
    page(id).replace(
      `"id":${id},"repository":${JSON.stringify({ name: project.name, url })}`,
      `"repository":${JSON.stringify({ url, name: project.name })},"id":${id}`,
    ),
  );
  expect(reorderedPages[0]).not.toBe(page(ids[0]!));
  await fixture.writeJson(selection(reorderedPages));
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  expect(await fixture.read()).toEqual(saved);
  expect(() =>
    normalizeSemgrepFindings(report, { sourceRepositoryUrl: url }, "cloud"),
  ).toThrow("local import");
});

test("native IDs and source URLs can identify a row with an empty display name", () => {
  const report = selectRow({ repository: { id: project.id, url, name: "" } });
  expect(report.findings).toHaveLength(1);
  expect(() => selectRow({ repository: { url, name: "" } })).toThrow(
    "project and ref",
  );
});

test("a short project name accepts a qualified display name on the same encoded clone URL", () => {
  const projectUrl = url.replace("project", "%70roject.git");
  const report = selectSemgrepPlatformFindings({
    deployment: "example",
    ref,
    projectResponse: JSON.stringify({
      project: { ...project, name: "project", url: projectUrl },
    }),
    findingsResponses: page("8", { url, name: "example/project" }),
    findingIds: ["8"],
  });
  expect(report.findings).toHaveLength(1);
});

test("a URL-less name must identify the exact project path on a private server", () => {
  const label = (path: string, name: string) =>
    selectSemgrepPlatformFindings({
      deployment: "example",
      ref,
      findingIds: ["8"],
      projectResponse: JSON.stringify({
        project: {
          ...project,
          name: "renamed",
          url: "https://scm.example.test/" + path,
        },
      }),
      findingsResponses: JSON.stringify({
        findings: [{ id: 8, ref, repository: { id: project.id, name } }],
      }),
    });
  expect(() => label("team/project.git", "team/project")).toThrow(
    "project and ref",
  );
  for (const name of ["team/proj%20one", "team/proj one"])
    expect(label("team/proj%20one", name).findings).toHaveLength(1);
});

test("contradictory private SCM mappings fail regardless of their order", () => {
  const web = "https://scm.example.test/team/project";
  const refs: ExternalSourceRepository[] = [
    { url: web, platform: "gitlab" },
    { url: web, platform: "github" },
  ];
  for (const sources of [refs, [...refs].reverse()])
    expect(() => selectedRepository(web, web, sources)).toThrow(
      "Conflicting SCM",
    );
});

test("replaying a saved selection requires the original string project ID", async () => {
  const report = selectedRepository(url, url);
  await using fixture = await localReportFixture(url);
  await writeFile(
    fixture.file,
    JSON.stringify(report).replace('"id":"77"', '"id":77.00000000000000000001'),
  );
  await expect(fixture.prepare()).rejects.toThrow("selected project ID");
});

test("new captures require a fully qualified ref while an older file replays its original ref", async () => {
  const branch = "release";
  const pageWithRef = page("8", { ref: branch });
  const input = {
    deployment: "example",
    ref: branch,
    projectResponse: JSON.stringify({ project }),
    findingsResponses: pageWithRef,
    findingIds: ["8"],
  };
  expect(() => selectSemgrepPlatformFindings(input)).toThrow("fully qualified");
  const prior = {
    ...selectedRepository(url, url),
    ref: branch,
    findings: [JSON.stringify(JSON.parse(pageWithRef).findings[0])],
  };
  await using fixture = await localReportFixture(url);
  await fixture.writeJson(prior);
  const first = await fixture.prepare();
  expect(first.preview.findings[0]?.evidence.branch).toBe(branch);
  expect((await first.import()).counts.created).toBe(1);
  expect((await (await fixture.prepare()).import()).counts.unchanged).toBe(1);
});

test("selection requires exact IDs from the selected source and ref", () => {
  const [first, second] = ids as [string, string];
  expect(() => selection([page(first)])).toThrow(second);
  expect(() => selection([page(first), page(first)])).toThrow("Duplicate");
  for (const options of [
    { ref: "refs/heads/main" },
    { url: "https://github.com/example/other" },
  ])
    expect(() => selection([page(first), page(second, options)])).toThrow(
      "project and ref",
    );
  const report = selection(ids.map((id) => page(id)));
  expect(() =>
    normalizeSemgrepFindings(
      report,
      { sourceRepositoryUrl: "https://github.com/example/other" },
      "local",
    ),
  ).toThrow("declared source");
});

test.each([
  ["github.com", undefined],
  ["github.com.", undefined],
  ["git.example.test", "https://git.example.test/example/PROJECT"],
  ["git.example.test", "git@git.example.test:example/project.git"],
  ["git.example.test", "ssh://git@git.example.test/example/project.git"],
] as const)(
  "GitHub input on %s agrees with reader source %s in file and SDK imports",
  async (host, hint) => {
    const projectUrl = `https://${host}:443/Example/Project`;
    const findingUrl = `https://${host}/example/PROJECT`;
    const declared = `https://${host}/EXAMPLE/project.git`;
    const sources = hint ? [{ url: hint, platform: "github" as const }] : [];
    const report = selectedRepository(
      projectUrl,
      findingUrl,
      sources,
      "EXAMPLE/Project",
    );
    await using fixture = await localReportFixture(declared);
    await fixture.writeJson(report);
    const options = {
      ...platformSource,
      repository: fixture.repository,
      sourceRepositoryUrl: declared,
    };
    const dependencies = {
      environment: fixture.environment,
      sourceRepositories: sources,
    };
    const file = await prepareLocalExternalImport(
      fixture.file,
      options,
      dependencies,
    );
    expect(
      (await prepareNormalizedLocalImport(file.preview, options, dependencies))
        .preview.findings,
    ).toHaveLength(1);
  },
);

test.each([
  ["github.com", "https::HTTPS://github.com/example/project", true],
  ["github.com", "https://a@b@github.com/example/project", false],
  ["github.com", "https://a%40b@github.com/example/project", true],
  ["github.com", "https://reader%0A@github.com/example/project", false],
  ["github.com", "https://a:b%0a@github.com/example/project", false],
  ["github.com", "https://a%00b@github.com/example/project", false],
  ["git.example.test", "https://git.example.test/example/project.git", false],
  ["git.example.test", "ssh://git@git.example.test/example/project", false],
  ["git.example.test", "ssh://git@git.example.test:443/example/project", false],
  ["git.example.test", "deploy@git.example.test:example/project", false],
  ["github.com", "ssh://deploy@ssh.github.com:443/example/project.git", false],
  ["github.com", "ssh://git@ssh.github.com:443/example/project.git", true],
  ["gitlab.com", "ssh://git@altssh.gitlab.com:443/example/project.git", true],
  [
    "bitbucket.org",
    "ssh://git@altssh.bitbucket.org:443/example/project.git",
    true,
  ],
] as const)(
  "binds %s to its Git fetch remote %s",
  async (host, remote, matches) => {
    const projectUrl = `https://${host}/example/project`;
    await using fixture = await localReportFixture(remote);
    await fixture.writeJson(selectedRepository(projectUrl, projectUrl));
    if (matches)
      expect((await fixture.prepare()).preview.findings).toHaveLength(1);
    else {
      await expect(fixture.prepare()).rejects.toThrow("configured remote");
      expect(await fixture.read()).toEqual([]);
    }
  },
);

test.each([
  "HTTPS://github.com/example/project",
  "HTTPS::https://github.com/example/project",
  url,
])(
  "mixed-case Git helper identity for %s follows the checkout's actual executable lookup",
  async (remote) => {
    await using fixture = await localReportFixture(remote);
    await fixture.writeJson(selectedRepository(url, url));
    if (remote === url)
      Object.assign(fixture.environment, {
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "remote.origin.vcs",
        GIT_CONFIG_VALUE_0: "HTTPS",
      });
    const gitCore = join(fixture.root, "git-core");
    await mkdir(gitCore);
    Object.assign(fixture.environment, {
      [process.platform === "win32" ? "Git_Exec_Path" : "GIT_EXEC_PATH"]:
        gitCore,
    });
    const suffix = process.platform === "win32" ? ".exe" : "";
    const lower = join(gitCore, "git-remote-https" + suffix);
    const upper = join(gitCore, "git-remote-HTTPS" + suffix);
    await writeFile(lower, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
    if (!(await stat(upper).catch(() => undefined))) {
      await writeFile(upper, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
      await expect(fixture.prepare()).rejects.toThrow("configured remote");
      await unlink(upper);
      await link(lower, upper);
    }
    expect((await fixture.prepare()).preview.findings).toHaveLength(1);
  },
);

test.each([
  ["127.0.0.1", "127.0.0.1", true],
  ["127.0.0.1", "0177.1.", false],
  ["127.0.0.1", "127%2e1", false],
  ["[::1]", "[::1]", true],
  ["[::ffff:7f00:1]", "[::ffff:127.0.0.1]", false],
] as const)(
  "compares Git request authority %s with %s",
  async (host, fetchHost, matches) => {
    const source = `https://${host}/org/project`;
    await using fixture = await localReportFixture(
      `https://${fetchHost}/org/project`,
    );
    await fixture.writeJson(selectedRepository(source, source));
    if (matches)
      expect((await fixture.prepare()).preview.findings).toHaveLength(1);
    else await expect(fixture.prepare()).rejects.toThrow("configured remote");
  },
);

test.each([url, undefined])(
  "a helper-only remote does not override other fetch evidence: %s",
  async (origin) => {
    await using fixture = await localReportFixture(origin);
    await fixture.writeJson(selectedRepository(url, url));
    Object.assign(fixture.environment, {
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "remote.backup.vcs",
      GIT_TRACE: "1",
      GIT_TRACE_PERFORMANCE: "1",
      GIT_CONFIG_VALUE_0: "example",
    });
    if (origin)
      expect((await fixture.prepare()).preview.findings).toHaveLength(1);
    else await expect(fixture.prepare()).rejects.toThrow("configured remote");
  },
);

test("a selection checks every caller-supplied source before saving API findings", () => {
  const foreign = { url: "https://github.com/example/other" };
  for (const refs of [[foreign], [{ url }, foreign]]) {
    expect(() => selectedRepository(url, url, refs)).toThrow(
      "reader's source repository",
    );
    expect(() =>
      normalizeSemgrepFindings(
        selectedRepository(url, url),
        { sourceRepositoryUrl: url, sourceRepositories: refs },
        "local",
      ),
    ).toThrow("reader's source repository");
  }
});

test("each named Git remote contributes only its active fetch URL", async () => {
  await using fixture = await localReportFixture(
    "https://github.com/example/other",
  );
  await fixture.writeJson(selectedRepository(url, url));
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", fixture.repository, ...args], {
      env: fixture.environment,
    });
  git(
    "config",
    "--file",
    join(fixture.repository, ".git", "config"),
    "--add",
    "remote.origin.url",
    url,
  );
  await expect(fixture.prepare()).rejects.toThrow("configured remote");
  git("remote", "add", "second", url);
  expect((await fixture.prepare()).preview.findings).toHaveLength(1);
});

test.each([
  { origin: undefined, fallback: undefined, matches: true },
  { origin: "./mirror", fallback: undefined, matches: true },
  { origin: url, fallback: undefined, matches: true },
  { origin: undefined, fallback: url, matches: true },
  {
    origin: undefined,
    fallback: "https://github.com/example/other",
    matches: false,
  },
  {
    origin: "https://github.com/example/other",
    fallback: undefined,
    matches: false,
  },
])(
  "resolves the effective fetch source for a push-only remote with origin $origin and rewrite $fallback",
  async ({ origin, fallback, matches }) => {
    await using fixture = await localReportFixture(origin);
    await fixture.writeJson(selectedRepository(url, url));
    Object.assign(fixture.environment, {
      GIT_CONFIG_COUNT: fallback ? "2" : "1",
      GIT_CONFIG_KEY_0: "remote.backup.pushurl",
      GIT_CONFIG_VALUE_0: "https://github.com/example/backup",
      ...(fallback && {
        GIT_CONFIG_KEY_1: `url.${fallback}.insteadOf`,
        GIT_CONFIG_VALUE_1: "backup",
      }),
    });
    if (matches) {
      expect((await fixture.prepare()).preview.findings).toHaveLength(1);
    } else {
      await expect(fixture.prepare()).rejects.toThrow("configured remote");
    }
  },
);

test("the Platform HTTP URL is serialized while Git fetch paths keep their literal bytes", async () => {
  const raw = "https://git.example.test/org/repo{one}";
  const encoded = new URL(raw).href;
  for (const remote of [raw, encoded]) {
    await using fixture = await localReportFixture(remote);
    const references = [{ url: raw }];
    const selection = selectedRepository(raw, encoded, references);
    await fixture.writeJson(selection);
    if (remote === encoded) {
      const options = { ...platformSource, repository: fixture.repository };
      const dependencies = {
        environment: fixture.environment,
        sourceRepositories: references,
      };
      const prepared = await prepareLocalExternalImport(
        fixture.file,
        options,
        dependencies,
      );
      expect(
        (
          await prepareNormalizedLocalImport(
            prepared.preview,
            options,
            dependencies,
          )
        ).preview.findings,
      ).toHaveLength(1);
      expect(
        prepared.preview.findings[0]!.evidence.details!.repository!.url,
      ).toBe(raw);
    } else {
      await expect(fixture.prepare()).rejects.toThrow("configured remote");
    }
  }
});

test("a file and its projected SDK rows use the same declared GitHub repository alias", async () => {
  const native = "https://git.example.test/org/project";
  const declared = native + ".git";
  const encoded = "https://git.example.test/org/%70roject.git";
  const references = [{ url: declared, platform: "github" as const }];
  await using fixture = await localReportFixture(encoded);
  const report = selectedRepository(native, native, references);
  await fixture.writeJson(report);
  const options = {
    ...platformSource,
    repository: fixture.repository,
    sourceRepositoryUrl: declared,
  };
  const deps = {
    environment: fixture.environment,
    sourceRepositories: references,
  };
  const file = await prepareLocalExternalImport(fixture.file, options, deps);
  for (const normalized of [
    file.preview,
    normalizeSemgrepFindings(
      report,
      { sourceRepositoryUrl: declared, sourceRepositories: references },
      "local",
    ),
  ]) {
    expect(
      (await prepareNormalizedLocalImport(normalized, options, deps)).preview
        .findings,
    ).toHaveLength(1);
  }
});

test.each([
  "https://git.example.test/group/project.git",
  "git@git.example.test:group/project.git",
])("a trusted private GitLab mapping accepts clone %s", async (checkout) => {
  const web = "https://git.example.test/group/project";
  const clone = web + ".git";
  const source = { url: web, platform: "gitlab" as const };
  await using fixture = await localReportFixture(checkout);
  await fixture.writeJson(selectedRepository(web, clone, [source]));
  const options = { ...platformSource, repository: fixture.repository };
  const deps = {
    environment: fixture.environment,
    sourceRepositories: [source],
  };
  const prepared = await prepareLocalExternalImport(
    fixture.file,
    options,
    deps,
  );
  expect(
    (await prepareNormalizedLocalImport(prepared.preview, options, deps))
      .preview.findings,
  ).toHaveLength(1);
  for (const refs of [
    [],
    [{ url: web + "-other", platform: "gitlab" as const }],
  ]) {
    await expect(
      prepareLocalExternalImport(fixture.file, options, {
        ...deps,
        sourceRepositories: refs,
      }),
    ).rejects.toThrow(/repository|project/);
  }
});

test("an extra custom Git reader source must match the selected checkout", async () => {
  const nativeUrl = "https://git.example.test/example/project";
  await using fixture = await localReportFixture(nativeUrl);
  await fixture.writeJson(selectedRepository(nativeUrl, nativeUrl));
  const options = { ...platformSource, repository: fixture.repository };
  const dependencies = {
    environment: fixture.environment,
    sourceRepositories: [{ url: nativeUrl + ".git" }],
  };
  await expect(
    prepareLocalExternalImport(fixture.file, options, dependencies),
  ).rejects.toThrow(/repository|remote/i);
});

test("raw UTF-8 and percent-encoded HTTP paths identify the same project", () => {
  const report = selectedRepository(
    "https://git.example.test/example/café",
    "https://git.example.test/example/caf%c3%a9",
  );
  expect(report.findings).toHaveLength(1);
});

test("a row without a repository URL needs the same project ID and name", () => {
  // The Findings API example has a short SCM name alongside an exact repository URL.
  expect(
    selectRow({ repository: { name: "project", url } }).findings,
  ).toHaveLength(1);
  expect(() =>
    selectRow({ repository: { name: "another-project", url } }),
  ).toThrow("project and ref");
  const repository = { name: project.name, url: null };
  expect(() => selectRow({ repository })).toThrow("project and ref");
  expect(
    selectRow({ repository: { ...repository, id: project.id } }).findings,
  ).toHaveLength(1);
  expect(() =>
    selectRow({
      repository: { ...repository, id: project.id, name: "other/project" },
    }),
  ).toThrow("project and ref");
  expect(() =>
    selectRow({ repository: { ...project, id: project.id + 1 } }),
  ).toThrow("project and ref");
});

test("selection rejects rows explicitly identified as other Semgrep products", () => {
  for (const fields of [{ issue_type: "ai_sast" }, { product: "sca" }])
    expect(() => selectRow(fields)).toThrow("SAST");
});

test("projects Windows-relative paths and retains the original spelling", () => {
  const file_path = "src\\example.ts";
  const selection = selectRow({
    location: { file_path, line: 2, end_line: 4 },
  });
  const { findings } = normalizeSemgrepFindings(
    selection,
    { sourceRepositoryUrl: url },
    "local",
  );
  expect(findings[0]!.evidence.locations).toEqual([
    { path: "src/example.ts", line: 2 },
  ]);
  expect(
    JSON.parse(String(findings[0]!.evidence.source_data?.[rawFindingKey]))
      .location.file_path,
  ).toBe(file_path);
});

test.each(["../outside.ts", "https://example.test/source.ts"])(
  "unprojectable path %s stays in the stored native evidence",
  async (file_path) => {
    const location = { file_path, line: 2, end_line: 4 };
    await using fixture = await localReportFixture(url);
    await fixture.writeJson(selectRow({ location }));
    expect((await (await fixture.prepare()).import()).counts.created).toBe(1);
    const [stored] = await fixture.read();
    expect(stored!.evidence.locations).toEqual([]);
    expect(stored!.evidence.details?.code?.end_line ?? null).toBeNull();
    expect(
      JSON.parse(String(stored!.evidence.source_data?.[rawFindingKey]))
        .location,
    ).toEqual(location);
  },
);

test("direct SDK imports respect the native source even with a caller-selected ID", async () => {
  await using fixture = await localReportFixture(url);
  const normalized = normalizeSemgrepFindings(
    selectRow({}),
    { sourceRepositoryUrl: url },
    "local",
  );
  const options = {
    repository: fixture.repository,
    provider: "semgrep" as const,
    sourceKey: fixture.sourceKey,
  };
  const deps = { environment: fixture.environment };
  const fetch = mock(async () => {
    throw new Error("Unexpected Cloud request");
  });
  await expect(
    prepareNormalizedExternalPublication(normalized, options, {
      ...deps,
      fetch,
    }),
  ).rejects.toThrow("local import");
  const oversized = structuredClone(normalized);
  oversized.findings[0]!.evidence.title = "a".repeat(256 * 1024);
  await expect(
    prepareNormalizedExternalPublication(oversized, options, {
      ...deps,
      fetch,
    }),
  ).rejects.toThrow("local import");
  expect(fetch).not.toHaveBeenCalled();

  const row = normalized.findings[0]!;
  const nativeId = row.source_finding_id;
  row.source_finding_id = normalizeSemgrepFindings(
    selection([page("9")], ["9"]),
    { sourceRepositoryUrl: url },
    "local",
  ).findings[0]!.source_finding_id;
  await expect(
    prepareNormalizedLocalImport(normalized, options, deps),
  ).rejects.toThrow("does not match its native occurrence");
  row.source_finding_id = "chosen-id";
  const prepared = await prepareNormalizedLocalImport(
    normalized,
    options,
    deps,
  );
  expect(prepared.preview.findings[0]!.source_finding_id).toBe("chosen-id");

  const genericOptions = { ...options, provider: "wiz" as const };
  delete row.evidence.source_data!["format"];
  await expect(
    prepareNormalizedLocalImport(normalized, genericOptions, deps),
  ).rejects.toThrow("semgrep provider");
  await expect(
    prepareNormalizedExternalPublication(normalized, genericOptions, {
      ...deps,
      fetch,
    }),
  ).rejects.toThrow("local import");
  const data = row.evidence.source_data!;
  const original = data[rawFindingKey] as string;
  data[rawFindingKey] = JSON.stringify({
    ...JSON.parse(original),
    id: "invalid",
  });
  await expect(
    prepareNormalizedLocalImport(normalized, options, deps),
  ).rejects.toThrow("Semgrep Platform ID");
  data[rawFindingKey] = original;
  row.evidence.details!.repository!.url = "https://github.com/example/other";
  await expect(
    prepareNormalizedLocalImport(normalized, options, deps),
  ).rejects.toThrow("original Semgrep repository and ref");

  row.evidence.details!.repository!.url = url;
  const rejectIncomplete = async () => {
    await expect(
      prepareNormalizedLocalImport(normalized, options, deps),
    ).rejects.toThrow(/Semgrep/i);
    await expect(
      prepareNormalizedExternalPublication(normalized, options, {
        ...deps,
        fetch,
      }),
    ).rejects.toThrow("local import");
  };
  delete data["deployment"];
  await rejectIncomplete();
  row.source_finding_id = nativeId;
  for (const raw of [
    { [rawFindingKey]: original },
    JSON.parse(original),
    undefined,
  ]) {
    if (raw) row.evidence.source_data = raw;
    else delete row.evidence.source_data;
    await rejectIncomplete();
  }
  expect(fetch).not.toHaveBeenCalled();

  const source_data = {
    findingJson: "{}",
    project: "example",
    ref,
    product: "sast",
    deployment: "example",
  };
  const evidence = { title: "Example", severity: "low" as const, source_data };
  const generic = {
    read: 1,
    excluded: [],
    findings: [{ source_finding_id: "vendor-1", evidence }],
  };
  expect(
    (await prepareNormalizedLocalImport(generic, genericOptions, deps)).preview
      .findings,
  ).toHaveLength(1);
  const credentials = async () => {
    throw new Error("Reached Cloud credentials");
  };
  await expect(
    prepareNormalizedExternalPublication(generic, genericOptions, {
      ...deps,
      fetch,
      credentials,
    }),
  ).rejects.toThrow("Reached Cloud credentials");
});

test("every selected native project must have an independent reference when supplied", async () => {
  const secondUrl = "https://github.com/example/other";
  const second = selectedRepository(secondUrl, secondUrl);
  second.project.id = "78";
  const combine = (selection: typeof second) =>
    normalizeSemgrepFindings(
      selection,
      { sourceRepositoryUrl: selection.project.url },
      "local",
    ).findings;
  const input = {
    read: 2,
    findings: [...combine(selectRow({})), ...combine(second)],
    excluded: [],
  };
  await using fixture = await localReportFixture();
  const options = {
    ...platformSource,
    repository: fixture.repository,
    provider: "semgrep" as const,
  };
  const prepare = (urls: string[]) =>
    prepareNormalizedLocalImport(input, options, {
      environment: fixture.environment,
      sourceRepositories: urls.map((url) => ({ url })),
    });
  await expect(prepare([url])).rejects.toThrow("reader's source repository");
  expect((await prepare([url, secondUrl])).preview.findings).toHaveLength(2);
});

test("a hosted projected alias uses the same fetch match while a separate generic source still must match", async () => {
  const web = "https://gitlab.com/example/project";
  const native = web + ".git";
  const report = normalizeSemgrepFindings(
    selectedRepository(native, native),
    { sourceRepositoryUrl: native },
    "local",
  );
  const row = report.findings[0]!;
  row.evidence.details!.repository!.url = web;
  await using fixture = await localReportFixture(
    "ssh://git@altssh.gitlab.com:443/example/project.git",
  );
  const options = {
    ...platformSource,
    repository: fixture.repository,
    provider: "semgrep" as const,
  };
  const deps = { environment: fixture.environment };
  expect(
    (await prepareNormalizedLocalImport(report, options, deps)).preview
      .findings,
  ).toHaveLength(1);
  const generic = structuredClone(row);
  generic.source_finding_id = "unrelated";
  delete generic.evidence.source_data;
  generic.evidence.details!.repository!.url =
    "https://gitlab.com/example/other";
  report.findings.push(generic);
  report.read++;
  const both = {
    ...deps,
    sourceRepositories: [
      { url: native },
      { url: generic.evidence.details!.repository!.url! },
    ],
  };
  for (const reader of [deps, both]) {
    await expect(
      prepareNormalizedLocalImport(report, options, reader),
    ).rejects.toThrow("configured remote");
  }
  execFileSync(
    "git",
    [
      "-C",
      fixture.repository,
      "remote",
      "add",
      "second",
      generic.evidence.details!.repository!.url!,
    ],
    { env: fixture.environment },
  );
  expect(
    (await prepareNormalizedLocalImport(report, options, both)).preview
      .findings,
  ).toHaveLength(2);
});

test("ordinary and Platform findings retain a shared GitHub Enterprise reader hint", async () => {
  const native = "https://git.example.test/Example/Project";
  const ordinary = native.toLowerCase();
  const sourceRepositories = [{ url: native, platform: "github" as const }];
  const report = normalizeSemgrepFindings(
    selectedRepository(native, native, sourceRepositories),
    { sourceRepositoryUrl: native },
    "local",
  );
  const other = {
    source_finding_id: "ordinary",
    evidence: {
      title: "Ordinary finding",
      severity: "low" as const,
      details: { kind: "sast" as const, repository: { url: ordinary } },
    },
  };
  await using fixture = await localReportFixture(native);
  const options = { ...platformSource, repository: fixture.repository };
  const prepare = (findings: typeof report.findings) =>
    prepareNormalizedLocalImport(
      { read: findings.length, findings, excluded: [] },
      options,
      { environment: fixture.environment, sourceRepositories },
    );
  expect((await prepare([other])).preview.findings).toHaveLength(1);
  for (const findings of [
    [...report.findings, other],
    [other, ...report.findings],
  ])
    expect((await prepare(findings)).preview.findings).toHaveLength(2);
  other.evidence.details.repository.url = ordinary + "-other";
  await expect(prepare([...report.findings, other])).rejects.toThrow(
    "configured remote",
  );
});

test("ordinary findings still validate the checkout when their URL equals the selected project's", async () => {
  const native = "https://gitlab.com/example/project";
  const report = normalizeSemgrepFindings(
    selectedRepository(native, native),
    { sourceRepositoryUrl: native },
    "local",
  );
  await using fixture = await localReportFixture(
    "ssh://git@altssh.gitlab.com:443/example/project.git",
  );
  const options = { ...platformSource, repository: fixture.repository };
  const deps = { environment: fixture.environment };
  const ordinary = structuredClone(report.findings[0]!);
  ordinary.source_finding_id = "ordinary";
  delete ordinary.evidence.source_data;
  await expect(
    prepareNormalizedLocalImport(
      { ...report, findings: [ordinary] },
      options,
      deps,
    ),
  ).rejects.toThrow("configured remote");
  report.findings.push(ordinary);
  report.read++;
  await expect(
    prepareNormalizedLocalImport(report, options, deps),
  ).rejects.toThrow("configured remote");
});

test("an ordinary finding without a repository still checks the shared reader source", async () => {
  const native = "https://gitlab.com/example/project";
  const ssh = "ssh://git@altssh.gitlab.com:443/example/project.git";
  const { findings } = normalizeSemgrepFindings(
    selectedRepository(native, native),
    { sourceRepositoryUrl: native },
    "local",
  );
  const ordinary = {
    source_finding_id: "ordinary",
    evidence: { title: "Example", severity: "low" as const },
  };
  await using fixture = await localReportFixture(ssh);
  const options = { ...platformSource, repository: fixture.repository };
  const prepare = (rows: typeof findings) =>
    prepareNormalizedLocalImport(
      { read: rows.length, findings: rows, excluded: [] },
      options,
      {
        environment: fixture.environment,
        sourceRepositories: [{ url: native }],
      },
    );
  expect((await prepare(findings)).preview.findings).toHaveLength(1);
  await expect(prepare([ordinary])).rejects.toThrow("configured remote");
  await expect(prepare([...findings, ordinary])).rejects.toThrow(
    "configured remote",
  );
  execFileSync(
    "git",
    ["-C", fixture.repository, "remote", "add", "web", native],
    {
      env: fixture.environment,
    },
  );
  expect(
    (await prepare([...findings, ordinary])).preview.findings,
  ).toHaveLength(2);
});
