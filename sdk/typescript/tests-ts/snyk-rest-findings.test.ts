import { expect, test } from "bun:test";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import {
  collectSnykIssues,
  normalizeSnykIssues,
  type CollectSnykIssuesOptions,
} from "../src/snyk-rest-findings.js";
import {
  createAndReplayFinding,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";

import {
  snykLocalFixture,
  snykOptions as options,
  snykProject as project,
  snykRestFixture,
  snykIssue as issue,
} from "./support/snyk-rest-fixtures.js";

const environment = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SNYK_TOKEN: "test-token",
};

function transport(...responses: unknown[]) {
  const calls: URL[] = [];
  return {
    calls,
    collect(
      selected: CollectSnykIssuesOptions = options,
      env: NodeJS.ProcessEnv = environment,
    ) {
      return collectSnykIssues(selected, {
        environment: env,
        fetch: async (url, init) => {
          calls.push(url);
          expect(init.redirect).toBe("error");
          expect(new Headers(init.headers).get("authorization")).toBe(
            "token test-token",
          );
          if (responses.length === 0) throw new Error("Unexpected request");
          const next = responses.shift();
          return next instanceof Response ? next : Response.json(next);
        },
      });
    },
  };
}

test("the Issues normalizer keeps long issue titles by default", async () => {
  const row = issue(false);
  row.attributes.title = "é".repeat(257);
  const report = await transport(project(), { data: [row] }).collect();
  expect(normalizeSnykIssues(report).findings[0]?.evidence.title).toBe(
    row.attributes.title,
  );
  const cloud = normalizeSnykIssues(report, "cloud");
  expect(cloud.findings).toHaveLength(0);
  expect(cloud.excluded[0]?.reason).toContain("title");
});

test.each(["open-source", "code"] as const)(
  "Snyk %s retries the scoped page, saves original evidence, and replays unchanged in SQLite",
  async (product) => {
    const code = product === "code";
    const asset = project(code ? "sast" : "npm");
    const record = issue(code);
    if (code) {
      const { representations } = record.attributes.coordinates[0]!;
      const location = representations[0]!.sourceLocation!;
      for (const file of [".", "src/", "src/.", "src\\app.ts"])
        representations.push({ sourceLocation: { ...location, file } });
    }
    const path = `/rest/orgs/${options.organizationId}/issues`;
    const cursor = "next+/=";
    const api = transport(
      asset,
      {
        data: [],
        links: {
          self: path,
          prev: null,
          next: `?starting_after=${encodeURIComponent(cursor)}`,
        },
      },
      new Response("try again", {
        status: 429,
        headers: {
          "Retry-After": "0",
          Location: "https://other.invalid/issues",
        },
      }),
      {
        data: [record],
        links: {
          self: { href: `?starting_after=${encodeURIComponent(cursor)}` },
          prev: "?ending_before=opaque",
        },
      },
    );
    const report = await api.collect({ ...options, product });
    expect(api.calls.map((url) => url.pathname)).toEqual([
      `/rest/orgs/${options.organizationId}/projects/${options.projectId}`,
      path,
      path,
      path,
    ]);
    for (const url of api.calls.slice(1)) {
      expect(url.origin).toBe(options.apiOrigin);
      expect(Object.fromEntries(url.searchParams)).toMatchObject({
        "scan_item.type": "project",
        "scan_item.id": options.projectId,
        type: record.attributes.type,
        status: "open,resolved",
      });
      expect(url.searchParams.get("include_code_flows")).toBe(
        code ? "true" : null,
      );
    }
    expect(api.calls[2]!.searchParams.get("starting_after")).toBe(cursor);
    expect(api.calls[3]!.href).toBe(api.calls[2]!.href);
    await using f = await snykLocalFixture({
      remote: options.sourceRepositoryUrl,
    });
    await f.writeJson(report);
    const stored = await createAndReplayFinding(f);
    const retained = stored.evidence.source_data!;
    expect(JSON.parse(retained["issueJson"] as string)).toEqual(record);
    expect(JSON.parse(retained["projectJson"] as string)).toEqual(asset.data);
    if (code) {
      expect(stored.evidence).toMatchObject({
        locations: [{ path: "src/app.ts", line: 3 }],
        code_revision: "abc123",
        details: { kind: "sast", rule: { id: "sample-rule" } },
      });
    } else {
      expect(stored.evidence.packages).toMatchObject([
        {
          name: "example-lib",
          installed_version: "1.0.0",
          manifest_path: "app/package.json",
        },
      ]);
    }
  },
);

test("reports the last HTTP error when the retried Snyk cursor is still throttled", async () => {
  const limited = (detail: string) =>
    new Response(detail, { status: 429, headers: { "Retry-After": "0" } });
  const api = transport(
    project(),
    { data: [], links: { next: "?starting_after=more" } },
    limited("first failure"),
    limited("still throttled"),
  );
  await expect(api.collect()).rejects.toThrow(
    "failed (HTTP 429); Retry-After: 0: still throttled",
  );
  expect(api.calls).toHaveLength(4);
  expect(api.calls[3]!.href).toBe(api.calls[2]!.href);
});

test.each([
  ["uat", "api.eu.snyk.io"],
  ["sat", "https://api.eu.snyk.io"],
])(
  "an explicit regional Snyk %s token only reaches its own API",
  async (kind, host) => {
    const payload = Buffer.from(JSON.stringify({ h: host })).toString(
      "base64url",
    );
    const token = `snyk_${kind}.12345678.${payload}.synthetic`;
    const seen: string[] = [];
    const collect = (apiOrigin: string) =>
      collectSnykIssues(
        { ...options, apiOrigin, token },
        {
          environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
          fetch: async (url, init) => {
            seen.push(url.origin);
            expect(new Headers(init.headers).get("authorization")).toBe(
              `token ${token}`,
            );
            return Response.json(
              url.pathname.endsWith("/issues") ? { data: [] } : project(),
            );
          },
        },
      );
    await expect(collect("https://api.snyk.io")).rejects.toThrow(
      "token's API host",
    );
    expect(seen).toHaveLength(0);
    expect((await collect(options.apiOrigin)).complete).toBe(true);
    expect(seen).toEqual([options.apiOrigin, options.apiOrigin]);
  },
);

test("forwarding the environment token keeps its region while a separate SDK token chooses its own", async () => {
  const calls: Array<[string, string | null]> = [];
  const collect = (token: string, apiOrigin?: string) =>
    collectSnykIssues(
      { ...options, token, apiOrigin },
      {
        environment: { ...environment, SNYK_API: options.apiOrigin },
        fetch: async (url, init) => {
          calls.push([
            url.origin,
            new Headers(init.headers).get("authorization"),
          ]);
          return Response.json(
            url.pathname.endsWith("/issues") ? { data: [] } : project(),
          );
        },
      },
    );
  for (const token of [environment.SNYK_TOKEN, environment.SNYK_TOKEN + " "])
    await expect(collect(token)).rejects.toThrow("SNYK_API");
  expect(calls).toBeEmpty();
  await collect(environment.SNYK_TOKEN, options.apiOrigin);
  await collect("separate-token");
  expect(calls).toEqual([
    [options.apiOrigin, "token test-token"],
    [options.apiOrigin, "token test-token"],
    ["https://api.snyk.io", "token separate-token"],
    ["https://api.snyk.io", "token separate-token"],
  ]);
});

test("the Snyk token stays in its configured region and on the selected Issues route", async () => {
  const regional = transport();
  await expect(
    regional.collect(options, {
      ...environment,
      SNYK_API: "https://api.snyk.io",
    }),
  ).rejects.toThrow();
  expect(regional.calls).toEqual([]);

  const next = "https://other.example.invalid/steal?starting_after=more";
  const crossOrigin = transport(project(), { data: [], links: { next } });
  await expect(crossOrigin.collect()).rejects.toThrow();
  expect(crossOrigin.calls.map((url) => url.origin)).toEqual([
    options.apiOrigin,
    options.apiOrigin,
  ]);
});

test("compares the Git HTTP authority of native and selected Snyk repositories", async () => {
  const canonical = "https://127.0.0.1/org/project";
  const ambiguous = "https://0177.1./org/project";
  for (const [source, target] of [
    [canonical, ambiguous],
    [ambiguous, canonical],
  ] as const) {
    const asset = project("npm", target);
    asset.data.attributes.origin = "cli";
    const api = transport(asset, { data: [] });
    await expect(
      api.collect({ ...options, sourceRepositoryUrl: source }),
    ).rejects.toThrow("target URL");
    expect(api.calls).toHaveLength(1);
    const report = snykRestFixture("open-source", {
      sourceRepositoryUrl: source,
    });
    report.projectJson = JSON.stringify(asset.data);
    expect(() => normalizeSnykIssues(report)).toThrow("target URL");
  }
  expect(
    normalizeSnykIssues(
      snykRestFixture("open-source", { sourceRepositoryUrl: canonical }),
    ).findings,
  ).toHaveLength(1);
});

test.each([
  ["numeric links", 123],
  ["a self cursor from a later page", { self: "?starting_after=page-two" }],
  ["a self link to another project", { self: "?scan_item.id=another-project" }],
  ["a self link to another endpoint", { self: "/v1/issues" }],
  ["a previous page before the first", { prev: "?ending_before=opaque" }],
] as const)(
  "rejects %s during collection and saved replay",
  async (_, links) => {
    const page = { data: [issue(false)], links };
    const api = transport(project(), page);
    await expect(api.collect()).rejects.toThrow();
    expect(api.calls).toHaveLength(2);

    const report = snykRestFixture("open-source");
    report.pages[0]!.responseJson = JSON.stringify(page);
    expect(() => normalizeSnykIssues(report)).toThrow();
  },
);

test.each([
  "https://api.snyk.io/rest/orgs/" +
    options.organizationId +
    "/issues?ending_before=opaque",
  "/rest/orgs/another-organization/issues?ending_before=opaque",
  "?scan_item.id=another-project&ending_before=opaque",
  "?ending_before=first&ending_before=second",
  "?starting_after=forward",
])(
  "rejects a later page with an out-of-scope previous link %s",
  async (prev) => {
    const first = { data: [], links: { next: "?starting_after=page-two" } };
    const last = { data: [], links: { prev } };
    const api = transport(project(), first, last);
    await expect(api.collect()).rejects.toThrow("Snyk previous page link");
    expect(api.calls).toHaveLength(3);

    const report = snykRestFixture("open-source");
    report.pages = [
      { startingAfter: null, responseJson: JSON.stringify(first) },
      { startingAfter: "page-two", responseJson: JSON.stringify(last) },
    ];
    expect(() => normalizeSnykIssues(report)).toThrow(
      "Snyk previous page link",
    );
  },
);

test("an invalid issue key cannot hide a duplicate resource UUID in saved pages", async () => {
  const valid = issue(false);
  const invalid = { ...valid, attributes: { ...valid.attributes, key: null } };
  const page = { data: [valid, invalid] };
  await expect(transport(project(), page).collect()).rejects.toThrow(
    "overlapping issue IDs",
  );

  const report = snykRestFixture("open-source");
  report.pages[0]!.responseJson = JSON.stringify(page);
  const result = normalizeSnykIssues(report);
  expect(result.findings).toBeEmpty();
  expect(result.excluded).toMatchObject([
    { position: 1, reason: expect.stringContaining("overlapping issue IDs") },
    { position: 2, reason: expect.stringContaining("Snyk issue key") },
  ]);
});

test("a malformed copy of a scoped issue cannot update its stored evidence", async () => {
  const valid = issue(false);
  const report = snykRestFixture("open-source");
  await using fixture = await snykLocalFixture({
    remote: options.sourceRepositoryUrl,
  });
  await fixture.writeJson(report);
  const saved = await createAndReplayFinding(fixture);

  const changed = {
    ...valid,
    attributes: { ...valid.attributes, title: "Changed" },
  };
  const { attributes, ...missing } = valid;
  const independent = {
    ...valid,
    id: "55555555-5555-4555-8555-555555555555",
    attributes: { ...attributes, key: "independent" },
  };
  // An explicitly different product remains a per-row exclusion.
  const otherProduct = {
    ...independent,
    attributes: { ...independent.attributes, type: "code" },
  };
  for (const malformed of [
    missing,
    { ...valid, id: undefined },
    { ...valid, id: "invalid" },
  ]) {
    const page = { data: [changed, malformed, independent, otherProduct] };
    report.pages[0]!.responseJson = JSON.stringify(page);
    await fixture.writeJson(report);

    const prepared = await fixture.prepare();
    expect(prepared.preview.excluded.map((row) => row.position)).toEqual([
      1, 2, 4,
    ]);
    expect((await prepared.import()).counts.updated).toBe(0);
    const rows = await fixture.read();
    expect(rows).toHaveLength(2);
    expect(rows).toContainEqual(saved);
  }
});

test("Snyk selections keep SCM coordinates out of CLI and API projects", async () => {
  async function capture(origin: string, independent = false) {
    const asset = project("sast");
    asset.data.attributes.origin = origin;
    const row = issue(true);
    if (independent) {
      row.id = "55555555-5555-4555-8555-555555555555";
      row.attributes.key = "independent";
    }
    const report = await transport(asset, { data: [row] }).collect({
      ...options,
      product: "code",
    });
    return normalizeSnykIssues(report);
  }

  const cli = await capture("cli");
  const scm = await capture("github");
  const api = await capture("api", true);
  await using fixture = await snykLocalFixture({
    remote: options.sourceRepositoryUrl,
  });
  await (await fixture.prepareNormalized(cli)).import();
  const saved = await fixture.read();
  expect(saved[0]!.evidence.locations).toEqual([]);
  expect(scm.findings[0]!.evidence.locations).toEqual([
    { path: "src/app.ts", line: 3 },
  ]);

  await expect(
    fixture.prepareNormalized({ ...cli, findings: scm.findings }),
  ).rejects.toThrow("project scope");
  await expect(
    fixture.prepareNormalized({
      read: 2,
      excluded: [],
      findings: [...scm.findings, ...api.findings],
    }),
  ).rejects.toThrow("project scope");
  expect(await fixture.read()).toEqual(saved);
  expect(
    (
      await (
        await fixture.prepareNormalized({ ...cli, findings: api.findings })
      ).import()
    ).counts.created,
  ).toBe(1);
});

test("normalized Snyk selections cannot import two keys for one native issue", async () => {
  const first = normalizeSnykIssues(snykRestFixture("open-source"));
  const nextIssue = issue(false);
  nextIssue.attributes.key = "rekeyed";
  const report = snykRestFixture("open-source");
  report.pages[0]!.responseJson = JSON.stringify({ data: [nextIssue] });
  const second = normalizeSnykIssues(report);
  expect(first.findings[0]!.source_finding_id).not.toBe(
    second.findings[0]!.source_finding_id,
  );
  await using fixture = await snykLocalFixture({
    remote: options.sourceRepositoryUrl,
  });
  const selected = {
    ...first,
    read: 2,
    findings: [...first.findings, ...second.findings],
  };
  const prepare = () => fixture.prepareNormalized(selected);
  await expect(prepare()).rejects.toThrow("overlapping issue IDs");
  expect(await fixture.read()).toBeEmpty();

  nextIssue.id = "55555555-5555-4555-8555-555555555555";
  report.pages[0]!.responseJson = JSON.stringify({ data: [nextIssue] });
  selected.findings = [
    ...first.findings,
    ...normalizeSnykIssues(report).findings,
  ];
  expect((await (await prepare()).import()).counts.created).toBe(2);
  expect((await (await prepare()).import()).counts.unchanged).toBe(2);
});

const invalidCoordinates = [
  7,
  { state: "open", representations: [{ sourceLocation: 7 }] },
];
test.each(invalidCoordinates)("rejects numeric Code data %j", async (value) => {
  const report = snykRestFixture("code");
  await using fixture = await snykLocalFixture({
    remote: options.sourceRepositoryUrl,
  });
  await fixture.writeJson(report);
  expect((await (await fixture.prepare()).import()).counts.created).toBe(1);
  const stored = await fixture.read();

  const malformed = issue(true);
  report.pages[0]!.responseJson = JSON.stringify({
    data: [
      {
        ...malformed,
        attributes: { ...malformed.attributes, coordinates: [value] },
      },
    ],
  });
  await fixture.writeJson(report);
  const prepared = await fixture.prepare();
  expect((await prepared.import()).counts.updated).toBe(0);
  expect(prepared.preview.findings).toBeEmpty();
  expect(prepared.preview.excluded).toMatchObject([
    { position: 1, reason: expect.stringContaining("must be an object") },
  ]);
  expect(await fixture.read()).toEqual(stored);
});

test("rejects mismatched project evidence before persisting a local import", async () => {
  const other = "https://github.com/example/other";
  const wrongProject = transport(project("npm", other));
  await expect(wrongProject.collect()).rejects.toThrow();
  expect(wrongProject.calls).toHaveLength(1);
  const wrongIssue = transport(project(), {
    data: [issue(false, "55555555-5555-4555-8555-555555555555")],
  });
  await expect(wrongIssue.collect()).rejects.toThrow();

  const report = await transport(project(), { data: [issue(false)] }).collect();
  await using f = await snykLocalFixture({ remote: other });
  await f.writeJson(report);
  await expect(f.prepare()).rejects.toThrow();
  expect(await f.read()).toEqual([]);
});

test("retains numeric evidence exactly and identifies an issue by its vendor key across resurfacings", async () => {
  const original = issue(false);
  const raw = JSON.stringify({
    data: [{ ...original, original_count: 0 }],
  }).replace('"original_count":0', '"original_count":-90071992547409930e-1');
  const responses = [JSON.stringify(project()), raw];
  const report = await collectSnykIssues(options, {
    environment,
    fetch: async () => new Response(responses.shift()),
  });
  expect(report.pages[0]!.responseJson).toContain(
    '"original_count":-90071992547409930e-1',
  );
  const row = normalizeSnykIssues(JSON.parse(JSON.stringify(report)))
    .findings[0]!;
  expect(row.evidence.source_data?.["issueJson"]).toContain(
    '"original_count":-9007199254740993',
  );
  report.pages[0]!.responseJson = raw.replace(
    original.id,
    "77777777-7777-4777-8777-777777777777",
  );
  expect(normalizeSnykIssues(report).findings[0]!.source_finding_id).toBe(
    row.source_finding_id,
  );
});

test("rechecks Snyk Code repository evidence for direct normalized imports without Git remotes", async () => {
  const report = await transport(project("sast"), {
    data: [issue(true)],
  }).collect({
    ...options,
    product: "code",
  });
  const normalized = normalizeSnykIssues(report);
  await using f = await snykLocalFixture();
  const settings = {
    provider: "snyk" as const,
    sourceKey: f.sourceKey,
    repository: f.repository,
  };
  const deps = { environment: f.environment };
  await expect(
    prepareNormalizedLocalImport(
      normalized,
      { ...settings, provider: "github" },
      deps,
    ),
  ).rejects.toThrow("snyk provider");
  const other = "https://github.com/example/other";
  await expect(
    prepareNormalizedLocalImport(normalized, settings, {
      ...deps,
      sourceRepositories: [{ url: other }],
    }),
  ).rejects.toThrow("original Snyk project");
  normalized.findings[0]!.evidence.details!.repository!.url = other;
  await expect(
    prepareNormalizedLocalImport(normalized, settings, deps),
  ).rejects.toThrow("original Snyk project");
});

test("an empty Snyk report still binds the selected checkout to the monitored project", async () => {
  const sourceRepositoryUrl = "https://git.example.invalid/team/repository";
  const asset = project("npm", sourceRepositoryUrl);
  asset.data.attributes.origin = "cli";
  const report = await transport(asset, { data: [] }).collect({
    ...options,
    sourceRepositoryUrl,
  });
  // A custom HTTP server can assign the two URLs to different repositories.
  await using f = await snykLocalFixture({
    remote: sourceRepositoryUrl + ".git",
  });
  await f.writeJson(report);
  await expect(f.prepare()).rejects.toThrow("configured remote");
  await expect(
    f.prepare({ sourceRepositoryUrl: options.sourceRepositoryUrl }),
  ).rejects.toThrow("original Snyk project");
});

test("requires target details when the project links a target without its URL", async () => {
  const expanded = project();
  const link = expanded.data.relationships.target.data;
  link.attributes.url = "";
  const separate = {
    type: "target",
    id: link.id,
    attributes: { url: options.sourceRepositoryUrl },
  };
  const api = transport(expanded, { data: separate }, { data: [issue(false)] });
  const report = await api.collect();
  expect(normalizeSnykIssues(report).findings).toHaveLength(1);
  expect(() =>
    normalizeSnykIssues({
      ...report,
      sourceRepositoryUrl: "https://example.invalid/other/repo",
      targetJson: "null",
    }),
  ).toThrow("target");
});

test("a contradictory integration label cannot alias a distinct Azure repository", async () => {
  const url = "https://dev.azure.com/example/project/_git/repo";
  const response = project("npm", url + ".git");
  response.data.attributes.origin = "github-enterprise";
  await expect(
    transport(response).collect({ ...options, sourceRepositoryUrl: url }),
  ).rejects.toThrow("target URL");
});

test("checks typed Snyk repository URLs against original evidence and the checkout", async () => {
  const sourceRepositoryUrl = "https://gitlab.com/Team/Repo";
  const asset = project("sast", sourceRepositoryUrl);
  asset.data.attributes.origin = "gitlab";
  const report = normalizeSnykIssues(
    await transport(asset, { data: [issue(true)] }).collect({
      ...options,
      product: "code",
      sourceRepositoryUrl,
    }),
  );
  const evidence = report.findings[0]!.evidence;
  await using f = await snykLocalFixture({ remote: sourceRepositoryUrl });
  const settings = {
    provider: "snyk" as const,
    sourceKey: f.sourceKey,
    repository: f.repository,
  };
  const prepare = (environment = f.environment) =>
    prepareNormalizedLocalImport(report, settings, { environment });
  expect((await prepare()).preview.findings).toHaveLength(1);
  await expect(
    prepare({
      ...f.environment,
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "url.https://gitlab.com/other/repository.insteadOf",
      GIT_CONFIG_VALUE_0: sourceRepositoryUrl,
    } as typeof f.environment),
  ).rejects.toThrow("configured remote");
  evidence.details!.repository!.url = "https://gitlab.com/team/repo";
  await expect(prepare()).rejects.toThrow("original Snyk project");
});

test("preserves explicit repository ports and literal Git paths on custom hosts", async () => {
  const sourceRepositoryUrl = "https://scm.example.invalid/team/repo";
  for (const [source, original] of [
    [sourceRepositoryUrl, "https://scm.example.invalid:443/team/repo"],
    [sourceRepositoryUrl + "{a}", sourceRepositoryUrl + "%7Ba%7D"],
  ] as const) {
    const asset = project("npm", original);
    asset.data.attributes.origin = "api";
    await expect(
      transport(asset).collect({ ...options, sourceRepositoryUrl: source }),
    ).rejects.toThrow("target URL");
  }
});

test("accepts standard GitHub Enterprise clone path spellings from saved Snyk targets", async () => {
  const url = "https://scm.example.invalid/Org/repo";
  const withClone = (clone: string) => {
    const asset = project("npm", clone);
    asset.data.attributes.origin = "github-enterprise";
    return transport(asset, { data: [] }).collect({
      ...options,
      sourceRepositoryUrl: url,
    });
  };
  expect(
    normalizeSnykIssues(
      await withClone("git@scm.example.invalid:/org/REPO.git"),
    ).read,
  ).toBe(0);
  expect(
    normalizeSnykIssues(
      await withClone("ssh://git@scm.example.invalid/Org/%72epo%2Egit"),
    ).read,
  ).toBe(0);
  await expect(
    withClone("ssh://git@scm.example.invalid/elsewhere/%2e%2e/Org/repo"),
  ).rejects.toThrow("target URL");
});

test.each([
  [
    "gitlab",
    "https://git.example.invalid/Team/Repo",
    "git@git.example.invalid:Team/Repo.git",
  ],
  [
    "gitlab",
    "https://git.example.invalid/Team/Repo",
    "https://git.example.invalid/Team/Repo.git",
  ],
  [
    "azure-repos",
    "https://dev.azure.com/org/My%20Project/_git/Repo",
    "git@SSH.DEV.AZURE.COM:v3/org/My%20Project/Repo",
  ],
  [
    "azure-repos",
    "https://dev.azure.com/org/My%20Project/_git/Repo",
    "ssh://git@SSH.DEV.AZURE.COM/v3/org/My Project/Repo",
  ],
  [
    "azure-repos",
    "https://dev.azure.com/org/My%20Project/_git/Repo",
    "ssh://git@ssh.dev.azure.com:22/v3/org/My%20Project/Repo",
  ],
  [
    "azure-repos",
    "https://dev.azure.com/org/My%20Project/_git/Repo",
    "ssh://git@ssh.dev.azure.com/v3/org/My%2520Project/Repo",
  ],
])(
  "matches a monitored %s project at %s to the checkout %s",
  async (origin, sourceRepositoryUrl, remote) => {
    const asset = project("npm", sourceRepositoryUrl);
    asset.data.attributes.origin = origin;
    const report = await transport(asset, { data: [issue(false)] }).collect({
      ...options,
      sourceRepositoryUrl,
    });
    await using fixture = await snykLocalFixture({ remote });
    await fixture.writeJson(report);
    if (origin === "gitlab") {
      await expect(fixture.prepare()).rejects.toThrow("configured remote");
      const prepare = (url: string) =>
        prepareNormalizedLocalImport(
          normalizeSnykIssues(report),
          {
            provider: "snyk",
            sourceKey: options.projectId,
            repository: fixture.repository,
          },
          {
            environment: fixture.environment,
            sourceRepositories: [{ url, platform: "gitlab" }],
          },
        );
      expect(
        (await prepare(sourceRepositoryUrl)).preview.findings,
      ).toHaveLength(1);
      await expect(
        prepare(sourceRepositoryUrl.replace("Repo", "repo")),
      ).rejects.toThrow();
    } else {
      expect((await fixture.prepare()).preview.findings).toHaveLength(1);
    }
    const scoped = async (clone: string, provider: string) => {
      const asset = project("npm", clone);
      asset.data.attributes.origin = provider;
      return transport(asset, { data: [] }).collect({
        ...options,
        sourceRepositoryUrl,
      });
    };
    await expect(
      scoped(remote.replace("Repo", "repo"), origin),
    ).rejects.toThrow("target URL");
    await expect(
      scoped(
        remote.replace(
          /(^git@|^https:\/\/|^ssh:\/\/git@)[^/:]+/u,
          "$1other.example.invalid",
        ),
        origin,
      ),
    ).rejects.toThrow("target URL");
    if (remote.startsWith("ssh://git@ssh.dev.azure.com:22/")) {
      await expect(
        scoped(remote.replace(":22/", ":2222/"), origin),
      ).rejects.toThrow("target URL");
      await expect(
        scoped(remote.replace("git@", "reader@"), origin),
      ).rejects.toThrow("target URL");
    }
    if (origin === "gitlab")
      await expect(scoped(remote, "api")).rejects.toThrow("target URL");
  },
);

test.each([
  ["https://github.com:443/example/repository", true],
  ["https://reader@github.com:443/example/repository", true],
  ["https://github.com:8443/example/repository", false],
] as const)(
  "compares the checkout's actual HTTPS endpoint for %s",
  async (remote, matches) => {
    await using fixture = await snykLocalFixture({ remote });
    await fixture.writeJson(snykRestFixture("open-source"));
    if (matches)
      expect((await fixture.prepare()).preview.findings).toHaveLength(1);
    else await expect(fixture.prepare()).rejects.toThrow("configured remote");
  },
);

test.each(["git+ssh", "ssh+git"])(
  "matches %s GitHub checkouts with the same URI path as ssh",
  async (scheme) => {
    const remote = `${scheme}://git@github.com/example/%72epository.git`;
    await using fixture = await snykLocalFixture({ remote });
    await fixture.writeJson(snykRestFixture("open-source"));
    expect((await fixture.prepare()).preview.findings).toHaveLength(1);
  },
);

test("a v1 Code location stays unchanged until v2 adds its reported source line to the same row", async () => {
  const { projectJson, targetJson, pages, ...scope } = snykRestFixture("code");
  const v1 = {
    ...scope,
    format: "snyk-rest-issues/v1",
    project: JSON.parse(projectJson),
    target: JSON.parse(targetJson),
    pages: pages.map(({ startingAfter, responseJson }) => ({
      startingAfter,
      response: JSON.parse(responseJson),
    })),
  };
  await using fixture = await snykLocalFixture({
    remote: options.sourceRepositoryUrl,
  });
  await fixture.writeJson(v1);
  const stored = await createAndReplayFinding(fixture);
  expect(stored.evidence.locations).toEqual([
    { path: "src/app.ts", line: null },
  ]);
  await fixture.writeJson(snykRestFixture("code"));
  const updated = await updateStoredFinding(fixture, stored);
  expect(updated.evidence.locations).toEqual([{ path: "src/app.ts", line: 3 }]);
  expect((await (await fixture.prepare()).import()).counts.unchanged).toBe(1);

  const v2 = snykRestFixture("code");
  v2.pages[0]!.responseJson = v2.pages[0]!.responseJson.replace(
    '"line":3',
    '"line":"3"',
  );
  expect(normalizeSnykIssues(v2).findings[0]!.evidence.locations).toEqual([
    { path: "src/app.ts", line: null },
  ]);
});
