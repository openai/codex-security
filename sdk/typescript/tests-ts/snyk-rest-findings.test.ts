import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  collectSnykIssues,
  normalizeSnykIssues,
  snykRestFindingRepository,
  type CollectSnykIssuesOptions,
  type SnykIssuesExport,
} from "../src/snyk-rest-findings.js";
import {
  normalizeSnykInput,
  normalizeSnykJson,
  readSnykFindings,
  snykRepositoryClaims,
} from "../src/snyk-findings.js";

import type {
  HostedExternalFindings,
  ExternalSourceRepository,
} from "../src/external-findings.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { snykJson, snykPluginExport } from "./support/snyk-import-fixtures.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  organizationId,
  projectId,
  targetId,
  issueId,
  apiOrigin,
  sourceRepositoryUrl,
  snykRestProject as project,
  snykRestIssue as issue,
  snykRestDocument as document,
  snykRestFixture,
} from "./support/snyk-rest-fixtures.js";

const otherId = "55555555-5555-4555-8555-555555555555";
const options: CollectSnykIssuesOptions = {
  organizationId,
  projectId,
  product: "open-source",
  sourceRepositoryUrl,
  apiOrigin,
};
const env = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SNYK_TOKEN: "synthetic-token",
};
const version = "2026-03-25";
const path = `/rest/orgs/${organizationId}/issues`;

function transport(...responses: unknown[]) {
  const requests: { url: URL; init: RequestInit }[] = [];
  return {
    requests,
    collect(selected = options, environment: NodeJS.ProcessEnv = env) {
      return collectSnykIssues(selected, {
        environment,
        fetch: async (url, init) => {
          requests.push({ url, init });
          if (!responses.length) throw new Error("Unexpected request.");
          const response = responses.shift();
          return response instanceof Response
            ? response
            : Response.json(response);
        },
      });
    },
  };
}

function envelope(data: unknown[] = [issue()]) {
  return snykRestFixture("open-source", { issues: data });
}

async function snykCheckout(remote: string, sourceKey = projectId) {
  const fixture = await localFindingsFixture({ remote });
  const selection = {
    repository: fixture.repository,
    provider: "snyk" as const,
    sourceKey,
  };
  return {
    ...fixture,
    selection,
    prepareNormalized(
      input: HostedExternalFindings,
      sourceRepositories?: ExternalSourceRepository[],
    ) {
      return prepareNormalizedLocalImport(input, selection, {
        environment: fixture.environment,
        sourceRepositories,
      });
    },
  };
}

test("preserves exact Snyk metadata and distinguishes numeric titles from text through collection and replay", async () => {
  const digits = "9007199254740993";
  const source = project();
  Object.assign(source.relationships.target.data, {
    meta: {
      integration_data: {
        build: digits,
        capacity: "1e400",
        ratio: "0.1234567890123456789",
        minimum: "1e-400",
        threshold: 0.125,
      },
    },
  });
  const quoted = issue({
    key: "quoted",
    title: digits,
    meta: { build: digits },
  });
  const rows = [
    quoted,
    issue({ key: "numeric", title: "numeric-title" }, { id: otherId }),
  ];
  const wire = (value: unknown) =>
    JSON.stringify(value)
      .replace(/"(build|capacity|ratio|minimum)":"([^"]+)"/gu, '"$1":$2')
      .replace('"threshold":0.125', '"threshold":1.250000000000000000e-1')
      .replace('"numeric-title"', digits);
  const report = await transport(
    new Response(wire(document(source))),
    new Response(wire(document(rows))),
  ).collect();
  const result = normalizeSnykIssues(report);
  const historical = normalizeSnykIssues({
    ...envelope([quoted]),
    project: source,
  });
  expect(historical.findings[0]?.evidence).toMatchObject({
    title: digits,
    source_data: { project: source },
  });
  expect(result.findings).toMatchObject(historical.findings);
  expect(historical.findings[0]!.evidence.source_data).not.toHaveProperty(
    "numericFields",
  );
  expect(result.findings[0]!.evidence.source_data?.["numericFields"]).toEqual({
    project: report.numericFields?.["project"],
    issue: { attributes: { meta: { build: digits } } },
  });
  expect(result.excluded).toEqual([
    {
      position: 2,
      source_finding_id: expect.any(String),
      reason: expect.stringContaining("Snyk issue title"),
    },
  ]);

  const saved = JSON.stringify(report);
  expect(normalizeSnykIssues(JSON.parse(saved))).toEqual(result);
  const directory = await mkdtemp(join(tmpdir(), "snyk-int64-"));
  try {
    const path = join(directory, "report.json.gz");
    for (const contents of [
      saved,
      wire({ ...envelope(rows), project: source }),
    ]) {
      await writeFile(path, gzipSync(contents));
      expect(await readSnykFindings(path)).toEqual(result);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("retries only the throttled JSON:API page within the selected Snyk scope", async () => {
  const primary = issue({
    description: "Original description",
    ignored: true,
    status: "open",
    problems: [
      { type: "rule", source: "Snyk", id: "SNYK-EXAMPLE-1" },
      { type: "vulnerability", source: "NVD", id: "CVE-2099-0001" },
    ],
    classes: [{ type: "weakness", source: "CWE", id: "CWE-79" }],
    coordinates: [
      {
        representations: [
          {
            dependency: {
              package_name: "@example/pkg",
              package_version: "1.0.0",
            },
          },
        ],
        state: "open",
        is_upgradeable: true,
        remedies: [
          {
            type: "manual",
            meta: {
              schema_version: "package_vulnerability/v0",
              data: { fixed_in: ["1.0.1"] },
            },
          },
        ],
      },
    ],
  });
  const secondary = issue({ key: "second-key" }, { id: otherId });
  const cursor = "opaque+/=";
  const { collect, requests } = transport(
    document(project({ origin: "github-app" })),
    document([primary], {
      href: `/orgs/${organizationId}/issues?version=${version}&starting_after=${encodeURIComponent(cursor)}`,
    }),
    new Response("try again", {
      status: 429,
      headers: { "Retry-After": "0", Location: "https://other.invalid/issues" },
    }),
    document([secondary], null),
  );
  const signal = new AbortController().signal;
  const report = await collect({ ...options, signal });
  expect(report.apiVersion).toBe(version);
  expect(requests.map(({ url }) => url.pathname)).toEqual([
    `/rest/orgs/${organizationId}/projects/${projectId}`,
    path,
    path,
    path,
  ]);
  for (const { url, init } of requests) {
    expect(url.origin).toBe(apiOrigin);
    expect(url.searchParams.get("version")).toBe(version);
    expect(init).toMatchObject({ method: "GET", redirect: "error", signal });
    const headers = new Headers(init.headers);
    expect(headers.get("accept")).toContain("application/vnd.api+json");
    expect(init.body).toBeUndefined();
    expect(headers.get("authorization")).toBe("token synthetic-token");
  }
  expect(requests[0]!.url.searchParams.get("expand")).toBe("target");
  for (const { url } of requests.slice(1)) {
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      "scan_item.type": "project",
      "scan_item.id": projectId,
      type: "package_vulnerability",
      limit: "100",
      status: "open,resolved",
    });
    expect(url.searchParams.has("include_code_flows")).toBe(false);
  }
  expect(requests[1]!.url.searchParams.has("starting_after")).toBe(false);
  expect(requests[2]!.url.searchParams.get("starting_after")).toBe(cursor);
  expect(requests[3]!.url.href).toBe(requests[2]!.url.href);
  expect(report.pages.map((page) => page.startingAfter)).toEqual([
    null,
    cursor,
  ]);
  expect(JSON.stringify(report)).not.toContain(env.SNYK_TOKEN);
  const before = structuredClone(report);
  const normalized = normalizeSnykInput(report);
  expect(report).toEqual(before);
  expect(normalized.excluded).toEqual([]);
  expect(normalized.read).toBe(2);
  expect(normalized.findings[0]!.evidence).toMatchObject({
    title: "Synthetic issue",
    description: "Original description",
    severity: "high",
    branch: null,
    code_revision: null,
    source_updated_at: Math.floor(
      Date.parse(primary.attributes.updated_at) / 1000,
    ),
    advisory_ids: ["SNYK-EXAMPLE-1", "CVE-2099-0001"],
    packages: [
      {
        name: "@example/pkg",
        installed_version: "1.0.0",
        ecosystem: "npm",
        manifest_path: "app/package.json",
        fixed_versions: ["1.0.1"],
      },
    ],
    source_data: {
      apiVersion: version,
      issue: primary,
      project: report.project,
    },
  });
  expect(normalized.findings[0]!.evidence.details).toBeUndefined();
  for (const origin of ["cli", "api"]) {
    const nested = normalizeSnykIssues({
      ...report,
      project: project({ origin }),
    }).findings[0]!.evidence;
    expect(nested.packages![0]!.manifest_path).toBeNull();
    expect(nested.source_data).toMatchObject({
      project: { attributes: { target_file: "app/package.json" } },
    });
  }
  expect(
    JSON.stringify(normalized.findings[0]!.evidence.source_data),
  ).not.toContain("second-key");
  expect(normalized.sourceRepositoryUrl).toBe(sourceRepositoryUrl);
});

test("collects hosted Code, retaining source locations, ranges, flow omissions, rule and independent ignore state", async () => {
  const location = {
    file: "src/example%20file.ts",
    region: { start: { line: 0, column: 0 }, end: { line: 2, column: 4 } },
    commit_id: "synthetic-commit",
  };
  const finding = issue({
    type: "code",
    status: "open",
    ignored: true,
    effective_severity_level: "info",
    problems: [{ source: "Snyk", type: "rule", id: "example-rule" }],
    coordinates: [
      {
        state: "open",
        representations: [
          { sourceLocation: location },
          {
            source_location: {
              file: "../another-project/file",
              commit_id: "synthetic-commit",
            },
          },
        ],
        code_flows_omitted: true,
      },
    ],
  });
  const selected = {
    ...options,
    product: "code" as const,
    apiOrigin: undefined,
    token: "explicit-test-token",
  };
  const { collect, requests } = transport(
    document(project({ manager: "sast" })),
    document([finding]),
  );
  const report = await collect(selected);
  expect(requests.map(({ url }) => url.origin)).toEqual([
    "https://api.snyk.io",
    "https://api.snyk.io",
  ]);
  expect(new Headers(requests[0]!.init.headers).get("authorization")).toBe(
    "token explicit-test-token",
  );
  expect(Object.fromEntries(requests[1]!.url.searchParams)).toMatchObject({
    type: "code",
    "scan_item.type": "project",
    "scan_item.id": projectId,
    include_code_flows: "true",
  });
  const output = normalizeSnykIssues(report);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence).toMatchObject({
    severity: "informational",
    locations: [{ path: "src/example%20file.ts", line: null }],
    code_revision: "synthetic-commit",
    details: {
      kind: "sast",
      source_status: "open",
      rule: { id: "example-rule" },
      repository: { url: sourceRepositoryUrl },
    },
    source_data: { issue: finding },
  });
  expect(
    normalizeSnykIssues({
      ...report,
      project: project({ manager: "sast", origin: "cli", remote: null }),
    }).findings[0]!.evidence.locations,
  ).toEqual([]);
  location.commit_id = "other-commit";
  const changed = normalizeSnykIssues(
    snykRestFixture("code", { issues: [finding] }),
  );
  expect(changed.findings[0]!.evidence.code_revision).toBeNull();
});

test.each(["open-source", "code"] as const)(
  "hosted %s projects only explicitly open coordinates of open issues and preserves historical evidence",
  (product) => {
    const code = product === "code";
    const coordinates = ["open", "resolved", undefined].map((state, index) => ({
      ...(state && { state }),
      representations: [
        code
          ? {
              sourceLocation: {
                file: `src/file-${index}`,
                commit_id: `commit-${index}`,
              },
            }
          : {
              dependency: {
                package_name: "@example/pkg",
                package_version: `1.0.${index}`,
              },
            },
      ],
    }));
    for (const status of ["open", "resolved"]) {
      const native = issue({
        type: code ? "code" : "package_vulnerability",
        status,
        coordinates,
      });
      const normalized = normalizeSnykIssues(
        snykRestFixture(product, { issues: [native] }),
      );
      expect(normalized.excluded).toEqual([]);
      const evidence = normalized.findings[0]!.evidence;
      expect(evidence.source_data?.["issue"]).toEqual(native);
      expect(evidence.packages?.map((pkg) => pkg.installed_version)).toEqual(
        !code && status === "open" ? ["1.0.0"] : [],
      );
      expect(evidence.locations?.map((location) => location.path)).toEqual(
        code && status === "open" ? ["src/file-0"] : [],
      );
      expect(evidence.code_revision).toBe(
        code && status === "open" ? "commit-0" : null,
      );
    }
  },
);

test.each(["open-source", "code"] as const)(
  "hosted %s per-finding provenance validates all native scope claims independently of display fields",
  (product) => {
    const report = snykRestFixture(product);
    const source =
      normalizeSnykIssues(report).findings[0]!.evidence.source_data!;
    const type = product === "code" ? "code" : "package_vulnerability";
    const attributes = { type, title: null, key: null };
    const native = issue(attributes);
    const scoped = { ...source, issue: native };
    expect(snykRestFindingRepository(scoped).url).toBe(sourceRepositoryUrl);
    const lookup = {
      ...scoped,
      project: project({
        manager: report.project.attributes.type,
        expanded: false,
      }),
      target: {
        id: targetId,
        type: "target",
        attributes: { url: "git@github.com:EXAMPLE/repository.git" },
      },
    };
    expect(snykRestFindingRepository(lookup).url).toBe(sourceRepositoryUrl);
    const swapped = {
      ...scoped,
      sourceRepositoryUrl: "https://github.com/example/other",
    };
    const caseSensitive = {
      ...scoped,
      sourceRepositoryUrl: "https://git.example.test/Example/repository",
      project: project({
        manager: report.project.attributes.type,
        remote: "https://git.example.test/example/repository",
      }),
    };
    expect(snykRepositoryClaims(scoped)).toEqual([
      { url: sourceRepositoryUrl, platform: undefined },
    ]);
    expect(() => snykRepositoryClaims(swapped)).toThrow("target URL");
    expect(() => snykRepositoryClaims(caseSensitive)).toThrow("target URL");
    for (const invalid of [
      { ...scoped, format: "other" },
      { ...scoped, apiVersion: "latest" },
      { ...scoped, apiOrigin: "https://api.invalid" },
      { ...scoped, organizationId: otherId },
      { ...scoped, projectId: otherId },
      { ...scoped, product: product === "code" ? "open-source" : "code" },
      { ...lookup, target: null },
      { ...lookup, target: { ...lookup.target, id: otherId } },
      { ...lookup, sourceRepositoryUrl: swapped.sourceRepositoryUrl },
      { ...scoped, target: lookup.target },
      { ...scoped, issue: issue(attributes, { org: otherId }) },
      { ...scoped, issue: issue(attributes, { project: otherId }) },
      { ...scoped, issue: issue(attributes, { itemType: "environment" }) },
      { ...scoped, issue: { ...native, type: "project" } },
      {
        ...scoped,
        issue: { ...native, attributes: { ...attributes, type: "license" } },
      },
    ])
      expect(() => snykRestFindingRepository(invalid)).toThrow();
  },
);

test.each([undefined, null, ""])(
  "looks up the linked target by org and ID when its URL is %j",
  async (expandedUrl) => {
    const integration = (type: string) => ({
      data: {
        type: "integration",
        id: otherId,
        attributes: { integration_type: type },
      },
    });
    const target = {
      id: targetId,
      type: "target",
      attributes: {
        display_name: "not/the-mapping",
        url: "git@github.com:EXAMPLE/repository.git",
      },
      relationships: {
        organization: { data: { type: "organization", id: organizationId } },
        integration: integration("github-cloud-app"),
      },
    };
    const expansion = {
      expanded: expandedUrl !== undefined,
      remote: expandedUrl,
    };
    const lookup = document(project(expansion));
    const { collect, requests } = transport(
      lookup,
      document(target),
      document([issue()]),
    );
    const report = await collect();
    expect(requests[1]!.url.href).toBe(
      `${apiOrigin}/rest/orgs/${organizationId}/targets/${targetId}?version=${version}`,
    );
    expect(report.target).toEqual(target);
    expect(normalizeSnykIssues(report).sourceRepositoryUrl).toBe(
      sourceRepositoryUrl,
    );
    for (const bad of [
      { ...target, id: otherId },
      { ...target, attributes: { url: "https://github.com/example/other" } },
      ...["gitlab", "docker-hub", "github-cr", "unknown-integration"].map(
        (type) => ({
          ...target,
          relationships: {
            ...target.relationships,
            integration: integration(type),
          },
        }),
      ),
      {
        ...target,
        relationships: {
          organization: { data: { id: otherId, type: "organization" } },
        },
      },
    ]) {
      const attempt = transport(lookup, document(bad));
      await expect(attempt.collect()).rejects.toThrow(/target|organization/i);
      expect(attempt.requests).toHaveLength(2);
      const saved = { ...report, target: bad };
      expect(() => normalizeSnykIssues(saved)).toThrow();
      expect(() =>
        snykRestFindingRepository({ ...saved, issue: issue() }),
      ).toThrow();
    }
    const enterprise = {
      ...report,
      project: project({ ...expansion, origin: "github-enterprise" }),
    };
    expect(normalizeSnykIssues(enterprise).sourceRepositoryPlatform).toBe(
      "github",
    );
    const noDetail = { ...enterprise, target: null };
    if (expandedUrl === undefined) {
      expect(() => normalizeSnykIssues(noDetail)).toThrow();
    } else {
      const legacy = normalizeSnykIssues(noDetail);
      expect(legacy.sourceRepositoryPlatform).toBeUndefined();
      expect(
        snykRestFindingRepository(legacy.findings[0]!.evidence.source_data!)
          .platform,
      ).toBeUndefined();
    }
    for (const origin of ["cli", "api"]) {
      const generic = {
        ...report,
        project: project({ expanded: false, origin }),
      };
      expect(
        normalizeSnykIssues(generic).sourceRepositoryPlatform,
      ).toBeUndefined();
    }
  },
);

test("uses the declared repository when Snyk omits the project's relationships", async () => {
  const { relationships: _links, ...withoutLinks } = project();
  const { collect, requests } = transport(
    document(withoutLinks),
    document([issue()]),
  );
  const report = await collect();
  expect(requests.map(({ url }) => url.pathname)).toEqual([
    `/rest/orgs/${organizationId}/projects/${projectId}`,
    path,
  ]);
  expect(report.target).toBeNull();
  const normalized = normalizeSnykIssues(report);
  expect(normalized.sourceRepositoryUrl).toBe(sourceRepositoryUrl);
  expect(normalized.sourceRepositoryPlatform).toBeUndefined();
  expect(normalized.findings).toHaveLength(1);
  expect(() =>
    normalizeSnykIssues({
      ...report,
      target: { type: "target", id: targetId },
    }),
  ).toThrow("separate Snyk target");
  const mixed = transport(
    document(withoutLinks),
    document([issue({}, { project: otherId })]),
  );
  await expect(mixed.collect()).rejects.toThrow("selected project");
});

test.each([
  "azure-repos",
  "bitbucket-cloud",
  "bitbucket-connect-app",
  "bitbucket-server",
  "gitlab",
])(
  "preserves %s project provenance when Snyk omits the target URL",
  (origin) => {
    const normalized = normalizeSnykIssues({
      ...envelope(),
      project: project({ origin, remote: null }),
    });
    expect(normalized.sourceRepositoryPlatform).toBe("other");
    const source = normalized.findings[0]!.evidence.source_data!;
    expect(snykRestFindingRepository(source).platform).toBe("other");
  },
);

test("accepts a custom-host .git alias only when the Snyk integration establishes it", () => {
  const url = "https://git.example.test/team/lib";
  const report = (origin: string, remote: string) => ({
    ...envelope(),
    sourceRepositoryUrl: url,
    project: project({ origin, remote }),
  });
  expect(() => normalizeSnykIssues(report("api", url + ".git"))).toThrow(
    "target URL",
  );
  for (const origin of ["gitlab", "github-enterprise"])
    expect(
      normalizeSnykIssues(report(origin, url + ".git")).findings,
    ).toHaveLength(1);
  expect(normalizeSnykIssues(report("api", url)).findings).toHaveLength(1);
});

test.each(["dev.azure.com", "dev.azure.com."])(
  "a Snyk integration label cannot alias distinct Azure repository names on %s",
  async (host) => {
    const url = `https://${host}/example/project/_git/library`;
    await using checkout = await snykCheckout(url);
    for (const origin of ["github-enterprise", "gitlab"]) {
      const report = {
        ...envelope(),
        sourceRepositoryUrl: url + ".git",
        project: project({ origin, remote: url + ".git" }),
      };
      expect(() =>
        normalizeSnykIssues({ ...report, sourceRepositoryUrl: url }),
      ).toThrow("target URL");
      const exact = normalizeSnykIssues(report);
      expect(exact.sourceRepositoryPlatform).toBe("other");
      await expect(checkout.prepareNormalized(exact)).rejects.toThrow(
        "does not match",
      );
    }
  },
);

test.each([
  ["Jalape%c3%b1o", "Jalape%C3%B1o"],
  ["Jalapeño", "Jalape%C3%B1o"],
  ["Product\u00a0API", "Product%C2%A0API"],
  ["Jalape%c3%b1o", "Jalapeño"],
])(
  "Snyk compares Azure project names %s and %s by their HTTP spelling",
  (declared, native) => {
    const repository = (name: string) =>
      `https://dev.azure.com/example/${name}/_git/project`;
    const report = {
      ...envelope(),
      sourceRepositoryUrl: repository(declared),
      project: project({ origin: "azure-repos", remote: repository(native) }),
    };
    const saved = normalizeSnykIssues(report);
    expect(saved.sourceRepositoryUrl).toBe(report.sourceRepositoryUrl);
    expect(saved.findings[0]!.evidence.source_data).toMatchObject({
      project: report.project,
    });
    for (const name of ["jalapeño", "Jalapen\u0303o"])
      expect(() =>
        normalizeSnykIssues({
          ...report,
          sourceRepositoryUrl: repository(name),
        }),
      ).toThrow("target URL");
  },
);

test.each([
  ["[2001:db8::1]", "[2001:0db8:0:0:0:0:0:1]"],
  ["xn--bcher-kva.example.test", "bücher.example.test"],
])(
  "Snyk retains the original HTTP authorities %s and %s",
  (declared, native) => {
    const sourceRepositoryUrl = `https://${declared}/Group/Repo`;
    const input = {
      ...envelope(),
      sourceRepositoryUrl,
      project: project({
        origin: "gitlab",
        remote: `https://${native}/Group/Repo`,
      }),
    };
    const saved = normalizeSnykIssues(input);
    expect(saved.sourceRepositoryUrl).toBe(sourceRepositoryUrl);
    expect(saved.findings[0]!.evidence.source_data).toMatchObject({
      project: input.project,
    });
    expect(() =>
      normalizeSnykIssues({
        ...input,
        sourceRepositoryUrl: sourceRepositoryUrl.toLowerCase(),
      }),
    ).toThrow("target URL");
  },
);

test("matches GitHub Enterprise SSH clone URLs to the selected HTTPS repository", () => {
  const source = "https://scm.example.test/Org/project";
  const check = (
    remote: string,
    origin = "github-enterprise",
    expanded = true,
  ) =>
    normalizeSnykIssues({
      ...envelope([]),
      sourceRepositoryUrl: source,
      project: project({ origin, remote, expanded }),
      target: expanded
        ? null
        : { id: targetId, type: "target", attributes: { url: remote } },
    });
  for (const remote of [
    "git@scm.example.test:org/PROJECT.git",
    "git@scm.example.test:/org/PROJECT.git",
    "ssh://git@scm.example.test/ORG/project",
    "ssh://git@scm.example.test/Org/%70roject%2Egit",
  ]) {
    expect(check(remote).read).toBe(0);
    expect(check(remote, "github-enterprise", false).read).toBe(0);
    for (const origin of ["gitlab", "cli"])
      expect(() => check(remote, origin)).toThrow();
  }
  for (const remote of [
    "other@scm.example.test:Org/project",
    "ssh://git@scm.example.test:2222/Org/project",
    "ssh://git@scm.example.test/elsewhere/%2e%2e/Org/project",
    "ssh://git@scm.example.test/elsewhere/../Org/project",
    "ssh://git@scm.example.test/elsewhere%2F%2E%2E/Org/project",
    "ssh://git@scm.example.test/Org/project%3Fquery",
    "ssh://git@scm.example.test/Org/project%23fragment",
    "ssh://git@scm.example.test/Org/%2570roject.git",
    "git@scm.example.test:/Org/%70roject.git",
    "git@scm.example.test://Org/project.git",
    "git@foreign.example.test:Org/project",
    "git@scm.example.test:Org/other",
  ])
    expect(() => check(remote)).toThrow();
});

test.each([
  ["gitlab", "gitlab.com", "Group/subgroup/project"],
  ["gitlab", "gitlab.com.", "Group/subgroup/project"],
  ["bitbucket-cloud", "bitbucket.org", "Group/project"],
  ["bitbucket-cloud", "bitbucket.org.", "Group/project"],
])(
  "collects and replays %s SSH targets on %s for the selected namespace and project",
  async (origin, host, name) => {
    const scp = `git@${host}:${name}.git`;
    const selected = {
      ...options,
      sourceRepositoryUrl: `https://${host}/${name}`,
    };
    await using checkout = await snykCheckout(scp);
    for (const remote of [
      scp,
      `ssh://git@${host}:22/${name}.git`,
      `ssh://git@altssh.${host}:443/${name}.git`,
    ]) {
      const { collect } = transport(
        document(project({ origin, remote })),
        document([issue()]),
      );
      const saved = await collect(selected);
      const normalized = normalizeSnykIssues(saved, "local");
      const prepared = await checkout.prepareNormalized(normalized);
      expect(prepared.preview.findings).toHaveLength(1);
    }
    for (const remote of [
      scp.toLowerCase(),
      `other@${host}:${name}`,
      `ssh://git@${host}:2222/${name}`,
      `ssh://other@altssh.${host}:443/${name}`,
      `ssh://git@altssh.${host}:22/${name}`,
      `git@scm.example.test:${name}`,
    ]) {
      const { collect, requests } = transport(
        document(project({ origin, remote })),
      );
      await expect(collect(selected)).rejects.toThrow("target URL");
      expect(requests).toHaveLength(1);
    }
  },
);

test("issue identity is stable across updates, resource IDs, pages and display names, not across scopes", () => {
  const original = envelope();
  const id = (input: unknown) =>
    normalizeSnykIssues(input).findings[0]!.source_finding_id;
  const changes = {
    title: "New title",
    effective_severity_level: "low",
    status: "open",
    ignored: true,
  };
  const changed = envelope([issue(changes, { id: otherId })]);
  changed.project.attributes.name = "Repository renamed";
  expect(id(changed)).toBe(id(original));
  const other = {
    ...envelope([issue({}, { project: otherId })]),
    projectId: otherId,
    project: project({ id: otherId }),
  };
  const otherOrg = {
    ...envelope([issue({}, { org: otherId })]),
    organizationId: otherId,
    project: project({ org: otherId }),
  };
  const scopes = [
    original,
    other,
    otherOrg,
    snykRestFixture("code"),
    { ...original, apiOrigin: "https://api.au.snyk.io" },
  ];
  expect(new Set(scopes.map(id)).size).toBe(scopes.length);
});

test("requires a valid zoned date-time for Snyk updates", () => {
  const report = envelope([
    issue({ key: "utc", updated_at: "2025-02-03T04:05:06Z" }),
    issue({ key: "offset", updated_at: "2025-02-02T20:05:06-08:00" }),
    issue({ key: "local", updated_at: "2025-02-03T04:05:06" }),
    issue({ key: "trailing-z", updated_at: "2025-02-03Z" }),
    issue({ key: "invalid-day", updated_at: "2025-02-30T04:05:06Z" }),
  ]);
  const output = normalizeSnykIssues(report);
  expect(
    output.findings.map(({ evidence }) => evidence.source_updated_at),
  ).toEqual([1738555506, 1738555506]);
  expect(output.excluded.map(({ position }) => position)).toEqual([3, 4, 5]);
});

test("duplicates, unsupported products and malformed records have explicit positional exclusions", () => {
  const report = envelope([
    issue(),
    issue({ key: "valid" }, { id: otherId }),
    issue({ title: "Second copy" }),
    issue({ type: "license" }),
    issue({ type: "code" }),
    issue({ key: "" }),
    issue({ key: "bad-title", title: null }),
    issue({ key: "bad-status", ignored: "false" }),
    issue({ key: "bad-time", updated_at: "invalid" }),
  ]);
  const output = normalizeSnykIssues(report);
  expect(output.read).toBe(9);
  expect(output.findings).toHaveLength(1);
  expect(output.excluded.map((entry) => entry.position)).toEqual([
    1, 3, 4, 5, 6, 7, 8, 9,
  ]);
  expect(output.excluded[0]!.source_finding_id).toBe(
    output.excluded[1]!.source_finding_id,
  );
  expect(output.excluded[0]!.reason).toContain("duplicate");
  expect(output.excluded[2]!.reason).toContain("package_vulnerability");
  expect(output.excluded[4]!.source_finding_id).toBeNull();
});

test("reads saved complete empty and excluded exports offline, retaining report-level mapping for either destination", async () => {
  const directory = await mkdtemp(join(tmpdir(), "snyk-rest-"));
  try {
    const filename = join(directory, "issues.json.gz");
    for (const rows of [[], [issue({ type: "license" })]]) {
      const report = envelope(rows);
      await writeFile(filename, gzipSync("\uFEFF" + JSON.stringify(report)));
      for (const target of ["local", "cloud"] as const) {
        const output = await readSnykFindings(filename, target);
        expect(output).toEqual(normalizeSnykInput(report, target));
        expect(output.findings).toEqual([]);
        expect(output.read).toBe(rows.length);
        expect(output.excluded).toHaveLength(rows.length);
        expect(output.sourceRepositoryUrl).toBe(sourceRepositoryUrl);
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects incomplete or inconsistent envelopes, including an empty tail without its preceding page", () => {
  const report = envelope([]);
  const first = {
    startingAfter: null,
    response: document([], "?starting_after=cursor"),
  };
  const last = { startingAfter: "cursor", response: document([]) };
  for (const invalid of [
    { ...report, pages: [] },
    { ...report, complete: false },
    { ...report, format: "snyk-rest-issues/v2" },
    { ...report, apiVersion: "latest" },
    { ...report, pages: [first] },
    { ...report, pages: [last] },
    { ...report, pages: [first, last, last] },
    { ...report, pages: [first, { ...last, startingAfter: "unrelated" }] },
    {
      ...report,
      pages: [{ startingAfter: null, response: { errors: [], data: [] } }],
    },
  ]) {
    expect(() => normalizeSnykInput(invalid)).toThrow();
  }
  expect(normalizeSnykIssues({ ...report, pages: [first, last] }).read).toBe(0);
});

test.each([
  `https://api.snyk.io${path}?starting_after=x`,
  `//other.invalid${path}?starting_after=x`,
  `https://name@api.eu.snyk.io${path}?starting_after=x`,
  `/rest/orgs/${otherId}/issues?starting_after=x`,
  `/rest/orgs/${organizationId}/projects?starting_after=x`,
  "?starting_after=x&scan_item.type=environment",
  `?starting_after=x&scan_item.id=${otherId}`,
  "?starting_after=x&type=code",
  "?starting_after=x&status=open",
  "?starting_after=x&version=other",
  "?starting_after=x&ending_before=z",
  "?starting_after=x&starting_after=y",
  "?starting_after=x#fragment",
  "?",
  "",
  { href: null },
])(
  "does not send credentials to a changed route or scoped query: %j",
  async (next) => {
    const { collect, requests } = transport(
      document(project()),
      document([], next),
    );
    await expect(collect()).rejects.toThrow(/Snyk next page/);
    expect(requests).toHaveLength(2);
  },
);

test("fails on a repeated cursor despite changes to the link spelling", async () => {
  const { collect, requests } = transport(
    document(project()),
    document([], "?starting_after=again"),
    document([], {
      href: `${apiOrigin}${path}?version=${version}&starting_after=again`,
    }),
  );
  await expect(collect()).rejects.toThrow(/repeated a cursor/);
  expect(requests).toHaveLength(3);
});

test("a wrong project, product or repository fails before listing issues or accepting replay", async () => {
  for (const source of [
    project({ id: otherId }),
    project({ org: otherId }),
    project({ manager: "sast" }),
    project({ manager: "deb" }),
    project({ origin: "docker-hub" }),
    project({ remote: "https://github.com/example/another" }),
    project({ remote: "ssh://git@github.com/example/repository.git?other" }),
    project({ remote: "ssh://git@[github.com:]/example/repository.git" }),
    project({ remote: "ssh://git@github.com%01/example/repository.git" }),
  ]) {
    const { collect, requests } = transport(document(source));
    await expect(collect()).rejects.toThrow();
    expect(requests).toHaveLength(1);
    expect(() =>
      normalizeSnykIssues({ ...envelope([]), project: source }),
    ).toThrow();
  }
  expect(() => normalizeSnykIssues({ ...envelope(), product: "code" })).toThrow(
    /project type/,
  );
});

test("rejects ambiguous Snyk monitor HTTP targets before fetching issues or replaying a report", async () => {
  // The CLI emits this same target for git@github.com:example/repository.git
  // and the local path /mnt/mirrors/git@github.com:example/repository.git.
  const http = "http://github.com/example/repository.git";
  const https = "https://github.com/example/repository.git";
  const monitored = project({ origin: "cli", remote: http });
  for (const source of [http, https]) {
    const { collect, requests } = transport(document(monitored));
    await expect(
      collect({ ...options, sourceRepositoryUrl: source }),
    ).rejects.toThrow("--remote-repo-url");
    expect(requests).toHaveLength(1);
    const report = {
      ...envelope(),
      sourceRepositoryUrl: source,
      project: monitored,
    };
    expect(() => normalizeSnykIssues(report)).toThrow("--remote-repo-url");
    expect(() =>
      snykRestFindingRepository({ ...report, issue: issue() }),
    ).toThrow("--remote-repo-url");
  }
  const run = transport(
    document(project({ origin: "cli", remote: https })),
    document([issue()]),
  );
  const explicit = await run.collect({
    ...options,
    sourceRepositoryUrl: https,
  });
  expect(normalizeSnykIssues(explicit).sourceRepositoryUrl).toBe(https);
});

test("compares Snyk native HTTP repository URLs without changing their scheme", () => {
  const plain = "http://gitlab.com/Group/my-project";
  const escaped = "http://gitlab.com/Group/my%2Dproject";
  const check = (
    remote: string | null,
    source: string,
    origin = "gitlab",
    product: "open-source" | "code" = "open-source",
  ) =>
    normalizeSnykIssues({
      ...snykRestFixture(product, { sourceRepositoryUrl: source }),
      project: project({
        manager: product === "code" ? "sast" : "npm",
        origin,
        remote,
      }),
    });
  for (const [native, selected] of [
    [plain, escaped],
    [escaped, plain],
  ] as const) {
    const report = check(native, selected);
    expect(report.sourceRepositoryUrl).toBe(selected);
    expect(report.findings[0]!.evidence.source_data).toMatchObject({
      project: project({ remote: native, origin: "gitlab" }),
    });
  }
  expect(
    check("http://gitlab.com/Group/old/../my-project", plain)
      .sourceRepositoryUrl,
  ).toBe(plain);
  expect(() =>
    check("http://gitlab.com/Group/old\t/../my-project", plain),
  ).toThrow("percent-encode");
  expect(check(null, plain, "cli").sourceRepositoryUrl).toBe(plain);
  expect(check(plain, plain, "api").sourceRepositoryUrl).toBe(plain);
  expect(check(plain, plain, "cli", "code").sourceRepositoryUrl).toBe(plain);
  expect(() =>
    check(plain, plain.replace("http:", "https:"), "cli", "code"),
  ).toThrow("target URL");
});

test("checks the actual HTTP and Git paths of native Snyk targets", async () => {
  const source = "https://scm.example.test/Team/repo";
  for (const path of [
    String.raw`foreign\sub/../repo`,
    "%2e%2e/../repo",
    "repo{one}",
  ]) {
    const remote = "https://scm.example.test/Team/" + path;
    const native = project({ origin: "gitlab", remote });
    const { requests, collect } = transport(
      document(native),
      document([issue()]),
    );
    await expect(
      collect({ ...options, sourceRepositoryUrl: source }),
    ).rejects.toThrow("repository URL");
    expect(requests).toHaveLength(1);
    for (const sourceRepositoryUrl of [source, remote])
      expect(() =>
        normalizeSnykIssues({
          ...envelope(),
          project: native,
          sourceRepositoryUrl,
        }),
      ).toThrow("repository URL");
  }
  for (const path of ["Team/foreign%5Csub/../repo", "%2e/../Team/repo"]) {
    const native = project({
      origin: "gitlab",
      remote: "https://scm.example.test/" + path,
    });
    const report = normalizeSnykIssues({
      ...envelope(),
      project: native,
      sourceRepositoryUrl: source,
    });
    expect(report.findings[0]!.evidence.source_data?.["project"]).toEqual(
      native,
    );
  }
});

test("does not save mixed or unverifiable issue scopes, even on the last page", async () => {
  for (const foreign of [
    issue({}, { project: otherId }),
    issue({}, { org: otherId }),
    issue({}, { itemType: "environment" }),
    { id: issueId },
  ]) {
    const report = transport(
      document(project()),
      document([issue()], "?starting_after=more"),
      document([foreign]),
    );
    await expect(report.collect()).rejects.toThrow(
      /project|organization|relationship/,
    );
    expect(() => normalizeSnykIssues(envelope([foreign]))).toThrow();
  }
});

test("gates and validates configuration and cancellation before issuing any credentialed request", async () => {
  const { collect, requests } = transport();
  await expect(collect(options, {})).rejects.toThrow("disabled");
  await expect(
    collect(options, { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" }),
  ).rejects.toThrow("SNYK_TOKEN");
  for (const choice of [
    { projectId: "../issues" },
    { organizationId: "org-name" },
    { sourceRepositoryUrl: "" },
    { sourceRepositoryUrl: "https://name@github.com/example/repository" },
    { apiOrigin: "https://api.snyk.io.evil.invalid" },
    { apiOrigin: "https://api.snyk.io/rest" },
    { apiOrigin: "http://api.snyk.io" },
    { apiOrigin: "https://api.snyk.io:8443" },
    { signal: AbortSignal.abort(new Error("cancelled")) },
  ]) {
    await expect(collect({ ...options, ...choice })).rejects.toThrow();
  }
  expect(requests).toEqual([]);
});

test("HTTP, JSON, and second-page failures are errors, never successful partial or empty collections", async () => {
  for (const response of [
    new Response("forbidden", { status: 403 }),
    new Response("rate limited", {
      status: 429,
      headers: { "retry-after": "60" },
    }),
    new Response("{"),
    { errors: [{ status: "400", detail: "issue error" }] },
    { data: null },
  ]) {
    const { collect, requests } = transport(
      document(project()),
      document([issue()], "?starting_after=more"),
      response,
    );
    await expect(collect()).rejects.toThrow();
    expect(requests).toHaveLength(3);
  }
});

test("reports the last HTTP error when the retried Snyk cursor is still throttled", async () => {
  const limited = (detail: string) =>
    new Response(detail, { status: 429, headers: { "Retry-After": "0" } });
  const { collect, requests } = transport(
    document(project()),
    document([issue()], "?starting_after=more"),
    limited("first failure"),
    limited("still throttled"),
  );
  await expect(collect()).rejects.toThrow(
    `GET ${apiOrigin}${path} failed (HTTP 429); Retry-After: 0: still throttled`,
  );
  expect(requests).toHaveLength(4);
  expect(requests[3]!.url.href).toBe(requests[2]!.url.href);
});

test.each(["options", "dependencies"] as const)(
  "aborting the %s signal with the other signal live cancels the request and prevents new requests",
  async (caller) => {
    const controllers = {
      options: new AbortController(),
      dependencies: new AbortController(),
    };
    const reason = new Error(`cancelled by ${caller}`);
    let requests = 0;
    const collect = () =>
      collectSnykIssues(
        { ...options, signal: controllers.options.signal },
        {
          environment: env,
          signal: controllers.dependencies.signal,
          fetch: async (_url, init) => {
            requests++;
            controllers[caller].abort(reason);
            expect(init.signal?.reason).toBe(reason);
            init.signal!.throwIfAborted();
            throw new Error("Snyk request was not cancelled.");
          },
        },
      );
    await expect(collect()).rejects.toBe(reason);
    expect(
      controllers[caller === "options" ? "dependencies" : "options"].signal
        .aborted,
    ).toBe(false);
    await expect(collect()).rejects.toBe(reason);
    expect(requests).toBe(1);
  },
);

test.each(["open-source", "code"] as const)(
  "hosted Snyk %s rejects the wrong checkout and creates, replays and updates unassessed SQLite evidence",
  async (product) => {
    const url = "https://scm.example.test/Org/project";
    const remote = "git@scm.example.test:org/PROJECT.git";
    const sourceKey = `${organizationId}/${projectId}/${product}`;
    await using fixture = await snykCheckout(remote, sourceKey);
    await using wrong = await snykCheckout(
      "https://github.com/example/other",
      sourceKey,
    );
    const manager = product === "code" ? "sast" : "npm";
    const report = (options?: Parameters<typeof snykRestFixture>[1]) => ({
      ...snykRestFixture(product, { ...options, sourceRepositoryUrl: url }),
      project: project({ manager, origin: "github-enterprise", remote }),
    });
    const initial = report();
    const prepare = async (
      report: SnykIssuesExport,
      local = fixture,
      references?: ExternalSourceRepository[],
      sourceRepositoryUrl = references?.[0]?.url,
    ) => {
      const filename = join(local.root, "snyk-hosted.json");
      await writeFile(filename, JSON.stringify(report));
      return prepareLocalExternalImport(
        filename,
        { ...local.selection, sourceRepositoryUrl },
        {
          environment: local.environment,
          sourceRepositories: references,
        },
      );
    };
    const empty = report({ issues: [] });
    await expect(
      prepare(
        initial,
        fixture,
        undefined,
        "https://scm.example.test/unusable path/../Org/project",
      ),
    ).rejects.toThrow("percent-encode");
    const excluded = report({
      issues: [issue({ type: "license" })],
    });
    for (const report of [initial, empty, excluded]) {
      await expect(prepare(report, wrong)).rejects.toThrow(
        /does not match a configured remote/,
      );
    }
    const normalizedEmpty = normalizeSnykIssues(empty, "local");
    await expect(wrong.prepareNormalized(normalizedEmpty)).rejects.toThrow(
      /does not match a configured remote/,
    );
    expect(
      (await fixture.prepareNormalized(normalizedEmpty)).preview.findings,
    ).toHaveLength(0);
    const {
      sourceRepositoryUrl: _url,
      sourceRepositoryPlatform: _platform,
      ...rows
    } = normalizeSnykIssues(initial, "local");
    expect(
      (await fixture.prepareNormalized(rows)).preview.findings,
    ).toHaveLength(1);
    const binding = [{ url: url.toLowerCase(), platform: "github" as const }];
    for (const saved of [empty, initial]) {
      const withProject = (origin: string, remote: string | null) => ({
        ...saved,
        project: project({ manager, origin, remote }),
      });
      const unknownReport = withProject("github-enterprise", null);
      const unknown = normalizeSnykIssues(unknownReport, "local");
      unknown.sourceRepositoryPlatform = "github";
      unknown.snykRestContext = {
        ...normalizedEmpty.snykRestContext,
        project: unknownReport.project,
      };
      await expect(fixture.prepareNormalized(unknown)).rejects.toThrow(
        /does not match a configured remote/,
      );
      expect(
        (await fixture.prepareNormalized(unknown, binding)).preview.read,
      ).toBe(unknown.read);
      expect(
        (await prepare(unknownReport, fixture, binding)).preview.read,
      ).toBe(unknown.read);
      const { relationships: _links, ...linkless } = project({
        manager,
        origin: "azure-repos",
      });
      for (const nonGitHubReport of [
        withProject("gitlab", url),
        withProject("gitlab", null),
        { ...saved, project: linkless },
      ]) {
        const normalized = normalizeSnykIssues(nonGitHubReport, "local");
        await expect(
          prepare(nonGitHubReport, fixture, binding),
        ).rejects.toThrow("does not match");
        await expect(fixture.prepareNormalized(normalized)).rejects.toThrow(
          /does not match a configured remote/,
        );
        await expect(
          fixture.prepareNormalized(normalized, binding),
        ).rejects.toThrow("does not match");
      }
    }
    const importReport = async (report: SnykIssuesExport) =>
      (await prepare(report)).import();
    expect((await importReport(initial)).counts.created).toBe(1);
    expect((await importReport(initial)).counts.unchanged).toBe(1);
    expect((await importReport(empty)).ready).toBe(0);

    const updated = report({
      title: "Updated source title",
      updatedAt: "2025-02-04T00:00:00Z",
    });
    expect((await importReport(updated)).counts.updated).toBe(1);
    const stored = await listLocalExternalFindings(fixture.selection, {
      environment: fixture.environment,
    });
    expect(stored).toHaveLength(1);
    const finding = normalizeSnykIssues(updated).findings[0]!;
    expect(stored).toMatchObject([
      {
        sourceFindingId: finding.source_finding_id,
        version: 2,
        assessment: { state: "not_assessed" },
        evidence: finding.evidence,
      },
    ]);
  },
);

test.each(
  ["gitlab.com", "scm.example.test"].flatMap((host) =>
    ["source", "native"].map((encoded) => [host, encoded] as const),
  ),
)(
  "projected Snyk rows preserve verified HTTP aliases on %s (encoded %s)",
  async (host, encodedClaim) => {
    const encodedSource = encodedClaim === "source";
    await using fixture = await localFindingsFixture();
    const plain = `https://${host}/Group/project`;
    const encoded = `https://${host}/Group/proj%65ct`;
    const url = encodedSource ? encoded : plain;
    const remote = encodedSource ? plain : encoded;
    const input = normalizeSnykIssues(
      {
        ...envelope(),
        sourceRepositoryUrl: url,
        project: project({ origin: "gitlab", remote }),
      },
      "local",
    );
    const prepare = (selected = input) =>
      prepareNormalizedLocalImport(
        selected,
        {
          provider: "snyk",
          sourceKey: projectId,
          repository: fixture.repository,
        },
        { environment: fixture.environment },
      );
    expect((await prepare()).preview.findings).toEqual(input.findings);
    input.findings[0]!.source_finding_id = "blackduck-bom:" + "a".repeat(64);
    expect((await prepare()).preview.findings).toEqual(input.findings);
    for (const wrong of [
      plain.replace("/Group/", "/group/"),
      plain + "-other",
    ]) {
      const conflicting = structuredClone(input);
      conflicting.findings[0]!.evidence.details = {
        kind: "sast",
        repository: { url: wrong },
      };
      await expect(prepare(conflicting)).rejects.toThrow(/does not match/);
    }
    execFileSync("git", [
      "-C",
      fixture.repository,
      "remote",
      "add",
      "origin",
      remote,
    ]);
    expect((await prepare()).preview.findings).toEqual(input.findings);
  },
);

test("a reader reference preserves Snyk aliases across sibling comparison platforms", async () => {
  await using fixture = await localFindingsFixture();
  const url = "https://scm.example.test/Group/project";
  const row = (origin: string, remote: string) =>
    normalizeSnykIssues(
      {
        ...envelope([issue({ key: origin })]),
        sourceRepositoryUrl: url,
        project: project({ origin, remote }),
      },
      "local",
    ).findings[0]!;
  const github = row("github-enterprise", url);
  const gitlab = row("gitlab", url.replace("project", "proj%65ct"));
  gitlab.source_finding_id = "blackduck-bom:" + "a".repeat(64);
  const input = { read: 2, findings: [github, gitlab], excluded: [] };
  const prepare = (sourceRepositories: ExternalSourceRepository[] = []) =>
    prepareNormalizedLocalImport(
      input,
      {
        provider: "snyk",
        sourceKey: projectId,
        repository: fixture.repository,
      },
      { environment: fixture.environment, sourceRepositories },
    );
  expect((await prepare()).preview.findings).toEqual(input.findings);
  expect((await prepare([{ url }])).preview.findings).toEqual(input.findings);
});

test("local Snyk replay accepts the verified GitLab.com SSH alias and preserves namespace case", async () => {
  const url = "https://gitlab.com/Group/project";
  const remote = "git@gitlab.com:Group/project.git";
  await using fixture = await snykCheckout(
    "ssh://git@gitlab.com:bad/other/project",
    "gitlab",
  );
  execFileSync("git", [
    "-C",
    fixture.repository,
    "remote",
    "add",
    "upstream",
    remote,
  ]);
  const input = normalizeSnykIssues({
    ...envelope(),
    sourceRepositoryUrl: url,
    project: project({ origin: "gitlab", remote }),
  });
  const prepare = (reference: string) =>
    fixture.prepareNormalized(input, [{ url: reference }]);
  expect((await prepare(remote)).preview.findings).toHaveLength(1);
  await expect(prepare(remote.toLowerCase())).rejects.toThrow("does not match");
});

test.each([
  ["empty", [], false],
  ["all excluded", [issue({ status: "unknown" })], true],
] as const)(
  "retains GitLab and GitHub Enterprise project proof in an %s report",
  async (_, issues, reverse) => {
    const bare = "https://scm.example.test/Team/repo";
    const sourceRepositoryUrl = reverse ? bare + ".git" : bare;
    const remote = reverse ? bare : bare + ".git";
    await using fixture = await snykCheckout(remote);
    const report = {
      ...envelope([...issues]),
      sourceRepositoryUrl,
      project: project({ origin: "gitlab", remote }),
    };
    const file = join(fixture.root, "snyk-hosted.json");
    await writeFile(file, JSON.stringify(report));
    const fromFile = await prepareLocalExternalImport(
      file,
      { ...fixture.selection, sourceRepositoryUrl: remote },
      { environment: fixture.environment },
    );
    expect(fromFile.preview.findings).toHaveLength(0);
    expect(fromFile.preview.excluded).toHaveLength(issues.length);
    const normalized = normalizeSnykIssues(report, "local");
    expect(
      (await fixture.prepareNormalized(normalized)).preview.findings,
    ).toHaveLength(0);
    delete normalized.snykRestContext;
    await expect(fixture.prepareNormalized(normalized)).rejects.toThrow(
      "does not match",
    );

    report.project.attributes.origin = "github-enterprise";
    const mixed = normalizeSnykIssues(report, "local");
    const sibling = normalizeSnykJson(snykJson(), "local");
    mixed.read += sibling.read;
    mixed.findings.push(...sibling.findings);

    const scp = "git@scm.example.test:team/";
    await using ssh = await snykCheckout(scp + "REPO.git");
    await using other = await snykCheckout(scp + "other.git");
    expect((await ssh.prepareNormalized(mixed)).preview.findings).toHaveLength(
      1,
    );
    await expect(other.prepareNormalized(mixed)).rejects.toThrow(
      "does not match",
    );
  },
);

test("mixed GitLab and plugin rows check each local repository claim", async () => {
  const url = "https://scm.example.test/Team/repo";
  await using fixture = await snykCheckout(url);
  const hosted = normalizeSnykIssues({
    ...envelope(),
    sourceRepositoryUrl: url,
    project: project({ origin: "gitlab", remote: url }),
  });
  const plugin = snykPluginExport();
  const prepare = (repository: string) => {
    plugin.collection.target.repository = repository;
    const legacy = normalizeSnykInput(plugin, "local");
    return fixture.prepareNormalized({
      ...hosted,
      findings: [...legacy.findings, ...hosted.findings],
    });
  };
  expect((await prepare(url + ".git")).preview.findings).toHaveLength(2);
  await expect(prepare(url.toLowerCase() + ".git")).rejects.toThrow(
    "does not match",
  );
  await expect(prepare(url + "-other.git")).rejects.toThrow("does not match");
});

test("typed and opaque siblings preserve a verified GitLab project's own clone alias", async () => {
  const url = "https://scm.example.test/Team/repo";
  const clone = url + ".git";
  const hosted = normalizeSnykIssues({
    ...envelope(),
    sourceRepositoryUrl: url,
    project: project({ origin: "gitlab", remote: clone }),
  });
  const sibling = {
    source_finding_id: "sibling",
    evidence: { title: "Example finding", severity: "high" as const },
  };
  const typed = {
    ...sibling,
    evidence: {
      ...sibling.evidence,
      details: { kind: "sast" as const, repository: { url } },
    },
  };
  const mixed = (...rows: (typeof sibling)[]) => ({
    ...hosted,
    findings: [...hosted.findings, ...rows],
  });
  await using selected = await snykCheckout(url);
  await using alternate = await snykCheckout(clone);
  expect(
    (await selected.prepareNormalized(mixed(sibling))).preview.findings,
  ).toHaveLength(2);
  expect(
    (await alternate.prepareNormalized(mixed(typed))).preview.findings,
  ).toHaveLength(2);
  await expect(alternate.prepareNormalized(mixed(sibling))).rejects.toThrow(
    "does not match",
  );
  const second = normalizeSnykIssues({
    ...envelope([issue({ key: "second" })]),
    sourceRepositoryUrl: clone,
    project: project({ origin: "gitlab", remote: url }),
  });
  const rows = [...hosted.findings, sibling, ...second.findings];
  for (const findings of [rows, rows.toReversed()]) {
    const projected = { read: 3, excluded: [], findings };
    for (const checkout of [selected, alternate])
      expect(
        (await checkout.prepareNormalized(projected)).preview.findings,
      ).toHaveLength(3);
  }
});

test("mixing Snyk project origins keeps case-sensitive native repository claims", async () => {
  const url = "https://scm.example.test/Owner/project";
  await using fixture = await snykCheckout(url, "mixed");
  const row = (origin: string, source: string, remote = source) =>
    normalizeSnykIssues({
      ...envelope([issue({ key: origin })]),
      sourceRepositoryUrl: source,
      project: project({ origin, remote }),
    }).findings[0]!;
  const literal = row("api", url);
  const clone = row("gitlab", url + ".git", url);
  await using wrong = await snykCheckout(url + ".git");
  for (const findings of [
    [clone, literal],
    [literal, clone],
  ]) {
    const input = { read: 2, findings, excluded: [] };
    expect(
      (await fixture.prepareNormalized(input)).preview.findings,
    ).toHaveLength(2);
    await expect(wrong.prepareNormalized(input)).rejects.toThrow(
      "does not match",
    );
  }
  const github = row("github-enterprise", url);
  const gitlab = row("gitlab", url.toLowerCase());
  const nativeCase = row("github-enterprise", url, url.toLowerCase());
  await expect(
    fixture.prepareNormalized({
      read: 1,
      findings: [nativeCase],
      excluded: [],
      sourceRepositoryPlatform: "other",
    }),
  ).rejects.toThrow("does not match");
  for (const findings of [
    [github, gitlab],
    [gitlab, github],
    [nativeCase, row("gitlab", url)],
  ]) {
    await expect(
      fixture.prepareNormalized({
        sourceRepositoryUrl: url,
        read: 2,
        findings,
        excluded: [],
      }),
    ).rejects.toThrow("does not match");
  }
  const projected = normalizeSnykIssues({
    ...snykRestFixture("code", { sourceRepositoryUrl: url.toLowerCase() }),
    project: project({
      manager: "sast",
      origin: "gitlab",
      remote: url.toLowerCase(),
    }),
  });
  delete projected.sourceRepositoryUrl;
  delete projected.findings[0]!.evidence.source_data;
  await expect(
    fixture.prepareNormalized({
      ...projected,
      read: 2,
      findings: [github, ...projected.findings],
    }),
  ).rejects.toThrow("does not match");
  await expect(
    fixture.prepareNormalized(projected, [{ url, platform: "github" }]),
  ).rejects.toThrow("does not match");
  const sca = normalizeSnykIssues({
    ...envelope(),
    sourceRepositoryUrl: url.toLowerCase(),
    project: project({ origin: "gitlab", remote: null }),
  });
  delete sca.sourceRepositoryUrl;
  delete sca.findings[0]!.evidence.source_data;
  await expect(
    fixture.prepareNormalized(sca, [
      { url: url.toLowerCase(), platform: "github" },
    ]),
  ).rejects.toThrow("does not match");
  expect(
    (await fixture.prepareNormalized(sca, [{ url, platform: "github" }]))
      .preview.findings,
  ).toHaveLength(1);
  expect((await fixture.prepareNormalized(sca)).preview.findings).toHaveLength(
    1,
  );
  const other = "https://gitlab.com/Other/project";
  execFileSync("git", [
    "-C",
    fixture.repository,
    "remote",
    "add",
    "other",
    other,
  ]);
  const references = [{ url }, { url: other }];
  for (const platform of ["github", "other"] as const)
    await expect(
      fixture.prepareNormalized(
        { ...sca, sourceRepositoryPlatform: platform },
        references,
      ),
    ).rejects.toThrow("does not match");
  delete sca.sourceRepositoryPlatform;
  expect(
    (await fixture.prepareNormalized(sca, references)).preview.findings,
  ).toHaveLength(1);
  sca.sourceRepositoryPlatform = "github";
  const ssh = {
    url: "git@scm.example.test:owner/project.git",
    platform: "github" as const,
  };
  for (const refs of [
    [ssh],
    [ssh, { url }],
    [{ url }, ssh],
    [
      {
        ...ssh,
        url: "ssh://%67it@%73cm.example.test%3A22/owner/project.git",
      },
    ],
  ])
    expect(
      (await fixture.prepareNormalized(sca, refs)).preview.findings,
    ).toHaveLength(1);
  const privateSsh = "ssh://deploy@scm.example.test/Owner/project.git";
  execFileSync("git", [
    "-C",
    fixture.repository,
    "remote",
    "set-url",
    "other",
    privateSsh,
  ]);
  sca.sourceRepositoryPlatform = "other";
  expect(
    (await fixture.prepareNormalized(sca, [{ url: privateSsh }])).preview
      .findings,
  ).toHaveLength(1);
  await expect(
    fixture.prepareNormalized(sca, [
      { url: privateSsh.replace("deploy@", "reader@") },
    ]),
  ).rejects.toThrow("does not match");
});
