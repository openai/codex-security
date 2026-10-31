import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { canonicalJson } from "../src/record.js";
import { normalizeSnykIssues } from "../src/snyk-rest-findings.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";

import {
  snykIssue,
  snykOptions,
  snykRestFixture,
} from "./support/snyk-rest-fixtures.js";

const { organizationId, projectId, sourceRepositoryUrl } = snykOptions;
const command = [
  "import",
  "snyk",
  projectId,
  "--snyk-org",
  organizationId,
  "--source-repository-url",
  sourceRepositoryUrl,
  "--format",
  "json",
];
const environment = {
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  SNYK_TOKEN: "synthetic",
};

test.each(["open-source", "code"] as const)(
  "import snyk emits the selected %s report directly",
  async (product) => {
    const cli = createCliTest(main);
    const code = product === "code";
    const apiOrigin = code ? snykOptions.apiOrigin : "https://api.snyk.io";
    const report = { ...snykRestFixture(product), apiOrigin };
    const productFlags = code
      ? ["--snyk-product", product, "--snyk-api-origin", apiOrigin]
      : [];
    const status = await cli.runCli([...command, ...productFlags], {
      ...dependencies({ environment }),
      hostedScannerFetch: async (url) => {
        expect(url.origin).toBe(apiOrigin);
        if (
          url.pathname === `/rest/orgs/${organizationId}/projects/${projectId}`
        )
          return Response.json({ data: JSON.parse(report.projectJson) });
        expect(url.pathname).toBe(`/rest/orgs/${organizationId}/issues`);
        expect(url.searchParams.get("type")).toBe(
          code ? "code" : "package_vulnerability",
        );
        return new Response(report.pages[0]!.responseJson);
      },
    });
    expect({ status, error: cli.stderr.text() }).toEqual({
      status: 0,
      error: "",
    });
    expect(JSON.parse(cli.stdout.text())).toEqual(report);
  },
);

test("import snyk requires opt-in and keeps failed collections out of redirected JSON", async () => {
  const fetch = mock(
    async () => new Response("projet refusé \u202edenied", { status: 403 }),
  );
  const disabled = createCliTest(main);
  expect(
    await disabled.runCli(command, {
      ...dependencies({ environment: {} }),
      hostedScannerFetch: fetch,
    }),
  ).toBe(2);
  expect(fetch).not.toHaveBeenCalled();
  expect(disabled.stdout.text()).toBe("");
  expect(disabled.stderr.text()).toContain(
    "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
  );

  const enabled = createCliTest(main);
  expect(
    await enabled.runCli(command, {
      ...dependencies({ environment }),
      hostedScannerFetch: fetch,
    }),
  ).toBe(2);
  expect(enabled.stdout.text()).toBe("");
  expect(enabled.stderr.text()).toContain("projet refusé \\u202edenied");
});

test("Snyk CLI escapes cursors in human output and retains the native JSON value", async () => {
  const cursor = "pré\u001b[2Jcursor";
  const report = snykRestFixture("open-source");
  for (const format of ["md", "default", "toon", "json"] as const) {
    const cli = createCliTest(main, { stdout: true });
    const args =
      format === "default" ? command.slice(0, -2) : command.with(-1, format);
    const status = await cli.runCli(args, {
      ...dependencies({ environment }),
      hostedScannerFetch: async (url) => {
        if (url.pathname.endsWith("/projects/" + projectId))
          return Response.json({ data: JSON.parse(report.projectJson) });
        if (url.searchParams.has("starting_after"))
          return Response.json({ data: [] });
        return Response.json({
          data: [],
          links: { next: "?starting_after=" + encodeURIComponent(cursor) },
        });
      },
    });
    expect(status).toBe(0);
    const output = cli.stdout.text();
    if (format !== "json") {
      expect(output).not.toContain("\u001b");
      expect(output).toContain("pré\\u001b[2Jcursor");
    } else {
      expect(JSON.parse(output).pages[1].startingAfter).toBe(cursor);
    }
  }
});

test("Snyk --schema describes the complete saved report", async () => {
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      ["import", "snyk", "--schema", "--json"],
      dependencies({
        environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
      }),
    ),
  ).toBe(0);
  const { output } = JSON.parse(cli.stdout.text());
  expect(output.properties).toMatchObject({
    format: { const: "snyk-rest-issues/v2" },
    complete: { const: true },
    projectJson: { type: "string" },
    targetJson: { type: "string" },
    pages: { items: { properties: { responseJson: { type: "string" } } } },
  });
});

test.each([
  ["open-source", "repeated"],
  ["code", "rekeyed"],
  ["open-source", "distinct"],
] as const)(
  "import snyk handles %s pages with %s resource IDs",
  async (product, variant) => {
    const report = snykRestFixture(product);
    const first = {
      ...snykIssue(product === "code"),
      id: "abcdef01-4444-4444-8444-444444444444",
    };
    const second = {
      ...first,
      id:
        variant === "distinct"
          ? "bbbbbbbb-4444-4444-8444-444444444444"
          : first.id.toUpperCase(),
      attributes: {
        ...first.attributes,
        key: variant === "rekeyed" ? "updated-key" : first.attributes.key,
      },
    };
    const pages = [
      {
        startingAfter: null,
        responseJson: canonicalJson({
          data: [first],
          links: { next: "?starting_after=page-two" },
        }),
      },
      {
        startingAfter: "page-two",
        responseJson: canonicalJson({ data: [second] }),
      },
    ];
    const cursors: (string | null)[] = [];
    const cli = createCliTest(main);
    const status = await cli.runCli([...command, "--snyk-product", product], {
      ...dependencies({ environment }),
      hostedScannerFetch: async (url) => {
        if (url.pathname.endsWith("/projects/" + projectId))
          return Response.json({ data: JSON.parse(report.projectJson) });
        const page = pages[cursors.length]!;
        cursors.push(url.searchParams.get("starting_after"));
        return new Response(page.responseJson);
      },
    });
    expect(cursors).toEqual([null, "page-two"]);
    if (variant === "distinct") {
      expect(status).toBe(0);
      expect(JSON.parse(cli.stdout.text())).toMatchObject({
        complete: true,
        pages,
      });
    } else {
      expect(status).toBe(2);
      expect(cli.stdout.text()).toBe("");
      expect(cli.stderr.text()).toContain("overlapping issue IDs");
    }
    const saved = normalizeSnykIssues({ ...report, pages });
    const reason =
      variant === "rekeyed"
        ? "overlapping issue IDs"
        : "Ambiguous duplicate source identity";
    expect(saved.findings).toBeEmpty();
    expect(saved.excluded).toMatchObject([
      { position: 1, reason: expect.stringContaining(reason) },
      { position: 2, reason: expect.stringContaining(reason) },
    ]);
  },
);
