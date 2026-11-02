import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  normalizeVeracodeFindings,
  readVeracodeFindings,
  veracodeReportRepositories,
} from "../src/veracode-findings.js";
import {
  veracodePolicyPage,
  veracodePolicyRow,
} from "./support/veracode-import-fixtures.js";

const repository = "https://vcs.example.test/org/application";
const normalize = (input: unknown, target: "cloud" | "local" = "cloud") =>
  normalizeVeracodeFindings(input, repository, target);
const otherApp = "00000000-0000-4000-8000-000000000002";

function capture() {
  return [0, 1, 2].map((number) =>
    veracodePolicyPage([veracodePolicyRow(number + 1)], {
      number,
      size: 1,
      total: 3,
    }),
  );
}

test("keeps only finding-level evidence, not a generated checkout location or a policy verdict", () => {
  const row = {
    ...veracodePolicyRow(),
    count: 4,
    violates_policy: false,
    extra: { retained: [1] },
  };
  const report = veracodePolicyPage([row]);
  const result = normalize({
    ...report,
    build: "unrelated collection snapshot",
  });
  expect(result).toEqual(normalize(report, "local"));
  expect(result.read).toBe(1);
  expect(result.excluded).toEqual([]);
  const { evidence } = result.findings[0]!;
  expect(evidence).toMatchObject({
    title: "Example category",
    severity: "high",
    description: row.description,
    locations: [],
    code_revision: null,
    source_scan_id: null,
    details: {
      kind: "sast",
      source_status: "OPEN",
      weakness_ids: ["CWE-79"],
      repository: { url: repository },
    },
  });
  const original = structuredClone(row);
  expect(evidence.source_data).toEqual({
    sourceRepositoryUrl: repository,
    applicationUrl: report._links.application.href,
    row: original,
  });
  row.extra.retained.push(2);
  expect(evidence.source_data?.["row"]).toEqual(original);
});

test("canonical severity covers the six native levels and malformed levels are not guessed", () => {
  const rows = [0, 1, 2, 3, 4, 5, 6, -1, 1.5].map((severity, index) => {
    const row = veracodePolicyRow(index + 1);
    row.finding_details.severity = severity;
    return row;
  });
  const result = normalize(veracodePolicyPage(rows));
  expect(result.findings.map(({ evidence }) => evidence.severity)).toEqual([
    "informational",
    "low",
    "low",
    "medium",
    "high",
    "critical",
  ]);
  expect(result.excluded.map(({ position }) => position)).toEqual([7, 8, 9]);
});

test("fully enumerated pages replay identically after reordering, page-size changes and omitted issues", () => {
  const pages = capture();
  const single = veracodePolicyPage(
    pages.flatMap((page) => page._embedded.findings),
  );
  const full = normalize(single);
  expect(full.findings).toHaveLength(3);
  expect(normalize(pages)).toEqual(full);
  expect(normalize(pages.toReversed())).toEqual(full);
  expect(
    normalize(veracodePolicyPage([veracodePolicyRow(2)])).findings,
  ).toEqual([full.findings[1]!]);
  const changed = veracodePolicyRow(2);
  changed.finding_status = {
    status: "CLOSED",
    resolution: "MITIGATED",
    mitigation_review_status: "APPROVED",
  };
  changed.build_id++;
  changed.finding_details.file_line_number++;
  const finding = normalize(veracodePolicyPage([changed])).findings[0]!;
  expect(finding.source_finding_id).toBe(full.findings[1]!.source_finding_id);
  expect(finding.evidence).not.toEqual(full.findings[1]!.evidence);
  expect(finding.evidence.source_data?.["row"]).toEqual(changed);
});

test("rejects holes, duplicate pages, changing totals or selection, and contradictory navigation", () => {
  const [first, middle, last] = capture() as [
    ReturnType<typeof veracodePolicyPage>,
    ReturnType<typeof veracodePolicyPage>,
    ReturnType<typeof veracodePolicyPage>,
  ];
  for (const input of [
    first,
    [first, last],
    [first, middle, middle],
    [first, middle, last, last],
    [first, { ...middle, _embedded: { findings: [] } }, last],
    [
      first,
      {
        ...middle,
        page: { ...middle.page, total_elements: 4, total_pages: 4 },
      },
      last,
    ],
    [first, { ...middle, page: { ...middle.page, size: 2 } }, last],
    [
      first,
      middle,
      { ...last, _links: { ...last._links, next: first._links.self } },
    ],
    [
      { ...first, _links: { ...first._links, next: first._links.self } },
      middle,
      last,
    ],
  ])
    expect(() => normalize(input)).toThrow();
  const filtered = structuredClone(middle);
  for (const [rel, link] of Object.entries(filtered._links))
    if (rel !== "application") link.href += "&violates_policy=true";
  expect(() => normalize([first, filtered, last])).toThrow(/selection/);
});

test("accepts collection self links while requiring navigation to identify the destination page", () => {
  const pages = capture();
  const expected = normalize(pages);
  for (const page of pages)
    page._links.self = {
      ...page._links.self,
      href: page._links.self.href.replace(/&page=\d+&size=\d+/u, ""),
    };
  expect(normalize(pages)).toEqual(expected);
  const before = pages[0]!._links.next!.href;
  pages[0]!._links.next!.href = before.replace("&size=1", "");
  expect(() => normalize(pages)).toThrow(/size/);
  pages[0]!._links.next!.href = pages[0]!._links.self.href;
  expect(() => normalize(pages)).toThrow(/page/);
});

test("matches row filters and equivalent HAL list and boolean selections", () => {
  const pages = capture();
  const expected = normalize(pages);
  for (const page of pages) {
    for (const [rel, link] of Object.entries(page._links)) {
      if (rel === "application") continue;
      link.href +=
        rel === "self"
          ? "&cwe=079,89&finding_category=04,20&include_annot=TRUE"
          : "&cwe=89&cwe=79&finding_category=20,4&include_annot=true";
    }
  }
  expect(normalize(pages)).toEqual(expected);
  const row = veracodePolicyRow();
  const status = (isNew: boolean) => ({
    ...row,
    finding_status: { ...row.finding_status, new: isNew },
  });
  for (const [query, message] of [
    ["cwe=89", "cwe"],
    ["finding_category=20", "finding_category"],
    ["new=TRUE", "new"],
  ] as const) {
    const page = veracodePolicyPage([status(false)]);
    page._links.self.href += "&" + query;
    expect(() => normalize(page)).toThrow(message);
  }
  const page = veracodePolicyPage([
    status(false),
    { ...status(true), issue_id: 2 },
  ]);
  page._links.self.href += "&new=false";
  expect(normalize(page).findings).toHaveLength(2);
});

test("a CWE-filtered capture retains static findings alongside unsupported manual findings", () => {
  const row = veracodePolicyRow();
  const page = veracodePolicyPage([row, row]);
  page._links.self.href = page._links.self.href.replace(
    "scan_type=STATIC",
    "cwe=79",
  );
  const manual = { ...row, scan_type: "MANUAL", finding_details: { cwe: 79 } };
  const report = normalize({ ...page, _embedded: { findings: [row, manual] } });
  expect(report.findings).toHaveLength(1);
  expect(report.excluded).toHaveLength(1);
});

test("checks explicit score, annotation and new-finding selections before retaining a row", () => {
  const row = veracodePolicyRow();
  const native = {
    ...row,
    finding_details: { ...row.finding_details, cvss: "9.1" },
    annotations: [{ comment: "Example annotation" }],
    finding_status: { ...row.finding_status, new: "false" },
  };
  const page = veracodePolicyPage([native]);
  const self = page._links.self.href;
  for (const [query, reason] of [
    ["cvss_gte=9.2", "cvss"],
    ["cvss=9", "cvss"],
    ["include_annot=false", "include_annot"],
    ["new=true", "new"],
    ["new=false&new=true", "new"],
  ] as const) {
    page._links.self.href = self + "&" + query;
    expect(() => normalize(page)).toThrow(reason);
  }
  page._links.self.href = self + "&cvss=9.10&include_annot=true";
  expect(
    normalize({
      ...page,
      _links: {
        ...page._links,
        first: { href: self + "&cvss=9.1&include_annot=TRUE" },
      },
    }).findings,
  ).toHaveLength(1);
  page._links.self.href = self + "&finding_category=4";
  const wrong = {
    ...native,
    finding_details: {
      ...native.finding_details,
      finding_category: { id: "20", name: "Other" },
    },
  };
  expect(() =>
    normalize({ ...page, _embedded: { findings: [wrong] } }),
  ).toThrow(/finding_category/);
});

test("accepts a scoped native empty page but rejects errors, summaries, Pipeline and raw row arrays", () => {
  const overlapping = capture();
  overlapping[1]!._embedded.findings = overlapping[0]!._embedded.findings;
  expect(() => normalize(overlapping)).toThrow(/Overlapping/);
  const empty = veracodePolicyPage([]);
  const { _embedded, ...omitted } = empty;
  expect(normalize(omitted)).toEqual(normalize(empty));
  expect(() =>
    normalize({ ...omitted, page: veracodePolicyPage().page }),
  ).toThrow();
  expect(normalize(empty)).toEqual({ read: 0, findings: [], excluded: [] });
  expect(
    normalize({ ...empty, page: { ...empty.page, total_pages: 1 } }),
  ).toEqual(normalize(empty));
  for (const input of [
    [],
    {},
    [veracodePolicyRow()],
    { scan_status: "SUCCESS", findings: [] },
    { policy_compliance_status: "PASSED" },
    { ...empty, status: 403 },
    { ...empty, error: "unavailable" },
    { ...empty, _embedded: { findings: [], errors: [{ detail: "failed" }] } },
    { ...empty, _embedded: {} },
    { ...empty, page: { ...empty.page, total_elements: "0" } },
    { ...empty, _links: { self: empty._links.self } },
  ])
    expect(() => normalize(input)).toThrow();
});

test("enforces exact and minimum native severity selections", () => {
  const page = veracodePolicyPage();
  const self = page._links.self.href;
  for (const filter of ["severity=4", "severity_gte=4", "severity_gte=0"]) {
    page._links.self.href = self + "&" + filter;
    expect(normalize(page).findings).toHaveLength(1);
  }
  for (const filter of ["severity=3", "severity_gte=5", "severity=6"]) {
    page._links.self.href = self + "&" + filter;
    expect(() => normalize(page)).toThrow(/severity/);
  }
});

test("detects overlap in unfiltered pages without conflating issues from different engines", () => {
  const pages = capture();
  for (const page of pages)
    for (const link of Object.values(page._links))
      link.href = link.href.replace("scan_type=STATIC&", "");
  const dynamic = { ...veracodePolicyRow(1), scan_type: "DYNAMIC" };
  pages[1]!._embedded.findings = [dynamic];
  expect(normalize(pages).findings).toHaveLength(2);
  pages[2]!._embedded.findings = [dynamic];
  expect(() => normalize(pages)).toThrow(/Overlapping/);
});

test("never widens the app, host, sandbox or requested engine, including through HAL links", () => {
  const page = veracodePolicyPage();
  const row = veracodePolicyRow();
  const self = page._links.self.href;
  for (const href of [
    self.replace("scanner.example.test", "other.example.test"),
    self.replace(row.context_guid, otherApp),
    self.replace("STATIC", "DYNAMIC"),
    self.replace("STATIC", "SCA"),
    self + `&context=${row.context_guid}`,
    self + "&scan_type=DAST",
    self + "&sca_dep_mode=DIRECT",
    self + "&sca_scan_mode=UPLOAD",
    self.replace("page=0", "page=1"),
    self.replace("size=20", "size=1"),
    self.replace("/findings", "/summary"),
    self.replace("/findings", "/wrong/../findings"),
    self + "#fragment",
  ])
    expect(() =>
      normalize({ ...page, _links: { ...page._links, self: { href } } }),
    ).toThrow();
  for (const finding of [
    { ...row, context_type: "SANDBOX" },
    { ...row, context_guid: otherApp },
    { ...row, scan_type: "DYNAMIC" },
  ])
    expect(() => normalize(veracodePolicyPage([row, finding]))).toThrow();
  expect(() =>
    normalize({
      ...page,
      _links: {
        ...page._links,
        sca: {
          href: self.replace("scanner.example.test", "other.example.test"),
        },
      },
    }),
  ).toThrow(/origin/);
  const mixed = capture();
  mixed[1] = JSON.parse(
    JSON.stringify(mixed[1]).replaceAll(row.context_guid, otherApp),
  );
  expect(() => normalize(mixed)).toThrow(/application/);
  const moved = JSON.parse(
    JSON.stringify(page).replaceAll(
      "scanner.example.test",
      "other.example.test",
    ),
  );
  const other = JSON.parse(
    JSON.stringify(page).replaceAll(row.context_guid, otherApp),
  );
  expect(
    new Set(
      [page, moved, other].map(
        (value) => normalize(value).findings[0]!.source_finding_id,
      ),
    ).size,
  ).toBe(3);
});

test("optional HAL query templates are not sandbox scope, and discovery links do not select SCA", () => {
  const row = veracodePolicyRow();
  const page = veracodePolicyPage([row]);
  const path = page._links.self.href.split("?")[0]!;
  const template = "{&context,severity,severity_gte,scan_type}";
  const links = {
    ...page._links,
    self: { href: `${path}?violates_policy=true${template}`, templated: true },
    sca: {
      href: `${path}?violates_policy=true&scan_type=SCA${template}`,
      templated: true,
    },
  };
  expect(normalize({ ...page, _links: links })).toEqual(normalize(page));
  const uppercase = {
    ...links,
    self: { ...links.self, href: links.self.href.replace("=true", "=TRUE") },
  };
  expect(normalize({ ...page, _links: uppercase })).toEqual(normalize(page));
  const invalidTemplate = {
    ...links,
    self: { ...links.self, href: links.self.href.replace("{&", "{?") },
  };
  expect(() => normalize({ ...page, _links: invalidTemplate })).toThrow(
    /HAL URL/,
  );
  expect(() =>
    normalize({
      ...page,
      _links: { ...links, self: { href: links.self.href } },
    }),
  ).toThrow();
  expect(() =>
    normalize({
      ...page,
      _links: links,
      _embedded: { findings: [{ ...row, violates_policy: false }] },
    }),
  ).toThrow(/violates_policy/);
  const rows = [
    row,
    { ...row, scan_type: "DYNAMIC" },
    { ...row, scan_type: "SCA" },
  ];
  const result = normalize({ ...veracodePolicyPage(rows), _links: links });
  expect(result.read).toBe(3);
  expect(result.findings).toHaveLength(1);
  expect(result.excluded.map(({ position }) => position)).toEqual([2, 3]);
});

test("declared totals cannot hide duplicate issues; malformed IDs do not consume valid occurrences", () => {
  const sparse = veracodePolicyPage();
  delete sparse._embedded.findings[0];
  expect(() => normalize(sparse)).toThrow(
    "Veracode finding must be an object.",
  );
  const valid = veracodePolicyRow(3);
  expect(() =>
    normalize(veracodePolicyPage([valid, veracodePolicyRow(2), valid])),
  ).toThrow(/duplicate|overlap/i);
  const result = normalize(veracodePolicyPage([valid, veracodePolicyRow(0)]));
  expect(result.findings).toHaveLength(1);
  expect(result.excluded).toMatchObject([
    { position: 2, source_finding_id: null },
  ]);
});

test("prepared provenance binds the repository and native occurrence", () => {
  const [first, second] = normalize(
    veracodePolicyPage([veracodePolicyRow(), veracodePolicyRow(2)]),
  ).findings;
  const data = first!.evidence.source_data;
  const retained = (source_data: typeof data, id = first!.source_finding_id) =>
    veracodeReportRepositories(
      "veracode",
      [
        {
          source_finding_id: id,
          evidence: { ...first!.evidence, source_data },
        },
      ],
      "cloud",
    ).get(id);
  expect(retained(data)?.url).toBe(repository);
  expect(() => retained(data, second!.source_finding_id)).toThrow(
    /source finding ID/,
  );
  expect(() => retained({ ...data, row: null })).toThrow(/retained finding/);
  expect(() =>
    retained({
      ...data,
      row: { ...veracodePolicyRow(), context_guid: otherApp },
    }),
  ).toThrow(/context/);
  expect(
    retained(
      { applicationUrl: "https://scanner.example.test/dashboard" },
      "custom-issue-id",
    ),
  ).toBeUndefined();
  expect(() => retained(undefined)).toThrow(/source-repository-url/);
  for (const source of [
    "",
    "https://vcs.example.test",
    "https://vcs.example.test/org",
    "https://user@vcs.example.test/org/repo",
    `${repository}?filter=1`,
    `${repository}#ref`,
    `${repository}/%2e%2e/repo`,
    `${repository}%2frepo`,
    `${repository}\\repo`,
  ]) {
    expect(() =>
      normalizeVeracodeFindings(veracodePolicyPage([]), source),
    ).toThrow(/source-repository-url/);
    expect(() => retained({ ...data, sourceRepositoryUrl: source })).toThrow(
      /source-repository-url/,
    );
  }
});

test("gzip replay preserves the native row, while Cloud and local retain their existing evidence limits", async () => {
  const path = await mkdtemp(join(tmpdir(), "veracode-findings-"));
  try {
    const report = join(path, "findings.json");
    const pages = capture();
    for (const bytes of [
      Buffer.from(JSON.stringify(pages)),
      gzipSync(JSON.stringify(pages)),
    ]) {
      await writeFile(report, bytes);
      for (const target of ["cloud", "local"] as const)
        expect(await readVeracodeFindings(report, repository, target)).toEqual(
          normalize(pages),
        );
    }
    const large = { ...veracodePolicyRow(), original: "x".repeat(270_000) };
    expect(normalize(veracodePolicyPage([large])).excluded).toHaveLength(1);
    expect(
      normalize(veracodePolicyPage([large]), "local").findings[0]!.evidence
        .source_data?.["row"],
    ).toEqual(large);
  } finally {
    await rm(path, { recursive: true, force: true });
  }
});
