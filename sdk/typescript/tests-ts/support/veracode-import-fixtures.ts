const origin = "https://scanner.example.test";
const application = "00000000-0000-4000-8000-000000000001";

export function veracodePolicyRow(issueId = 1) {
  return {
    issue_id: issueId,
    scan_type: "STATIC",
    context_type: "APPLICATION",
    context_guid: application,
    violates_policy: true,
    build_id: 12,
    count: 1,
    description: "Vendor description",
    finding_status: {
      status: "OPEN",
      resolution: "UNRESOLVED",
      mitigation_review_status: "NONE",
    },
    finding_details: {
      severity: 4,
      cwe: { id: 79, name: "Example weakness" },
      finding_category: { id: 4, name: "Example category" },
      module: "example.jar",
      file_path: "compiled/Example.java",
      file_line_number: 17,
    },
  };
}

export function veracodePolicyPage(
  findings = [veracodePolicyRow()],
  { number = 0, size = 20, total = findings.length } = {},
) {
  const resource = `${origin}/appsec/v2/applications/${application}/findings`;
  const link = (page: number) => ({
    href: `${resource}?scan_type=STATIC&page=${page}&size=${size}`,
  });
  const pages = Math.ceil(total / size);
  return {
    _embedded: { findings },
    _links: {
      self: link(number),
      application: { href: `${origin}/appsec/v1/applications/${application}` },
      ...(number > 0 ? { prev: link(number - 1) } : {}),
      ...(number + 1 < pages ? { next: link(number + 1) } : {}),
    },
    page: { size, number, total_elements: total, total_pages: pages },
  };
}
