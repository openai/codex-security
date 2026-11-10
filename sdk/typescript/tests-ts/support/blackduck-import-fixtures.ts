const api = "https://scanner.example.test/api";
const projectVersion = `${api}/projects/project-a/versions/release-a`;
const component = "components/component-a/versions/version-a";

export function blackDuckBomRow(
  advisory = "BDSA-2099-0001",
  version = "release-a",
) {
  return {
    componentVersion: `${api}/${component}`,
    componentName: "Example Library",
    componentVersionName: "1.0",
    componentVersionOriginName: "maven",
    componentVersionOriginId: "example:library:1.0",
    vulnerabilityWithRemediation: {
      source: "BDSA",
      vulnerabilityName: advisory,
      severity: "HIGH",
      remediationStatus: "NEW",
    },
    _meta: {
      links: [
        {
          rel: "matched-files",
          href: `${api}/projects/project-a/versions/${version}/${component}/origins/origin-a/matched-files`,
        },
      ],
    },
  };
}

export function blackDuckBomReport(items = [blackDuckBomRow()]) {
  return {
    totalCount: items.length,
    items,
    _meta: { href: `${projectVersion}/vulnerable-bom-components`, links: [] },
  };
}
