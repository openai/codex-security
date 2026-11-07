const repositoryUrl = "https://github.com/example/repo";
const asset = {
  asset_id: "10000000-0000-4000-8000-000000000001",
  asset_class: "CODE_REPOSITORY",
  asset_name: "example/repo",
};
export const tenableFinding = {
  asset_id: asset.asset_id,
  finding_id: "00017",
  finding_name: "Example finding",
  severity: "High",
  state: "ACTIVE",
};
export const tenableReport = {
  format: "tenable-one-code-repository/v1",
  asset,
  repository_url: repositoryUrl,
  findings: [
    { ...tenableFinding, code_file_path: "src/app.ts", code_line_number: "7" },
  ],
};
