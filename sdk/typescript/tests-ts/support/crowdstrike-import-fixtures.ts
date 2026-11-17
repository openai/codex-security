import { createHash } from "node:crypto";

// The checkout fixture writes empty files, as FCS scanned them.
const emptyFile = createHash("sha256").update("").digest("hex");
export const detection = {
  file: "infra/net/main.tf",
  file_sha256: emptyFile,
  line: 7,
  resource_type: "aws_security_group",
  resource_name: "example",
  issue_type: "IncorrectValue",
  reason: "aws_security_group[example] 'SSH' (Port:22) is public",
  recommendation:
    "aws_security_group[example] 'SSH' (Port:22) should not be public",
};
export const misconfiguration = {
  rule_name: "Example Sensitive Port Is Exposed",
  rule_uuid: "10000000-0000-4000-8000-000000000001",
  rule_category: "Networking and Firewall",
  description: "Example rule description",
  severity: "High",
  platform: "Terraform",
  cloud_provider: "AWS",
  service: "EC2",
  rule_type: "Example",
  detections: [detection],
};
export const secret = {
  rule_name: "Passwords And Secrets - Example Access Key",
  rule_uuid: "20000000-0000-4000-8000-000000000002",
  rule_category: "Secret Management",
  description: "Example secret description",
  severity: "Critical",
  platform: "Generic",
  cloud_provider: "common",
  service: "common",
  rule_type: "Example",
  detections: [
    {
      file: "infra/provider.tf",
      file_sha256: emptyFile,
      line: 3,
      resource_type: null,
      resource_name: null,
      issue_type: "RedundantAttribute",
      reason: "Hardcoded secret key appears in source",
      recommendation: "Hardcoded secret key should not appear in source",
    },
  ],
};
export const report = {
  fcs_version: "4.2.3",
  path: ".",
  project_name: "",
  scan_type: "Local",
  scan_uuid: "30000000-0000-4000-8000-000000000003",
  scan_performed_at: "2026-11-10T12:00:00Z",
  rule_detections: [misconfiguration, secret],
  detection_summary: {},
  stats: {},
};
