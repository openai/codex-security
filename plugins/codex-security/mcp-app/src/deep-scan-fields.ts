import type defaults from "../../scripts/deep_scan_defaults.json";
import fields from "../../scripts/deep_scan_fields.json";

export const DEEP_SCAN_FIELDS = fields as [
  name: keyof typeof defaults,
  tomlKey: string,
  cliFlag: string | null,
  projectKey?: string,
][];
