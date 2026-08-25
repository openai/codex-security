export const CODEX_SECURITY_THREAD_SOURCES = {
  scan: "security_scan",
  validation: "security_validation",
  remediation: "security_remediation",
  scanComparison: "security_scan_comparison",
} as const;

export type CodexSecurityThreadSource =
  (typeof CODEX_SECURITY_THREAD_SOURCES)[keyof typeof CODEX_SECURITY_THREAD_SOURCES];
