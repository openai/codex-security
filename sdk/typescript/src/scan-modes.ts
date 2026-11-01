export const SCAN_MODES = ["standard", "deep"] as const;
export type ScanMode = (typeof SCAN_MODES)[number];
