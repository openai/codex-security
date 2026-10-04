import type { JsonObject, SemanticScan } from "./scan-semantics.js";

export interface ScanMergeInput {
  scanId: string;
  scanDir: string;
  draft: SemanticScan;
  sourceFindings: JsonObject[];
}
