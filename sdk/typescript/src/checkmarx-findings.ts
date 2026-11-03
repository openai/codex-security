import { normalizeCheckmarxOne } from "./checkmarx-one.js";
import { normalizeCheckmarxXml } from "./checkmarx-xml.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import { readScannerText } from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

/** Read a Checkmarx One CLI JSON export or a self-managed CxSAST XML report. */
export async function readCheckmarxFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
) {
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Checkmarx",
    target,
  );
  const contents = await readScannerText(path);
  switch (contents.trimStart()[0]) {
    case "{":
      return normalizeCheckmarxOne(contents, repository, target);
    case "<":
      return normalizeCheckmarxXml(contents, repository, target);
    default:
      throw new Error(
        "Expected a Checkmarx One CLI JSON report or a CxSAST XML report.",
      );
  }
}
