import { normalizeCheckmarxOne } from "./checkmarx-one.js";
import { normalizeCheckmarxXml } from "./checkmarx-xml.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import { readScannerBytes } from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

// XML can signal its byte order with a BOM or the opening '<' code unit.
function reportEncoding(bytes: Buffer) {
  const [first, second] = bytes;
  if ((first === 0xff && second === 0xfe) || (first === 0x3c && second === 0))
    return "utf-16le";
  if ((first === 0xfe && second === 0xff) || (first === 0 && second === 0x3c))
    return "utf-16be";
  return "utf-8";
}

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
  const bytes = await readScannerBytes(path);
  const encoding = reportEncoding(bytes);
  const contents = new TextDecoder(encoding, { fatal: true }).decode(bytes);
  const first = contents.trimStart()[0];
  if (first === "<") return normalizeCheckmarxXml(contents, repository, target);
  if (first === "{" && encoding === "utf-8")
    return normalizeCheckmarxOne(contents, repository, target);
  throw new Error(
    "Expected a Checkmarx One CLI JSON report or a CxSAST XML report.",
  );
}
