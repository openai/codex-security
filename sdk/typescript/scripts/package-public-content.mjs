import { createHash } from "node:crypto";
import { brotliDecompressSync } from "node:zlib";

export const MAX_EXPANDED_ASSET_BYTES = 32 * 1024 * 1024;

const PUBLIC_PNG_SHA256 = new Set([
  "9b9c2b09b2fa064611fb62307d321d5c2ea70cf0789f7ce34cdb0fc0d9190b3a", // logo
  "5656b77b2794178ccbfbc162e449b8d269351a90284ee41bca25189fb529ac90", // context overview
  "d73d369bb50117fd3a6d085ca6be45e6a26192b28f87f69eaddd48894fbbe727", // context path
]);

const internalMarker =
  /(?:internal\.api\.openai\.org|gateway\.[a-z0-9.-]*internal|\.openai\.org|openai\.firewall\.socket\.dev|socket\x2dfirewall\x2dregistry|openai\.(?:enterprise\.)?slack\.com|app\.slack\.com\/client|(?:app\.notion\.com\/p|notion\.so)\/openai|linear\.app\/openai|(?:github\.com[:/]|api\.github\.com\/repos\/|raw\.githubusercontent\.com\/)openai\/openai(?:\.git)?(?![a-z0-9_-])|LicenseRef\x2dProprietary|\/Users\/|\/home\/dev-user|flow\.apps\.openai\.org|(?<![a-z0-9_-])go\/[a-z0-9_-]+)/iu;

/**
 * @param {Map<string, Buffer>} archiveFiles
 * @param {Buffer} [archiveMetadata]
 */
export function assertPublicPackageContents(
  archiveFiles,
  archiveMetadata = Buffer.alloc(0),
) {
  assertPublicText(archiveMetadata.toString("utf8"));
  const compressedParts = new Map();
  for (const [path, bytes] of archiveFiles) {
    assertPublicText(path);
    const part = /^(.*\.br)\.part-([0-9]+)$/iu.exec(path);
    if (part !== null) {
      const [, name, index] = part;
      const parts = compressedParts.get(name) ?? [];
      parts.push({ path, index: Number(index), bytes });
      compressedParts.set(name, parts);
    } else if (/\.br$/iu.test(path)) {
      assertPublicBrotli(bytes, path);
    } else if (/\.png$/iu.test(path)) {
      if (
        !PUBLIC_PNG_SHA256.has(createHash("sha256").update(bytes).digest("hex"))
      )
        throw new Error(
          `npm tarball contains an unexpected PNG asset: ${path}.`,
        );
    } else {
      assertPublicText(bytes.toString("utf8"));
    }
  }
  for (const parts of compressedParts.values()) {
    parts.sort((left, right) => left.index - right.index);
    assertPublicBrotli(
      Buffer.concat(parts.map(({ bytes }) => bytes)),
      parts[0].path,
    );
  }
}

function assertPublicBrotli(bytes, path) {
  const result = brotliDecompressSync(bytes, {
    info: true,
    maxOutputLength: MAX_EXPANDED_ASSET_BYTES,
  });
  if (result.engine.bytesWritten !== bytes.length) {
    throw new Error(`npm tarball contains trailing Brotli data: ${path}.`);
  }
  assertPublicText(result.buffer.toString("utf8"));
}

export function assertPublicText(contents, binaryRanges = []) {
  const pattern = new RegExp(internalMarker.source, "giu");
  let match;
  while ((match = pattern.exec(contents)) !== null) {
    if (
      !binaryRanges.some(
        ({ start, end }) =>
          match.index >= start && match.index + match[0].length <= end,
      )
    )
      throw new Error("npm tarball contains an internal reference.");
    pattern.lastIndex = match.index + 1;
  }
}
