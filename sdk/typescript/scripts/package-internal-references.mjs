import { brotliDecompressSync } from "node:zlib";

const internalMarker =
  /(?:internal\.api\.openai\.org|gateway\.[a-z0-9.-]*internal|\.openai\.org|openai\.firewall\.socket\.dev|socket\x2dfirewall\x2dregistry|openai\.(?:enterprise\.)?slack\.com|app\.slack\.com\/client|(?:app\.notion\.com\/p|notion\.so)\/openai|linear\.app\/openai|(?:github\.com[:/]|api\.github\.com\/repos\/|raw\.githubusercontent\.com\/)openai\/openai(?:\.git)?(?:[^a-z0-9_-]|$)|LicenseRef\x2dProprietary|\/Users\/|\/home\/dev-user|flow\.apps\.openai\.org|(?:^|[^a-z0-9_-])go\/[a-z0-9_-]+)/iu;

function brotliPayload(bytes, file, maxExpandedAssetBytes) {
  const result = brotliDecompressSync(bytes, {
    info: true,
    maxOutputLength: maxExpandedAssetBytes,
  });
  if (result.engine.bytesWritten !== bytes.length) {
    throw new Error(`npm tarball contains trailing Brotli data: ${file}.`);
  }
  return result.buffer;
}

export function assertNoInternalReference(contents) {
  if (internalMarker.test(contents.toString("utf8"))) {
    throw new Error("npm tarball contains an internal reference.");
  }
}

export function assertNoInternalReferences(
  archiveFiles,
  maxExpandedAssetBytes,
) {
  const compressedParts = new Map();

  for (const [file, contents] of archiveFiles) {
    assertNoInternalReference(Buffer.from(file));
    const match = /^(.*\.br)\.part-([0-9]+)$/iu.exec(file);
    if (match !== null) {
      const [, name, part] = match;
      const parts = compressedParts.get(name) ?? [];
      parts.push({ file, part: Number(part), contents });
      compressedParts.set(name, parts);
    } else if (/\.br$/iu.test(file)) {
      assertNoInternalReference(
        brotliPayload(contents, file, maxExpandedAssetBytes),
      );
    } else if (!/\.png$/iu.test(file)) {
      assertNoInternalReference(contents);
    }
  }

  for (const parts of compressedParts.values()) {
    parts.sort((left, right) => left.part - right.part);
    const bytes = Buffer.concat(parts.map(({ contents }) => contents));
    assertNoInternalReference(
      brotliPayload(bytes, parts[0].file, maxExpandedAssetBytes),
    );
  }
}
