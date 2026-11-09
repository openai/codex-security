import { assertPublicText } from "./package-public-content.mjs";

const blockSize = 512;
function invalidTarEntry() {
  throw new Error("npm tarball contains an invalid tar entry.");
}

function unsupportedSparseEntry() {
  throw new Error("npm tarball contains an unsupported sparse entry.");
}

function headerText(header, start, end) {
  return header.subarray(start, end).toString("utf8").split("\0", 1)[0];
}

function octalNumber(header, start, end) {
  const field = headerText(header, start, end).trim();
  if (!/^[0-7]*$/u.test(field)) invalidTarEntry();
  return Number.parseInt(field || "0", 8);
}

function paxAttributes(contents) {
  const attributes = new Map();
  let offset = 0;
  while (offset < contents.byteLength) {
    const separator = contents.indexOf(0x20, offset);
    const lengthField = contents.subarray(offset, separator).toString("ascii");
    if (separator === -1 || !/^[0-9]+$/u.test(lengthField)) invalidTarEntry();
    const end = offset + Number(lengthField);
    const equals = contents.indexOf(0x3d, separator + 1);
    if (
      end > contents.byteLength ||
      equals <= separator + 1 ||
      equals >= end - 1 ||
      contents[end - 1] !== 0x0a
    )
      invalidTarEntry();
    const key = contents.subarray(separator + 1, equals).toString("utf8");
    if (
      key === "GNU.sparse" ||
      key.startsWith("GNU.sparse.") ||
      key === "SCHILY.realsize" ||
      key === "SUN.holesdata"
    ) {
      unsupportedSparseEntry();
    }
    attributes.set(
      key,
      contents.subarray(equals + 1, end - 1).toString("utf8"),
    );
    offset = end;
  }
  return attributes;
}

export function readTarArchive(archiveBytes) {
  const entries = [];
  const archiveFiles = new Map();
  const archiveMetadata = [];
  const npmFiles = new Map();
  let offset = 0;
  const globalAttributes = new Map();
  const nextAttributes = new Map();
  let nextName;
  let nextNpmPath;

  while (offset + blockSize <= archiveBytes.byteLength) {
    const header = archiveBytes.subarray(offset, offset + blockSize);
    if (header.every((byte) => byte === 0)) {
      archiveMetadata.push(header);
      offset += blockSize;
      continue;
    }

    const signature = header.subarray(257, 265).toString("latin1");
    const directory = header[156] === 0x35;
    // libarchive also reads the GNU sparse map, continuation flag and real
    // size from GNU member headers, even on an otherwise regular entry.
    if (
      header[156] === 0x53 ||
      (signature === "ustar  \0" &&
        (header[386] !== 0 || header[482] !== 0 || header[483] !== 0))
    ) {
      unsupportedSparseEntry();
    }
    const longName = header[156] === 0x4c;
    const extended = header[156] === 0x78 || header[156] === 0x67 || longName;
    if (
      (header[156] !== 0 && header[156] !== 0x30 && !directory && !extended) ||
      (signature !== "ustar\0" + "00" &&
        signature !== "ustar  \0" &&
        signature !== "\0".repeat(8))
    ) {
      invalidTarEntry();
    }

    const name = headerText(header, 0, 100);
    // GNU headers use this area for timestamps and sparse-file metadata.
    const prefix =
      signature === "ustar\0" + "00" ? headerText(header, 345, 500) : "";
    const attribute = (key) =>
      nextAttributes.has(key)
        ? nextAttributes.get(key) || undefined
        : globalAttributes.get(key);
    const headerPath = prefix === "" ? name : `${prefix}/${name}`;
    const path = attribute("path") ?? nextName ?? headerPath;
    if (!extended && (path === "" || path.endsWith("/") !== directory))
      invalidTarEntry();
    assertPublicText(path);

    const headerSize = octalNumber(header, 124, 136);
    const paxSize = extended ? undefined : attribute("size");
    if (paxSize !== undefined && !/^[0-9]+$/u.test(paxSize)) invalidTarEntry();
    const size = paxSize === undefined ? headerSize : Number(paxSize);
    const contentsStart = offset + blockSize;
    const contentsEnd = contentsStart + size;
    const nextOffset = contentsStart + Math.ceil(size / blockSize) * blockSize;
    if (nextOffset > archiveBytes.byteLength || (directory && size !== 0)) {
      invalidTarEntry();
    }

    if (extended) {
      const contents = archiveBytes.subarray(contentsStart, contentsEnd);
      archiveMetadata.push(archiveBytes.subarray(offset, nextOffset));
      if (longName) {
        nextName = headerText(contents, 0, contents.length);
        nextNpmPath = nextName;
      } else {
        const destination =
          header[156] === 0x67 ? globalAttributes : nextAttributes;
        for (const [key, value] of paxAttributes(contents)) {
          // npm merges local PAX paths and GNU long names in record order.
          if (destination === nextAttributes && key === "path")
            nextNpmPath = value || undefined;
          if (destination === globalAttributes && value === "")
            destination.delete(key);
          else destination.set(key, value);
        }
      }
    } else {
      if (directory)
        archiveMetadata.push(archiveBytes.subarray(offset, nextOffset));
      else {
        const contents = archiveBytes.subarray(contentsStart, contentsEnd);
        npmFiles.set(nextNpmPath ?? headerPath, contents);
        archiveFiles.set(path, contents);
        archiveMetadata.push(archiveBytes.subarray(offset, contentsStart));
        archiveMetadata.push(archiveBytes.subarray(contentsEnd, nextOffset));
      }
      entries.push({ path, size });
      nextAttributes.clear();
      nextName = undefined;
      nextNpmPath = undefined;
    }
    offset = nextOffset;
  }

  if (archiveBytes.subarray(offset).some((byte) => byte !== 0))
    invalidTarEntry();
  return {
    entries,
    files: archiveFiles,
    metadata: archiveMetadata,
    npmFiles,
  };
}
