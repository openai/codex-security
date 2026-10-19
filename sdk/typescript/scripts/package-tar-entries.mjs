import { assertPublicText } from "./package-public-content.mjs";

const blockSize = 512;
function invalidTarEntry() {
  throw new Error("npm tarball contains an invalid tar entry.");
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
    attributes.set(
      contents.subarray(separator + 1, equals).toString("utf8"),
      contents.subarray(equals + 1, end - 1).toString("utf8"),
    );
    offset = end;
  }
  return attributes;
}

function sparseMap(contents, paxMap) {
  if (paxMap) {
    const values = paxMap.split(",").map(Number);
    const extents = [];
    for (let index = 0; index < values.length; index += 2)
      extents.push({ offset: values[index], size: values[index + 1] });
    return { contents, extents, dataOffset: 0 };
  }
  let offset = 0;
  function number() {
    while (offset < contents.length) {
      const end = contents.indexOf(0x0a, offset);
      if (end === -1) invalidTarEntry();
      const line = contents.subarray(offset, end).toString("ascii");
      offset = end + 1;
      if (line.startsWith("#")) continue;
      if (!/^[0-9]*$/u.test(line)) invalidTarEntry();
      return Number(line);
    }
    invalidTarEntry();
  }
  const count = number();
  const extents = [];
  for (let index = 0; index < count; index++) {
    extents.push({ offset: number(), size: number() });
  }
  const dataOffset = Math.ceil(offset / blockSize) * blockSize;
  if (dataOffset > contents.length) invalidTarEntry();
  return { contents, extents, dataOffset };
}

export function assertStoredSparseContents(archive, extractedFiles) {
  const sparseMetadata = new Map();
  for (const [path, { contents, extents, dataOffset }] of archive.sparseFiles) {
    const extracted = extractedFiles.get(path);
    let metadata;
    // GNU tar pads stored extents; libarchive also accepts packed extents.
    for (const padded of [false, true]) {
      let offset = dataOffset;
      const parts = [contents.subarray(0, dataOffset)];
      const matches = extents.every((extent, index) => {
        const end = offset + extent.size;
        if (
          !contents
            .subarray(offset, end)
            .equals(
              extracted.subarray(extent.offset, extent.offset + extent.size),
            )
        )
          return false;
        const next =
          padded && index < extents.length - 1
            ? Math.ceil(end / blockSize) * blockSize
            : end;
        parts.push(
          { binary: contents.subarray(offset, end) },
          contents.subarray(end, next),
        );
        offset = next;
        return true;
      });
      if (matches) {
        parts.push(contents.subarray(offset));
        metadata = parts;
        break;
      }
    }
    if (metadata === undefined) invalidTarEntry();
    sparseMetadata.set(path, metadata);
  }
  const parts = archive.metadata.flatMap((part) =>
    typeof part === "string" ? sparseMetadata.get(part) : part,
  );
  const binaryRanges = [];
  let text = "";
  for (const part of parts) {
    const binary = !Buffer.isBuffer(part);
    const decoded = (binary ? part.binary : part).toString("utf8");
    if (binary) {
      const previous = binaryRanges.at(-1);
      if (previous?.end === text.length) previous.end += decoded.length;
      else
        binaryRanges.push({
          start: text.length,
          end: text.length + decoded.length,
        });
    }
    text += decoded;
  }
  assertPublicText(text, binaryRanges);
}

export function readTarArchive(archiveBytes) {
  const entries = [];
  const archiveFiles = new Map();
  const archiveMetadata = [];
  const sparseFiles = new Map();
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
    const oldSparse = header[156] === 0x53;
    const longName = header[156] === 0x4c;
    const extended = header[156] === 0x78 || header[156] === 0x67 || longName;
    if (
      (header[156] !== 0 &&
        header[156] !== 0x30 &&
        !directory &&
        !extended &&
        !oldSparse) ||
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
    const path =
      attribute("GNU.sparse.name") ??
      attribute("path") ??
      nextName ??
      headerPath;
    if (!extended && (path === "" || path.endsWith("/") !== directory))
      invalidTarEntry();
    assertPublicText(path);

    const headerSize = octalNumber(header, 124, 136);
    const paxSize = extended ? undefined : attribute("size");
    if (paxSize !== undefined && !/^[0-9]+$/u.test(paxSize)) invalidTarEntry();
    const size = paxSize === undefined ? headerSize : Number(paxSize);
    let contentsStart = offset + blockSize;
    const oldSparseExtents = [];
    if (oldSparse) {
      let map = header;
      let start = 386;
      let count = 4;
      for (;;) {
        let index = 0;
        for (; index < count; index++) {
          const field = start + index * 24;
          if (map[field + 12] === 0) break;
          const offset = octalNumber(map, field, field + 12);
          const size = octalNumber(map, field + 12, field + 24);
          if (offset !== 0 || size !== 0)
            oldSparseExtents.push({ offset, size });
        }
        if (index < count || map[start + count * 24] === 0) break;
        map = archiveBytes.subarray(contentsStart, contentsStart + blockSize);
        if (map.length !== blockSize) invalidTarEntry();
        contentsStart += blockSize;
        start = 0;
        count = 21;
      }
    }
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
        // npm ignores old-GNU sparse entries and GNU sparse name overrides.
        const npmPath = oldSparse ? undefined : (nextNpmPath ?? headerPath);
        if (npmPath !== undefined) npmFiles.set(npmPath, contents);
        archiveMetadata.push(archiveBytes.subarray(offset, contentsStart));
        const paxSparseMap = nextAttributes.get("GNU.sparse.map");
        if (
          (oldSparse ||
            paxSparseMap ||
            Number.parseInt(nextAttributes.get("GNU.sparse.major"), 10) ===
              1) &&
          /\.(?:png|br(?:\.part-[0-9]+)?)$/iu.test(path)
        ) {
          sparseFiles.set(
            path,
            oldSparse
              ? { contents, extents: oldSparseExtents, dataOffset: 0 }
              : sparseMap(contents, paxSparseMap),
          );
          // Retain sparse framing in order with the surrounding headers and padding.
          archiveMetadata.push(path);
        } else {
          archiveFiles.set(path, contents);
          if (oldSparse) archiveMetadata.push(contents);
        }
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
  const deferredStreams = new Set(
    [...sparseFiles.keys()].map((path) => path.replace(/\.part-[0-9]+$/iu, "")),
  );
  for (const path of archiveFiles.keys()) {
    if (deferredStreams.has(path.replace(/\.part-[0-9]+$/iu, ""))) {
      archiveFiles.delete(path);
    }
  }
  return {
    entries,
    files: archiveFiles,
    metadata: archiveMetadata,
    sparseFiles,
    npmFiles,
  };
}
