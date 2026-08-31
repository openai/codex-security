import { assertNoInternalReference } from "./package-internal-references.mjs";

const blockSize = 512;
const invalidTarEntryError = "npm tarball contains an invalid tar entry.";
function invalidTarEntry() {
  throw new Error(invalidTarEntryError);
}

function headerText(header, start, end) {
  const field = header.subarray(start, end);
  return field.toString("utf8").split("\0", 1)[0];
}

function canonicalSize(header) {
  const field = header.subarray(124, 136).toString("latin1");
  // pnpm and npm use different space/NUL terminators for their octal sizes.
  if (!/^(?:[0-7]{11} |[0-7]{10} \0)$/u.test(field)) {
    invalidTarEntry();
  }
  return Number.parseInt(field, 8);
}

export function plainTarEntries(archiveBytes) {
  if (archiveBytes.byteLength % blockSize !== 0) invalidTarEntry();
  const entries = [];
  let offset = 0;

  while (offset + blockSize <= archiveBytes.byteLength) {
    const header = archiveBytes.subarray(offset, offset + blockSize);
    if (header.every((byte) => byte === 0)) {
      const secondBlock = archiveBytes.subarray(
        offset + blockSize,
        offset + blockSize * 2,
      );
      if (
        secondBlock.byteLength !== blockSize ||
        secondBlock.some((byte) => byte !== 0) ||
        archiveBytes.subarray(offset + blockSize * 2).some((byte) => byte !== 0)
      ) {
        invalidTarEntry();
      }
      return entries;
    }

    assertNoInternalReference(header);
    if (
      (header[156] !== 0 && header[156] !== 0x30) ||
      !header.subarray(257, 263).equals(Buffer.from("ustar\0")) ||
      !header.subarray(263, 265).equals(Buffer.from("00"))
    ) {
      invalidTarEntry();
    }

    const name = headerText(header, 0, 100);
    const prefix = headerText(header, 345, 500);
    const path = prefix === "" ? name : `${prefix}/${name}`;
    if (name === "" || path.endsWith("/")) {
      invalidTarEntry();
    }
    assertNoInternalReference(Buffer.from(path));

    const size = canonicalSize(header);
    const contentsEnd = offset + blockSize + size;
    const nextOffset =
      offset + blockSize + Math.ceil(size / blockSize) * blockSize;
    if (
      nextOffset > archiveBytes.byteLength ||
      archiveBytes.subarray(contentsEnd, nextOffset).some((byte) => byte !== 0)
    ) {
      invalidTarEntry();
    }

    entries.push({ path, size });
    offset = nextOffset;
  }

  invalidTarEntry();
}
