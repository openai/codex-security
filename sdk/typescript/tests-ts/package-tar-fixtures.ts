export const blockSize = 512;

export function octal(value: number, width: number, terminator = "\0"): Buffer {
  return Buffer.from(
    value.toString(8).padStart(width - terminator.length, "0") + terminator,
  );
}

function tarHeader({
  name,
  prefix = "",
  size = 0,
  mtime = 0,
  mode = 0o644,
  type = 0x30,
  sizeField = octal(size, 12, " "),
  magic = "ustar\0",
  version = "00",
  user = "",
  deviceNumbers = Buffer.alloc(16),
  reserved = Buffer.alloc(12),
}: {
  name: string;
  prefix?: string;
  size?: number;
  mtime?: number;
  mode?: number;
  type?: number;
  sizeField?: Buffer;
  magic?: string;
  version?: string;
  user?: string;
  deviceNumbers?: Buffer;
  reserved?: Buffer;
}): Buffer {
  const header = Buffer.alloc(blockSize);
  header.write(name, 0, 100, "utf8");
  octal(mode, 8).copy(header, 100);
  octal(0, 8).copy(header, 108);
  octal(0, 8).copy(header, 116);
  sizeField.copy(header, 124);
  octal(mtime, 12).copy(header, 136);
  header.fill(0x20, 148, 156);
  header[156] = type;
  header.write(magic, 257, "binary");
  header.write(version, 263, "binary");
  header.write(user, 265, 32, "utf8");
  deviceNumbers.copy(header, 329, 0, 16);
  header.write(prefix, 345, 155, "utf8");
  reserved.copy(header, 500, 0, 12);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  Buffer.from(checksum.toString(8).padStart(6, "0") + "\0 ").copy(header, 148);
  return header;
}

export function tarRecord(
  contents: Buffer,
  options: Omit<Parameters<typeof tarHeader>[0], "size">,
): Buffer {
  return Buffer.concat([
    tarHeader({ ...options, size: contents.length }),
    contents,
    Buffer.alloc(
      Math.ceil(contents.length / blockSize) * blockSize - contents.length,
    ),
  ]);
}

export function oldGnuSparseRecord(
  contents: Buffer,
  name: string,
  extents = [{ offset: 0, size: contents.length }],
  metadataMarker?: "continuation" | "boundary" | "unused",
): Buffer {
  const stored = Buffer.concat(
    extents.flatMap(({ offset, size }, index) => [
      contents.subarray(offset, offset + size),
      Buffer.alloc(index < extents.length - 1 ? (512 - (size % 512)) % 512 : 0),
    ]),
  );
  const record = tarRecord(stored, {
    name,
    type: 0x53,
    magic: "ustar ",
    version: " \0",
  });
  const header = record.subarray(0, blockSize);
  const continuations = [];
  let remaining = extents;
  let map = header;
  let start = 386;
  let count = 4;
  do {
    for (const [index, extent] of remaining.slice(0, count).entries()) {
      octal(extent.offset, 12).copy(map, start + index * 24);
      octal(extent.size, 12).copy(map, start + index * 24 + 12);
    }
    remaining = remaining.slice(count);
    map[start + count * 24] = remaining.length > 0 ? 1 : 0;
    if (remaining.length > 0) {
      map = Buffer.alloc(blockSize);
      continuations.push(map);
      start = 0;
      count = 21;
    }
  } while (remaining.length > 0);
  if (metadataMarker === "unused") {
    const used =
      extents.length <= 4 ? extents.length : ((extents.length - 5) % 21) + 1;
    map.write("public", start + (used + 1) * 24);
  }
  octal(contents.length, 12).copy(header, 483);
  if (metadataMarker === "continuation")
    continuations.at(-1)!.write("go/test", 505);
  if (metadataMarker === "boundary") header.write("go/", 509);
  header.fill(0x20, 148, 156);
  octal(
    header.reduce((sum, byte) => sum + byte, 0),
    8,
    "\0 ",
  ).copy(header, 148);
  return Buffer.concat([header, ...continuations, record.subarray(blockSize)]);
}

export function archive(...records: Buffer[]): Buffer {
  return Buffer.concat([...records, Buffer.alloc(blockSize * 2)]);
}

export function paxRecords(attributes: Record<string, string>): Buffer {
  return Buffer.concat(
    Object.entries(attributes).map(([key, value]) => {
      const record = ` ${key}=${value}\n`;
      let length = Buffer.byteLength(record) + 1;
      while (length !== Buffer.byteLength(record) + String(length).length)
        length = Buffer.byteLength(record) + String(length).length;
      return Buffer.from(`${length}${record}`);
    }),
  );
}

// Synthetic alphanumeric text whose compressed bytes happen to contain " Go/w".
export const cleanCompressedPayload = Buffer.from(
  "G/8DAGRwm7EiGn34sGFNRM5DuwB8/2zECGTx7hk1/DY6puqEJWJumAz3HfjBg7bx5FxwfFCafaN2of0Oi2uTSSE+wAYOJS4Ii53urIa5BOIkTbR5t2YJ4/UM6dWzXcEvk92TZNz/Y7hNVxjrsXKemVnN4i1pUOdQiCYQNLU7Dbh77pXyrGIWSl+X+L7DUfFR+4Rz3GF85xCbj1NuwlDfIWj42+ueic5NDX4bPXmp46fE8bTdpAUmMvt48x99pm2wlp+oKNvvcb64GT4i7F9zCJMIdfmc06UCn7Go4jQ1WI2P+e05ZbpsWoTkPXnAFULsyUtefeZ1d5nbvE2CDXV3eF7Hxc2KgtQQv8j/CIEd+9vG3REfGcJVIVMqjo1SKzOfADpWQYh3p18YFMyF6R4qOYzPB+zjBy/ZQiCaNm1LpVYdJ7XL0wXPjAVOzJU4zeSUvNFqQ0TeXFGat6ikPEii43FRFSx3aQi2HnWI3rBd1tts0LlTjIWUq8+agHu/mwmJ+jWxAF74Yvij4++fUTHxm8PvqXOK+3QpR82rAPZ+pyRgKX1Z9k9XHlVwNXzJCd5laKwKOWnAOF6vKnrqhZz4aw1VqEJ+1x/4+AM++Pw58PdlRKBjKoLl7DKgEBCGKsd5FF8XPQz9pC3MWj1UbdVa/jLl5M1iIfl9P44zgKV1TaG1LEjuS09t7e0UFSrgXI0BWvBuyNfEras635PJBiZuI8mX6s5yt5NkocDkATyMNP1BnW+wKyTzduIFbd2yV45t/t6ttd5y5FeAAKnT0Jjsmk3zbYdl12fpKKDUvs363EVzTjWEhNaoTC3ntUZKNlYzX74UMDogR28vd8vvJniJvfamegrjMcf3fviFr9caYVQH+bq/TpxK078VtU0Z5iah0E2+ttjzWXHi//ftzs9e+xArq7zohSgVrMpgsL2kjfl/zaltHiNmTgogtQI6gRiI1ICa3kimcK2a/gj0cTkCVwKywUt6xu1N2x2lPi7dk/pnx8/iSkdyphyFA4OQov+d8maitV0XwU9/NKTW048C",
  "base64",
);
