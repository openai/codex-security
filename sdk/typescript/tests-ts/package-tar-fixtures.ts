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
  octal(0, 12).copy(header, 136);
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

export function archive(...records: Buffer[]): Buffer {
  return Buffer.concat([...records, Buffer.alloc(blockSize * 2)]);
}
