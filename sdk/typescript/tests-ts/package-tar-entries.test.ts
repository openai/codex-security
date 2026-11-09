import { describe, expect, test } from "bun:test";
import {
  archive,
  blockSize,
  octal,
  paxRecords,
  tarRecord,
} from "./package-tar-fixtures.js";

type PlainTarEntry = {
  path: string;
  size: number;
};

type PackageTarEntries = {
  readTarArchive: (archiveBytes: Buffer) => {
    entries: PlainTarEntry[];
    files: Map<string, Buffer>;
    metadata: Buffer[];
  };
};

const { readTarArchive } = (await import(
  new URL("../scripts/package-tar-entries.mjs", import.meta.url).href
)) as PackageTarEntries;
const { assertPublicPackageContents } = (await import(
  new URL("../scripts/package-public-content.mjs", import.meta.url).href
)) as {
  assertPublicPackageContents: (
    files: Map<string, Buffer>,
    metadata: Buffer,
  ) => void;
};

function plainTarEntries(bytes: Buffer): PlainTarEntry[] {
  const archive = readTarArchive(bytes);
  assertPublicPackageContents(archive.files, Buffer.concat(archive.metadata));
  return archive.entries;
}

const invalidTarEntryError = "npm tarball contains an invalid tar entry.";
const sparseEntryError = "npm tarball contains an unsupported sparse entry.";
const internalReferenceError = "npm tarball contains an internal reference.";

describe("plain npm tar entries", () => {
  test.each([" ", " \0", "\0"])(
    "accepts package size fields ending in %j",
    (terminator) => {
      expect(
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("readme"), {
              name: "package/README.md",
              sizeField: octal(6, 12, terminator),
            }),
          ),
        ),
      ).toEqual([{ path: "package/README.md", size: 6 }]);
    },
  );

  test.each([0, 0x30])(
    "accepts regular typeflag %i and prefix paths",
    (type) => {
      // POSIX prefix bytes can occupy all three old GNU sparse field offsets.
      const prefix = `package/${"nested/".repeat(20)}deep`;
      const longPath = `${prefix}/README.md`;
      expect(longPath.length).toBeGreaterThan(100);

      const bytes = archive(
        tarRecord(Buffer.from("license"), { name: "package/LICENSE", type }),
        tarRecord(Buffer.from("readme"), { name: "README.md", prefix, type }),
      );

      expect(plainTarEntries(bytes)).toEqual([
        { path: "package/LICENSE", size: 7 },
        { path: longPath, size: 6 },
      ]);
    },
  );

  test("rejects unsupported entry types and malformed extended headers", () => {
    for (const type of [0x31, 0x32, 0x33, 0x34, 0x36, 0x44, 0x4b, 0x67, 0x78]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              type,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test("uses GNU long names for one member and scans their complete payload", () => {
    const path = `package/${"nested/".repeat(16)}README.md`;
    const records = (tail: string) =>
      archive(
        tarRecord(Buffer.from(`${path}\0${tail}`), {
          name: "././@LongLink",
          type: 0x4c,
        }),
        tarRecord(Buffer.from("readme"), { name: "placeholder" }),
        tarRecord(Buffer.from("license"), { name: "package/LICENSE" }),
      );
    expect(plainTarEntries(records(""))).toEqual([
      { path, size: 6 },
      { path: "package/LICENSE", size: 7 },
    ]);
    expect(() => plainTarEntries(records("go/example"))).toThrow(
      internalReferenceError,
    );
  });

  test.each([0x78, 0x67])("accepts POSIX pax metadata typeflag %i", (type) => {
    const attributes = paxRecords({
      ctime: "0.123456789",
      "SCHILY.xattr.user.note": "sparse",
    });
    expect(
      plainTarEntries(
        archive(
          tarRecord(attributes, { name: "package/PaxHeaders/README.md", type }),
          tarRecord(Buffer.from("readme"), { name: "package/README.md" }),
        ),
      ),
    ).toEqual([{ path: "package/README.md", size: 6 }]);
  });

  test("uses local pax paths and sizes and clears them after their member", () => {
    const path = `package/${"nested/".repeat(16)}README.md`;
    expect(
      plainTarEntries(
        archive(
          tarRecord(paxRecords({ path, size: "6" }), {
            name: "package/PaxHeaders/README.md",
            type: 0x78,
          }),
          tarRecord(Buffer.from("readme"), {
            name: "placeholder",
            sizeField: octal(0, 12),
          }),
          tarRecord(Buffer.from("license"), { name: "package/LICENSE" }),
        ),
      ),
    ).toEqual([
      { path, size: 6 },
      { path: "package/LICENSE", size: 7 },
    ]);
  });

  test("retains global pax attributes and honors local overrides", () => {
    expect(
      plainTarEntries(
        archive(
          tarRecord(paxRecords({ path: "package/README.md" }), {
            name: "GlobalHead",
            type: 0x67,
          }),
          tarRecord(Buffer.from("readme"), { name: "placeholder" }),
          tarRecord(paxRecords({ path: "package/LICENSE" }), {
            name: "package/PaxHeaders/LICENSE",
            type: 0x78,
          }),
          tarRecord(Buffer.from("license"), { name: "placeholder" }),
        ),
      ),
    ).toEqual([
      { path: "package/README.md", size: 6 },
      { path: "package/LICENSE", size: 7 },
    ]);
  });

  test("scans the complete pax metadata payload", () => {
    expect(() =>
      plainTarEntries(
        archive(
          tarRecord(paxRecords({ comment: "go/example" }), {
            name: "package/PaxHeaders/README.md",
            type: 0x78,
          }),
          tarRecord(Buffer.from("readme"), { name: "package/README.md" }),
        ),
      ),
    ).toThrow(internalReferenceError);
  });

  test("rejects the old GNU sparse typeflag", () => {
    const member = tarRecord(Buffer.from("data"), {
      name: "package/README.md",
      type: 0x53,
      magic: "ustar ",
      version: " \0",
    });
    expect(() => readTarArchive(archive(member))).toThrow(sparseEntryError);
  });

  test.each([
    [386, "00000000000"],
    [482, "\x01"],
    [483, "00000000004"],
  ] as const)(
    "rejects a regular GNU member with a sparse field at byte %i",
    (offset, field) => {
      const member = tarRecord(Buffer.from("data"), {
        name: "package/README.md",
        type: 0x30,
        magic: "ustar ",
        version: " \0",
        prefix: "\0".repeat(offset - 345) + field,
      });
      expect(() => readTarArchive(archive(member))).toThrow(sparseEntryError);
    },
  );

  test.each([0x78, 0x67])(
    "rejects sparse PAX attributes of type %i",
    (type) => {
      for (const [key, value] of [
        ["GNU.sparse", ""],
        ["GNU.sparse.map", "0,4"],
        ["GNU.sparse.major", "1\0"],
        ["GNU.sparse.name", "package/README.md"],
        ["SCHILY.realsize", "1024"],
        ["SUN.holesdata", " 512 1024"],
      ] as const) {
        const header = tarRecord(paxRecords({ [key]: value }), {
          name: "PaxHeaders/readme",
          type,
        });
        expect(() =>
          readTarArchive(
            archive(
              header,
              tarRecord(Buffer.from("data"), { name: "package/README.md" }),
            ),
          ),
        ).toThrow(sparseEntryError);
      }
    },
  );

  test("rejects trailing sparse metadata even when the attribute is reset", () => {
    const attributes = Buffer.concat([
      paxRecords({ "GNU.sparse.map": "0,4" }),
      paxRecords({ "GNU.sparse.map": "" }),
    ]);
    expect(() =>
      readTarArchive(
        archive(
          tarRecord(Buffer.from("data"), { name: "package/README.md" }),
          tarRecord(attributes, { name: "PaxHeaders/readme", type: 0x78 }),
        ),
      ),
    ).toThrow(sparseEntryError);
  });

  test("scans regular file contents under a GNU header", () => {
    const member = tarRecord(Buffer.from("go/example"), {
      name: "package/README.md",
      magic: "ustar ",
      version: " \0",
    });
    expect(() => plainTarEntries(archive(member))).toThrow(
      internalReferenceError,
    );
  });

  test("checks markers across concatenated archive metadata", () => {
    const record = tarRecord(Buffer.from("Public contents."), {
      name: "package/README.md",
    });
    record.write("go/", record.length - 3);
    expect(() =>
      plainTarEntries(
        archive(
          record,
          tarRecord(paxRecords({ uid: "0" }), { name: "example", type: 0x78 }),
        ),
      ),
    ).toThrow(internalReferenceError);
  });

  test("accepts an empty size field for an empty file", () => {
    expect(
      plainTarEntries(
        archive(
          tarRecord(Buffer.alloc(0), {
            name: "package/README.md",
            sizeField: Buffer.alloc(12),
          }),
        ),
      ),
    ).toEqual([{ path: "package/README.md", size: 0 }]);
  });

  test("rejects invalid or binary size encodings", () => {
    const base256 = Buffer.alloc(12);
    base256[0] = 0x80;
    base256[11] = 1;
    for (const sizeField of [base256, Buffer.from("00000000008\0")]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              sizeField,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test.each([0, 0x30])("accepts basic V7 regular typeflag %i", (type) => {
    expect(
      plainTarEntries(
        archive(
          tarRecord(Buffer.from("readme"), {
            name: "package/README.md",
            type,
            magic: "\0".repeat(6),
            version: "\0\0",
          }),
        ),
      ),
    ).toEqual([{ path: "package/README.md", size: 6 }]);
  });

  test("rejects alternate ustar signatures", () => {
    for (const options of [
      { magic: "ustar " },
      { magic: "ustar\0", version: " \0" },
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              ...options,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test("scans complete header text fields", () => {
    expect(() =>
      plainTarEntries(
        archive(
          tarRecord(Buffer.from("clean"), {
            name: "package/README.md",
            user: "public\0go/example",
          }),
        ),
      ),
    ).toThrow(internalReferenceError);
  });

  test("scans complete raw headers", () => {
    for (const options of [
      {
        deviceNumbers: Buffer.concat([
          Buffer.from("go/example"),
          Buffer.alloc(6),
        ]),
      },
      { reserved: Buffer.from("go/example") },
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("clean"), {
              name: "package/README.md",
              ...options,
            }),
          ),
        ),
      ).toThrow(internalReferenceError);
    }
  });

  test("accepts explicit empty directory members", () => {
    expect(
      plainTarEntries(
        archive(tarRecord(Buffer.alloc(0), { name: "package/", type: 0x35 })),
      ),
    ).toEqual([{ path: "package/", size: 0 }]);
    expect(() =>
      plainTarEntries(
        archive(tarRecord(Buffer.from("x"), { name: "package/", type: 0x35 })),
      ),
    ).toThrow(invalidTarEntryError);
  });

  test("accepts GNU headers without treating timestamps as a path prefix", () => {
    expect(
      plainTarEntries(
        archive(
          tarRecord(Buffer.from("readme"), {
            name: "package/README.md",
            magic: "ustar ",
            version: " \0",
            prefix: "00000000000",
          }),
        ),
      ),
    ).toEqual([{ path: "package/README.md", size: 6 }]);
  });

  test("accepts padding, optional end markers, and zero blocks between files", () => {
    const record = tarRecord(Buffer.from("x"), { name: "package/README.md" });
    record[record.length - 1] = 1;
    const secondRecord = tarRecord(Buffer.from("y"), {
      name: "package/LICENSE",
    });

    expect(plainTarEntries(record)).toEqual([
      { path: "package/README.md", size: 1 },
    ]);
    for (const trailingBytes of [1, 511]) {
      expect(
        plainTarEntries(
          Buffer.concat([archive(record), Buffer.alloc(trailingBytes)]),
        ),
      ).toEqual([{ path: "package/README.md", size: 1 }]);
    }
    for (const zeroBlocks of [1, 2]) {
      expect(
        plainTarEntries(
          Buffer.concat([
            record,
            Buffer.alloc(blockSize * zeroBlocks),
            secondRecord,
          ]),
        ),
      ).toEqual([
        { path: "package/README.md", size: 1 },
        { path: "package/LICENSE", size: 1 },
      ]);
    }
  });

  test("still scans padding and rejects partial blocks or truncated contents", () => {
    const record = tarRecord(Buffer.from("x"), { name: "package/README.md" });
    const paddingMarker = Buffer.from(record);
    paddingMarker.write("go/example", blockSize + 1);
    expect(() => plainTarEntries(paddingMarker)).toThrow(
      internalReferenceError,
    );
    for (const bytes of [
      Buffer.concat([archive(record), Buffer.from([1])]),
      record.subarray(0, blockSize),
    ]) {
      expect(() => plainTarEntries(bytes)).toThrow(invalidTarEntryError);
    }
  });
});
