import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import {
  archive,
  blockSize,
  cleanCompressedPayload,
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
    metadata: (Buffer | string)[];
  };
  assertStoredSparseContents: (
    archive: ReturnType<PackageTarEntries["readTarArchive"]>,
    files: Map<string, Buffer>,
  ) => void;
};

const { readTarArchive, assertStoredSparseContents } = (await import(
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
  assertPublicPackageContents(
    archive.files,
    Buffer.concat(
      archive.metadata.filter((part): part is Buffer => Buffer.isBuffer(part)),
    ),
  );
  return archive.entries;
}

const invalidTarEntryError = "npm tarball contains an invalid tar entry.";
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
      const prefix = `package/${"nested/".repeat(13)}deep`;
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
    const attributes = paxRecords({ ctime: "0.123456789" });
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

  test.each([false, true])(
    "scans discarded sparse-map padding, marker=%j",
    (marker) => {
      const map = Buffer.alloc(blockSize);
      map.write("1\n512\n512\n");
      if (marker) map.write("go/example", 32);
      const bytes = archive(
        tarRecord(
          paxRecords({
            "GNU.sparse.major": "1",
            "GNU.sparse.minor": "0",
            "GNU.sparse.name": "package/README.md",
            "GNU.sparse.realsize": "1024",
          }),
          { name: "package/PaxHeaders/README.md", type: 0x78 },
        ),
        tarRecord(Buffer.concat([map, Buffer.alloc(blockSize)]), {
          name: "package/README.md",
        }),
      );
      if (marker)
        expect(() => plainTarEntries(bytes)).toThrow(internalReferenceError);
      else
        expect(plainTarEntries(bytes)).toEqual([
          { path: "package/README.md", size: 1024 },
        ]);
    },
  );

  for (const format of [
    "gnu-01",
    "gnu-nul",
    "bsd-comments",
    "bsd-solaris",
  ] as const) {
    test.each([false, true])(
      `scans all stored sparse bytes for ${format}, marker=%j`,
      (marker) => {
        let attributes: Record<string, string>;
        let contents: Buffer;
        if (format === "gnu-01") {
          attributes = {
            "GNU.sparse.size": "1024",
            "GNU.sparse.numblocks": "1",
            "GNU.sparse.map": "512,512",
          };
          contents = Buffer.alloc(1024);
          if (marker) contents.write("go/example", 512);
        } else if (format === "bsd-solaris") {
          attributes = { "SUN.holesdata": " 512 1024" };
          contents = Buffer.alloc(1024);
          if (marker) contents.write("go/example", 0);
        } else {
          attributes = {
            "GNU.sparse.major": format === "gnu-nul" ? "1\0" : "1",
            "GNU.sparse.minor": "0",
            "GNU.sparse.name": "package/README.md",
            "GNU.sparse.realsize": format === "bsd-comments" ? "1536" : "1024",
          };
          contents = Buffer.alloc(format === "bsd-comments" ? 1536 : 1024);
          if (format === "bsd-comments") {
            const comments = `${`# ${"x".repeat(60)}\n`.repeat(9)}# ${marker ? "go/example" : "public note"}\n1\n1024\n512\n`;
            contents.write(comments);
          } else {
            contents.write("1\n512\n512\n");
            if (marker) contents.write("go/example", 32);
          }
        }
        const bytes = archive(
          tarRecord(paxRecords(attributes), {
            name: "package/PaxHeaders/README.md",
            type: 0x78,
          }),
          tarRecord(contents, { name: "package/README.md" }),
        );
        if (marker)
          expect(() => plainTarEntries(bytes)).toThrow(internalReferenceError);
        else
          expect(plainTarEntries(bytes)).toEqual([
            { path: "package/README.md", size: contents.length },
          ]);
      },
    );
  }

  test("checks stored old GNU sparse bodies", () => {
    const contents = Buffer.alloc(1024);
    contents.write("go/example");
    const record = tarRecord(contents, {
      name: "package/README.md",
      magic: "ustar ",
      version: " \0",
    });
    for (const offset of [386, 410]) {
      octal(0, 12).copy(record, offset);
      octal(512, 12).copy(record, offset + 12);
    }
    octal(1024, 12).copy(record, 483);
    expect(() => plainTarEntries(archive(record))).toThrow(
      internalReferenceError,
    );
  });

  test("checks stored bytes after an empty repeated sparse attribute", () => {
    const contents = Buffer.alloc(1024);
    contents.write("go/example", 512);
    const attributes = Buffer.concat([
      paxRecords({ "GNU.sparse.map": "512,512" }),
      paxRecords({ "GNU.sparse.map": "" }),
    ]);
    expect(() =>
      plainTarEntries(
        archive(
          tarRecord(attributes, { name: "PaxHeaders/readme", type: 0x78 }),
          tarRecord(contents, { name: "package/README.md" }),
        ),
      ),
    ).toThrow(internalReferenceError);
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

  test.each([false, true])(
    "keeps public Brotli content semantics across retained sparse extents, split=%j",
    (split) => {
      const path = "package/runtime.mjs.br";
      const size = cleanCompressedPayload.length;
      const middle = cleanCompressedPayload.indexOf("Go/w") + 2;
      expect(middle).toBeGreaterThan(2);
      const bytes = archive(
        tarRecord(
          paxRecords({
            "GNU.sparse.size": String(size),
            "GNU.sparse.numblocks": split ? "2" : "1",
            "GNU.sparse.map": split
              ? `0,${middle},${middle},${size - middle}`
              : `0,${size}`,
          }),
          { name: "PaxHeaders/runtime", type: 0x78 },
        ),
        tarRecord(cleanCompressedPayload, { name: path }),
      );
      expect(plainTarEntries(bytes)).toEqual([{ path, size }]);
      expect(() =>
        assertStoredSparseContents(
          readTarArchive(bytes),
          new Map([[path, cleanCompressedPayload]]),
        ),
      ).not.toThrow();
    },
  );

  test("keeps retained extents between separate sparse metadata segments", () => {
    const path = "package/logo.png";
    const logo = readFileSync(
      new URL(
        "../../../plugins/codex-security/assets/logo.png",
        import.meta.url,
      ),
    );
    const firstPadding = Buffer.alloc(512 - 250);
    firstPadding.write(".openai.", firstPadding.length - 8);
    const secondPadding = Buffer.alloc(512 - 250);
    secondPadding.write("org");
    const bytes = archive(
      tarRecord(
        paxRecords({
          "GNU.sparse.size": String(logo.length),
          "GNU.sparse.numblocks": "3",
          "GNU.sparse.map": `0,250,250,250,500,${logo.length - 500}`,
        }),
        { name: "PaxHeaders/logo", type: 0x78 },
      ),
      tarRecord(
        Buffer.concat([
          logo.subarray(0, 250),
          firstPadding,
          logo.subarray(250, 500),
          secondPadding,
          logo.subarray(500),
        ]),
        { name: path },
      ),
    );
    expect(() =>
      assertStoredSparseContents(
        readTarArchive(bytes),
        new Map([[path, logo]]),
      ),
    ).not.toThrow();
  });

  test("checks markers crossing discarded padding and retained sparse bytes", () => {
    const path = "package/logo.png";
    const logo = readFileSync(
      new URL(
        "../../../plugins/codex-security/assets/logo.png",
        import.meta.url,
      ),
    );
    expect(logo.subarray(387, 390).toString()).toBe("org");
    const padding = Buffer.alloc(512 - 387);
    padding.write(".openai.", padding.length - 8);
    const bytes = archive(
      tarRecord(
        paxRecords({
          "GNU.sparse.size": String(logo.length),
          "GNU.sparse.numblocks": "2",
          "GNU.sparse.map": `0,387,387,${logo.length - 387}`,
        }),
        { name: "PaxHeaders/logo", type: 0x78 },
      ),
      tarRecord(
        Buffer.concat([logo.subarray(0, 387), padding, logo.subarray(387)]),
        { name: path },
      ),
    );
    expect(() =>
      assertStoredSparseContents(
        readTarArchive(bytes),
        new Map([[path, logo]]),
      ),
    ).toThrow(internalReferenceError);
  });

  test("uses the native GNU sparse name while retaining stored content", () => {
    const path = "package/README.md";
    const stored = Buffer.alloc(1024);
    stored.write("1\n512\n512\n");
    stored.fill(0x78, 512);
    expect(
      plainTarEntries(
        archive(
          tarRecord(
            paxRecords({
              "GNU.sparse.major": "1",
              "GNU.sparse.minor": "0",
              "GNU.sparse.name": path,
              "GNU.sparse.realsize": "1024",
            }),
            { name: "PaxHeaders/readme", type: 0x78 },
          ),
          tarRecord(stored, { name: "package/GNUSparseFile.1/readme" }),
        ),
      ),
    ).toEqual([{ path, size: stored.byteLength }]);
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
