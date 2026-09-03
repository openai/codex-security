import { describe, expect, test } from "bun:test";
import { brotliCompressSync, brotliDecompressSync } from "node:zlib";

type PackageInternalReferences = {
  assertNoInternalReferences: (
    archiveFiles: ReadonlyMap<string, Buffer>,
    maxExpandedAssetBytes: number,
  ) => void;
};

const { assertNoInternalReferences } = (await import(
  new URL("../scripts/package-internal-references.mjs", import.meta.url).href
)) as PackageInternalReferences;

const maxExpandedAssetBytes = 1024;
const internalReferenceError = "npm tarball contains an internal reference.";

describe("npm package internal reference checks", () => {
  test("ignores marker-like bytes in Brotli metadata", () => {
    // Valid Brotli metadata containing Go/1 followed by an empty final block.
    const compressed = Buffer.from("6b1100ff476f2f3103", "hex");

    expect(compressed.toString("utf8")).toMatch(
      /(?:^|[^a-z0-9_-])go\/[a-z0-9_-]+/iu,
    );
    expect(brotliDecompressSync(compressed)).toEqual(Buffer.alloc(0));
    expect(() =>
      assertNoInternalReferences(
        new Map([["package/payload.br", compressed]]),
        maxExpandedAssetBytes,
      ),
    ).not.toThrow();
  });

  test("rejects an internal reference in normal text", () => {
    expect(() =>
      assertNoInternalReferences(
        new Map([["package/README.md", Buffer.from("See go/example.")]]),
        maxExpandedAssetBytes,
      ),
    ).toThrow(internalReferenceError);
  });

  test("rejects an internal reference in an archive path", () => {
    expect(() =>
      assertNoInternalReferences(
        new Map([
          ["package/references/go/example.md", Buffer.from("Public text.")],
        ]),
        maxExpandedAssetBytes,
      ),
    ).toThrow(internalReferenceError);
  });

  test("rejects an internal reference in a Brotli payload", () => {
    const compressed = brotliCompressSync(Buffer.from("See go/example."));

    expect(() =>
      assertNoInternalReferences(
        new Map([["package/payload.br", compressed]]),
        maxExpandedAssetBytes,
      ),
    ).toThrow(internalReferenceError);
  });

  test("rejects an internal reference in a partitioned Brotli payload", () => {
    const compressed = brotliCompressSync(Buffer.from("See go/example."));
    const split = Math.floor(compressed.length / 2);

    expect(() =>
      assertNoInternalReferences(
        new Map([
          ["package/payload.br.part-000", compressed.subarray(0, split)],
          ["package/payload.br.part-001", compressed.subarray(split)],
        ]),
        maxExpandedAssetBytes,
      ),
    ).toThrow(internalReferenceError);
  });
});
