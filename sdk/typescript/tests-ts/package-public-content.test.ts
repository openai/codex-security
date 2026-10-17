import { readFileSync } from "node:fs";
import { brotliCompressSync, brotliDecompressSync } from "node:zlib";
import { describe, expect, test } from "bun:test";

import { assertPublicPackageContents } from "../scripts/package-public-content.mjs";

import { cleanCompressedPayload } from "./package-tar-fixtures.js";

function compressedFiles(bytes: Buffer, split: boolean): Map<string, Buffer> {
  if (!split) return new Map([["package/runtime.mjs.br", bytes]]);
  const middle = Math.floor(bytes.length / 2);
  return new Map([
    ["package/runtime.mjs.br.part-001", bytes.subarray(middle)],
    ["package/runtime.mjs.br.part-000", bytes.subarray(0, middle)],
  ]);
}

describe("npm package public contents", () => {
  test.each([false, true])(
    "accepts clean expanded contents despite compressed marker bytes (split: %p)",
    (split) => {
      expect(cleanCompressedPayload.toString("utf8")).toContain(" Go/w");
      expect(
        brotliDecompressSync(cleanCompressedPayload).toString("utf8"),
      ).toMatch(/^[A-Za-z0-9]+$/u);
      expect(() =>
        assertPublicPackageContents(
          compressedFiles(cleanCompressedPayload, split),
        ),
      ).not.toThrow();
    },
  );

  test.each([false, true])(
    "rejects a marker in expanded contents (split: %p)",
    (split) => {
      const bytes = brotliCompressSync(
        Buffer.from("See go/synthetic-reference."),
      );
      expect(() =>
        assertPublicPackageContents(compressedFiles(bytes, split)),
      ).toThrow("npm tarball contains an internal reference.");
    },
  );

  test.each([false, true])(
    "rejects trailing bytes after a valid Brotli stream (split: %p)",
    (split) => {
      const bytes = Buffer.concat([
        cleanCompressedPayload,
        Buffer.from("extra"),
      ]);
      expect(() =>
        assertPublicPackageContents(compressedFiles(bytes, split)),
      ).toThrow("npm tarball contains trailing Brotli data");
    },
  );

  test("checks the approved PNG digest before exempting binary contents", () => {
    const approved = readFileSync(
      new URL(
        "../../../plugins/codex-security/assets/logo.png",
        import.meta.url,
      ),
    );
    expect(() =>
      assertPublicPackageContents(new Map([["package/logo.png", approved]])),
    ).not.toThrow();
    const stored = Buffer.from(approved);
    expect(stored.subarray(171, 178)).toEqual(Buffer.alloc(7));
    stored.set(Buffer.from("\0go/x\0\0"), 171);
    expect(() =>
      assertPublicPackageContents(new Map([["package/logo.png", stored]])),
    ).toThrow("npm tarball contains an unexpected PNG asset");
  });

  test("keeps the expanded Brotli size bound", () => {
    const bytes = brotliCompressSync(Buffer.alloc(32 * 1024 * 1024 + 1));
    expect(() =>
      assertPublicPackageContents(compressedFiles(bytes, false)),
    ).toThrow();
  });

  test("checks tar metadata", () => {
    expect(() =>
      assertPublicPackageContents(new Map(), Buffer.from("go/synthetic-owner")),
    ).toThrow("npm tarball contains an internal reference.");
  });

  test("checks plaintext and public paths", () => {
    expect(() =>
      assertPublicPackageContents(
        new Map([["package/README.md", Buffer.from("Public documentation.")]]),
      ),
    ).not.toThrow();
    expect(() =>
      assertPublicPackageContents(
        new Map([
          ["package/README.md", Buffer.from("See go/synthetic-reference.")],
        ]),
      ),
    ).toThrow("npm tarball contains an internal reference.");
    expect(() =>
      assertPublicPackageContents(
        new Map([
          ["package/go/synthetic-reference.br", cleanCompressedPayload],
        ]),
      ),
    ).toThrow("npm tarball contains an internal reference.");
  });
});
