import { brotliCompressSync, brotliDecompressSync } from "node:zlib";
import { describe, expect, test } from "bun:test";

import { assertPublicPackageContents } from "../scripts/package-public-content.mjs";

// Synthetic alphanumeric text whose compressed bytes happen to contain " Go/w".
const cleanCompressedPayload = Buffer.from(
  "G/8DAGRwm7EiGn34sGFNRM5DuwB8/2zECGTx7hk1/DY6puqEJWJumAz3HfjBg7bx5FxwfFCafaN2of0Oi2uTSSE+wAYOJS4Ii53urIa5BOIkTbR5t2YJ4/UM6dWzXcEvk92TZNz/Y7hNVxjrsXKemVnN4i1pUOdQiCYQNLU7Dbh77pXyrGIWSl+X+L7DUfFR+4Rz3GF85xCbj1NuwlDfIWj42+ueic5NDX4bPXmp46fE8bTdpAUmMvt48x99pm2wlp+oKNvvcb64GT4i7F9zCJMIdfmc06UCn7Go4jQ1WI2P+e05ZbpsWoTkPXnAFULsyUtefeZ1d5nbvE2CDXV3eF7Hxc2KgtQQv8j/CIEd+9vG3REfGcJVIVMqjo1SKzOfADpWQYh3p18YFMyF6R4qOYzPB+zjBy/ZQiCaNm1LpVYdJ7XL0wXPjAVOzJU4zeSUvNFqQ0TeXFGat6ikPEii43FRFSx3aQi2HnWI3rBd1tts0LlTjIWUq8+agHu/mwmJ+jWxAF74Yvij4++fUTHxm8PvqXOK+3QpR82rAPZ+pyRgKX1Z9k9XHlVwNXzJCd5laKwKOWnAOF6vKnrqhZz4aw1VqEJ+1x/4+AM++Pw58PdlRKBjKoLl7DKgEBCGKsd5FF8XPQz9pC3MWj1UbdVa/jLl5M1iIfl9P44zgKV1TaG1LEjuS09t7e0UFSrgXI0BWvBuyNfEras635PJBiZuI8mX6s5yt5NkocDkATyMNP1BnW+wKyTzduIFbd2yV45t/t6ttd5y5FeAAKnT0Jjsmk3zbYdl12fpKKDUvs363EVzTjWEhNaoTC3ntUZKNlYzX74UMDogR28vd8vvJniJvfamegrjMcf3fviFr9caYVQH+bq/TpxK078VtU0Z5iah0E2+ttjzWXHi//ftzs9e+xArq7zohSgVrMpgsL2kjfl/zaltHiNmTgogtQI6gRiI1ICa3kimcK2a/gj0cTkCVwKywUt6xu1N2x2lPi7dk/pnx8/iSkdyphyFA4OQov+d8maitV0XwU9/NKTW048C",
  "base64",
);

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
