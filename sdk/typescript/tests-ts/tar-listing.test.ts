import { describe, expect, test } from "bun:test";

type TarListing = {
  tarListingLines: (listing: string) => string[];
  hasOnlyRegularEntries: (listingLines: string[]) => boolean;
};

const { tarListingLines, hasOnlyRegularEntries } = (await import(
  new URL("../scripts/tar-listing.mjs", import.meta.url).href
)) as TarListing;

const directory = "drwxr-xr-x  0 owner group      0 Jan  1 00:00 package/";
const regularFile =
  "-rw-r--r--  0 owner group     26 Jan  1 00:00 package/package.json";
const launcher =
  "-rwxr-xr-x  0 owner group    128 Jan  1 00:00 package/bin/cli.mjs";
const symbolicLink =
  "lrwxrwxrwx  0 owner group      0 Jan  1 00:00 package/link -> package/package.json";

const listingWith = (lineEnding: string, ...lines: string[]) =>
  lines.map((line) => `${line}${lineEnding}`).join("");

describe("tar verbose listing parsing", () => {
  test("splits a listing that ends its lines with LF", () => {
    expect(tarListingLines(listingWith("\n", directory, regularFile))).toEqual([
      directory,
      regularFile,
    ]);
  });

  test("splits a listing that ends its lines with CRLF", () => {
    expect(
      tarListingLines(listingWith("\r\n", directory, regularFile)),
    ).toEqual([directory, regularFile]);
  });

  test("drops the trailing empty line of an unterminated listing", () => {
    expect(tarListingLines(`${regularFile}\n`)).toEqual([regularFile]);
    expect(tarListingLines(regularFile)).toEqual([regularFile]);
    expect(tarListingLines("")).toEqual([]);
  });
});

describe("tar entry types", () => {
  test("accepts directories, regular files, and executables", () => {
    expect(hasOnlyRegularEntries([directory, regularFile, launcher])).toBe(
      true,
    );
  });

  test("accepts a CRLF listing of only regular entries", () => {
    // A `tar` that emits CRLF must not be mistaken for a tarball carrying
    // links, devices, or pipes: a multiline `^` also matches between CR and
    // LF, which tests the LF as the first character of a line.
    const listing = listingWith("\r\n", directory, regularFile, launcher);

    expect(hasOnlyRegularEntries(tarListingLines(listing))).toBe(true);
  });

  test("rejects a symbolic link regardless of the line ending", () => {
    for (const lineEnding of ["\n", "\r\n"]) {
      const listing = listingWith(
        lineEnding,
        directory,
        regularFile,
        symbolicLink,
      );

      expect(hasOnlyRegularEntries(tarListingLines(listing))).toBe(false);
    }
  });

  test("rejects hard links, devices, and pipes", () => {
    const nonRegular = [
      "hrw-r--r--  0 owner group      0 Jan  1 00:00 package/hard-link",
      "crw-rw-rw-  0 owner group    1,3 Jan  1 00:00 package/device",
      "prw-r--r--  0 owner group      0 Jan  1 00:00 package/pipe",
    ];

    for (const entry of nonRegular) {
      expect(hasOnlyRegularEntries([directory, entry])).toBe(false);
    }
  });

  test("accepts an empty listing", () => {
    expect(hasOnlyRegularEntries([])).toBe(true);
  });
});
