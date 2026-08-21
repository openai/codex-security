const REGULAR_ENTRY_TYPES = ["d", "-"];

/**
 * Split a `tar -tv` verbose listing into entry lines.
 *
 * `tar` implementations differ in line endings: some on Windows emit CRLF. The
 * listing must be normalized before entry types are inspected, because a
 * multiline `^` also matches between CR and LF, which would test the LF as the
 * first character of a line.
 */
export function tarListingLines(listing) {
  return listing.split(/\r?\n/u).filter(Boolean);
}

/**
 * Whether every listed entry is a directory or a regular file, rather than a
 * symbolic or hard link, device, or pipe.
 */
export function hasOnlyRegularEntries(listingLines) {
  return listingLines.every((line) =>
    REGULAR_ENTRY_TYPES.includes(line[0] ?? ""),
  );
}
