export function regularTarListingLines(listing) {
  const lines = listing.split(/\r?\n/u).filter(Boolean);
  if (lines.some((line) => !line.startsWith("d") && !line.startsWith("-"))) {
    throw new Error(
      "npm tarball contains a non-regular entry (symbolic or hard link, device, or pipe).",
    );
  }
  return lines;
}
