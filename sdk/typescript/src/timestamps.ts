/** Compare timestamps without dropping their sub-millisecond digits. */
export function compareTimestamps(left: string, right: string): number {
  const timestamp = Date.parse(left) - Date.parse(right);
  if (timestamp !== 0) return timestamp;
  const leftFraction = left.match(/\.\d{3}(\d*[1-9])/u)?.[1] ?? "";
  const rightFraction = right.match(/\.\d{3}(\d*[1-9])/u)?.[1] ?? "";
  return leftFraction < rightFraction
    ? -1
    : leftFraction > rightFraction
      ? 1
      : 0;
}
