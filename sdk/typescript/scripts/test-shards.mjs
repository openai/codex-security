/** Place the longest measured files first, without omitting new test files. */
export function shardTestFiles(files, count, durations = {}) {
  if (!Number.isSafeInteger(count) || count < 1) {
    throw new Error("The test shard count must be a positive integer.");
  }
  const shards = Array.from({ length: count }, () => ({
    files: [],
    seconds: 0,
  }));
  const duration = (file) => durations[file] ?? 1;
  const ordered = [...files].sort(
    (left, right) =>
      duration(right) - duration(left) ||
      (left < right ? -1 : left > right ? 1 : 0),
  );
  for (const file of ordered) {
    const shard = shards.reduce((shortest, candidate) =>
      candidate.seconds < shortest.seconds ? candidate : shortest,
    );
    shard.files.push(file);
    shard.seconds += duration(file);
  }
  return shards;
}
