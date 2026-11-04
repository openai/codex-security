export type TestTimings = Record<
  string,
  Partial<Record<NodeJS.Platform, number>>
>;

export function partitionTests(
  files: readonly string[],
  count: number,
  timings: TestTimings,
  platform: NodeJS.Platform,
): string[][] {
  const known = files.flatMap((file) => {
    const seconds = timings[file]?.[platform];
    return seconds === undefined ? [] : [seconds];
  });
  const fallback = known.length
    ? known.reduce((total, seconds) => total + seconds, 0) / known.length
    : 1;
  const duration = (file: string) => timings[file]?.[platform] ?? fallback;
  const shards = Array.from({ length: count }, () => ({
    files: [] as string[],
    seconds: 0,
  }));
  for (const file of [...files]
    .sort()
    .sort((left, right) => duration(right) - duration(left))) {
    const shard = shards.reduce((least, candidate) =>
      candidate.seconds < least.seconds ? candidate : least,
    );
    shard.files.push(file);
    shard.seconds += duration(file);
  }
  return shards.map((shard) => shard.files.sort());
}
