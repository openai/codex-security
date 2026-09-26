export function shardTestFiles(
  files: readonly string[],
  count: number,
  durations?: Readonly<Record<string, number>>,
): Array<{ files: string[]; seconds: number }>;
