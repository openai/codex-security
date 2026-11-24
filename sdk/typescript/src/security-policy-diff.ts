import { setImmediate } from "node:timers/promises";

type Range = [aStart: number, aEnd: number, bStart: number, bEnd: number];
type Work<T> = Generator<void, T>;

function* lines(text: string): Work<string[]> {
  const result: string[] = [];
  let start = 0;
  for (let end = 0; end < text.length; end++) {
    if (text.charCodeAt(end) === 10) {
      result.push(text.slice(start, end + 1));
      start = end + 1;
    }
    yield;
  }
  if (start < text.length) result.push(text.slice(start));
  return result;
}

// Match Python's SequenceMatcher(None, a, b), including its default autojunk
// heuristic. A different longest-common-subsequence algorithm changes the diff.
function* changedRanges(a: string[], b: string[]): Work<Range[]> {
  const positions = new Map<string, number[]>();
  for (let j = 0; j < b.length; j++) {
    const line = b[j]!;
    const indices = positions.get(line);
    if (indices) indices.push(j);
    else positions.set(line, [j]);
    yield;
  }
  if (b.length >= 200) {
    const threshold = Math.floor(b.length / 100) + 1;
    for (const [line, indices] of positions) {
      if (indices.length > threshold) positions.delete(line);
      yield;
    }
  }

  const pending: Range[] = [[0, a.length, 0, b.length]];
  const changes: Range[] = [];
  while (pending.length) {
    const range = pending.pop()!;
    const [alo, ahi, blo, bhi] = range;
    if (alo === ahi || blo === bhi) {
      if (alo < ahi || blo < bhi) changes.push(range);
      yield;
      continue;
    }
    let bestA = alo;
    let bestB = blo;
    let size = 0;
    let lengths = new Map<number, number>();
    for (let i = alo; i < ahi; i++) {
      const next = new Map<number, number>();
      for (const j of positions.get(a[i]!) ?? []) {
        yield;
        if (j < blo) continue;
        if (j >= bhi) break;
        const length = (lengths.get(j - 1) ?? 0) + 1;
        next.set(j, length);
        if (length > size) {
          bestA = i - length + 1;
          bestB = j - length + 1;
          size = length;
        }
      }
      lengths = next;
      yield;
    }
    // Popular lines may extend a match, even though they cannot anchor one.
    while (bestA > alo && bestB > blo && a[bestA - 1] === b[bestB - 1]) {
      bestA--;
      bestB--;
      size++;
      yield;
    }
    while (
      bestA + size < ahi &&
      bestB + size < bhi &&
      a[bestA + size] === b[bestB + size]
    ) {
      size++;
      yield;
    }
    if (size) {
      // Visit the unmatched ranges left to right, including insertions and deletions.
      if (bestA + size < ahi || bestB + size < bhi) {
        pending.push([bestA + size, ahi, bestB + size, bhi]);
      }
      if (alo < bestA || blo < bestB) {
        pending.push([alo, bestA, blo, bestB]);
      }
    } else {
      changes.push(range);
    }
    yield;
  }
  return changes;
}

function formatRange(start: number, end: number): string {
  const length = end - start;
  return length === 1
    ? String(start + 1)
    : `${length ? start + 1 : start},${length}`;
}

function* unifiedDiff(
  before: string,
  after: string,
  fromfile: string,
  tofile: string,
): Work<string> {
  const a = yield* lines(before);
  const b = yield* lines(after);
  const changes = yield* changedRanges(a, b);
  if (!changes.length) return "";

  const output = [`--- ${fromfile}\n+++ ${tofile}\n`];
  function* emit(
    prefix: " " | "-" | "+",
    start: number,
    end: number,
  ): Work<void> {
    const source = prefix === "+" ? b : a;
    for (let i = start; i < end; i++) {
      const line = source[i]!;
      output.push(prefix + line);
      if (!line.endsWith("\n")) output.push("\n\\ No newline at end of file\n");
      yield;
    }
  }

  const context = 3;
  let next = 0;
  while (next < changes.length) {
    const first = changes[next]!;
    let end = next + 1;
    while (
      end < changes.length &&
      changes[end]![0] - changes[end - 1]![1] <= 2 * context
    ) {
      end++;
      yield;
    }
    const last = changes[end - 1]!;
    let line = Math.max(0, first[0] - context);
    const stop = Math.min(a.length, last[1] + context);
    const oldRange = formatRange(line, stop);
    const newRange = formatRange(
      Math.max(0, first[2] - context),
      Math.min(b.length, last[3] + context),
    );
    output.push(`@@ -${oldRange} +${newRange} @@\n`);
    while (next < end) {
      const [aStart, aEnd, bStart, bEnd] = changes[next++]!;
      yield* emit(" ", line, aStart);
      yield* emit("-", aStart, aEnd);
      yield* emit("+", bStart, bEnd);
      line = aEnd;
    }
    yield* emit(" ", line, stop);
  }
  return output.join("");
}

export async function securityPolicyUnifiedDiff(
  before: string,
  after: string,
  fromfile: string,
  tofile: string,
  signal?: AbortSignal,
): Promise<string> {
  const work = unifiedDiff(before, after, fromfile, tofile);
  for (;;) {
    signal?.throwIfAborted();
    // Bound synchronous work, including the quadratic inner matching loop.
    for (let operation = 0; operation < 4096; operation++) {
      const result = work.next();
      if (result.done) return result.value;
    }
    await setImmediate();
  }
}
