import { setImmediate } from "node:timers/promises";

type Match = [a: number, b: number, size: number];
type Range = [aStart: number, aEnd: number, bStart: number, bEnd: number];
type Opcode = [equal: boolean, ...Range];
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
function* matchingBlocks(a: string[], b: string[]): Work<Match[]> {
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

  const pending: (Range | Match)[] = [[0, a.length, 0, b.length]];
  const matches: Match[] = [];
  while (pending.length) {
    const range = pending.pop()!;
    if (range.length === 3) {
      const previous = matches.at(-1);
      if (
        previous &&
        previous[0] + previous[2] === range[0] &&
        previous[1] + previous[2] === range[1]
      ) {
        previous[2] += range[2];
      } else {
        matches.push(range);
      }
      yield;
      continue;
    }

    const [alo, ahi, blo, bhi] = range;
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
      // Visit matches in order, avoiding a blocking sort of the result.
      if (bestA + size < ahi && bestB + size < bhi) {
        pending.push([bestA + size, ahi, bestB + size, bhi]);
      }
      pending.push([bestA, bestB, size]);
      if (alo < bestA && blo < bestB) {
        pending.push([alo, bestA, blo, bestB]);
      }
    }
    yield;
  }
  matches.push([a.length, b.length, 0]);
  return matches;
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
  const matches = yield* matchingBlocks(a, b);
  const codes: Opcode[] = [];
  let i = 0;
  let j = 0;
  for (const [ai, bj, size] of matches) {
    if (i < ai || j < bj) codes.push([false, i, ai, j, bj]);
    i = ai + size;
    j = bj + size;
    if (size) codes.push([true, ai, i, bj, j]);
    yield;
  }
  const first = codes[0];
  const last = codes.at(-1);
  if (first?.[0]) {
    first[1] = Math.max(first[1], first[2] - 3);
    first[3] = Math.max(first[3], first[4] - 3);
  }
  if (last?.[0]) {
    last[2] = Math.min(last[2], last[1] + 3);
    last[4] = Math.min(last[4], last[3] + 3);
  }

  const output: string[] = [];
  function* emit(group: Opcode[]): Work<void> {
    if (!group.length || (group.length === 1 && group[0]![0])) return;
    if (!output.length) output.push(`--- ${fromfile}\n+++ ${tofile}\n`);
    const first = group[0]!;
    const last = group.at(-1)!;
    output.push(
      `@@ -${formatRange(first[1], last[2])} +${formatRange(first[3], last[4])} @@\n`,
    );
    for (const [equal, aStart, aEnd, bStart, bEnd] of group) {
      for (let index = aStart; index < aEnd; index++) {
        const line = a[index]!;
        output.push((equal ? " " : "-") + line);
        if (!line.endsWith("\n")) {
          output.push("\n\\ No newline at end of file\n");
        }
        yield;
      }
      if (!equal) {
        for (let index = bStart; index < bEnd; index++) {
          const line = b[index]!;
          output.push("+" + line);
          if (!line.endsWith("\n")) {
            output.push("\n\\ No newline at end of file\n");
          }
          yield;
        }
      }
      yield;
    }
  }

  let group: Opcode[] = [];
  for (const [equal, aStart, aEnd, bStart, bEnd] of codes) {
    if (equal && aEnd - aStart > 6) {
      group.push([true, aStart, aStart + 3, bStart, bStart + 3]);
      yield* emit(group);
      group = [[true, aEnd - 3, aEnd, bEnd - 3, bEnd]];
    } else {
      group.push([equal, aStart, aEnd, bStart, bEnd]);
    }
    yield;
  }
  yield* emit(group);
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
