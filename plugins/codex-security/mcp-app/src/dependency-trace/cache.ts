import type { ScopeResult, TraceCache } from "./types.js";

const MAX_ENTRIES = 1024;

// Charge two bytes per UTF-16 code unit and allow overhead for the Map,
// strings, arrays, and small records. This estimates retained data, not RSS.
function stringBytes(value?: string): number {
  return value === undefined ? 0 : 32 + 2 * value.length;
}

function entryBytes(key: string, result: ScopeResult): number {
  let bytes =
    256 +
    stringBytes(key) +
    stringBytes(result.fingerprint) +
    stringBytes(result.reason);
  for (const scope of result.next) {
    bytes += 128;
    for (const value of Object.values(scope)) bytes += stringBytes(value);
  }
  for (const { step, source } of result.evidence) {
    bytes +=
      256 +
      stringBytes(source) +
      stringBytes(step.relation) +
      stringBytes(step.calleeText) +
      stringBytes(step.sourceText);
    for (const endpoint of [step.from, step.to]) {
      if (!endpoint) continue;
      bytes +=
        128 +
        stringBytes(endpoint.kind) +
        stringBytes(endpoint.name) +
        stringBytes(endpoint.scope);
    }
  }
  for (const { source, text } of result.textMatches ?? []) {
    bytes += 128 + stringBytes(source) + stringBytes(text);
  }
  return bytes;
}

export function createTraceCache(maxBytes = 16 * 1024 * 1024): TraceCache {
  const entries = new Map<string, { result: ScopeResult; bytes: number }>();
  let usedBytes = 0;
  return {
    read(key) {
      const entry = entries.get(key);
      if (!entry) return undefined;
      entries.delete(key);
      entries.set(key, entry);
      return entry.result;
    },
    store(key, result) {
      if (!result.complete) return;
      const bytes = entryBytes(key, result);
      if (bytes > maxBytes) return;
      const previous = entries.get(key);
      if (previous) {
        entries.delete(key);
        usedBytes -= previous.bytes;
      }
      // Map iteration yields the least recently used entry first.
      for (const [oldKey, oldEntry] of entries) {
        if (usedBytes + bytes <= maxBytes && entries.size < MAX_ENTRIES) break;
        entries.delete(oldKey);
        usedBytes -= oldEntry.bytes;
      }
      entries.set(key, { result, bytes });
      usedBytes += bytes;
    },
    clear() {
      entries.clear();
      usedBytes = 0;
    },
  };
}
