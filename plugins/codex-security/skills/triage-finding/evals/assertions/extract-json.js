module.exports = function extractJson(output, schemaVersion, { requireSingle = false } = {}) {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  const fencedBlocks = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].map((match) =>
    match[1].trim(),
  );
  const candidates = fencedBlocks.length > 0
    ? fencedBlocks
    : [text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1)];
  if (requireSingle) {
    candidates.length = 0;
    let depth = 0;
    let start = 0;
    for (const match of text.matchAll(/"(?:\\.|[^"\\])*"|[{}]/gs)) {
      if (match[0] === "{") {
        if (depth++ === 0) start = match.index;
      } else if (match[0] === "}" && depth > 0 && --depth === 0) {
        candidates.push(text.slice(start, match.index + 1));
      }
    }
  }

  const matches = [];
  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && parsed.schema_version === schemaVersion) {
        if (!requireSingle) return parsed;
        matches.push(parsed);
      }
    } catch {
      // Keep trying other candidates.
    }
  }
  if (matches.length === 1) return matches[0];

  throw new Error(`Could not find a parseable ${schemaVersion} JSON block.`);
};
