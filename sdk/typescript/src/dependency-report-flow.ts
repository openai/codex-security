import type {
  DependencyUse,
  DependencyVerdict,
} from "./dependency-reachability.js";

export type DependencyReportStep = {
  kind: "source" | "path" | "sink" | "result";
  title: string;
  excerpt: string;
  evidence: number[];
  observations: number[];
};

const verdictTitles = {
  exploitable: "Exploitable",
  potentially_exploitable: "Potentially exploitable",
  ruled_out: "Ruled out",
  unknown: "Unknown",
} satisfies Record<DependencyVerdict, string>;

const sentenceSegmenter = new Intl.Segmenter("en", { granularity: "sentence" });
const pathCharacter = /[\p{L}\p{N}_.\\/-]/u;
const exclusion =
  /\b(?:skips?|skipped|bypass\w*|exclud\w*|prevent\w*|returns? before|(?:never|cannot|does not) reach)\b/iu;
const control = /\b(?:skip\w*|guard\w*|patch\w*|fixed|fixes)\b/iu;
const gap =
  /\b(?:unknown|unverified|unobserved|unavailable|missing|could not|does not establish|not established|not confirmed)\b/iu;
const impact =
  /\b(?:affected|exploitable|reach(?:es|ed)?|running|caller access)\b/iu;

function mentionsPath(text: string, path: string): boolean {
  for (
    let offset = text.indexOf(path);
    offset !== -1;
    offset = text.indexOf(path, offset + 1)
  ) {
    if (
      !pathCharacter.test(text[offset - 1] ?? "") &&
      !pathCharacter.test(text[offset + path.length] ?? "")
    )
      return true;
  }
  return false;
}

function indices<T>(values: readonly T[], matches: (value: T) => boolean) {
  return values.flatMap((value, index) => (matches(value) ? [index] : []));
}

export function dependencyReportSteps(
  use: DependencyUse,
): DependencyReportStep[] {
  const [first, ...rest] = use.location.split(/\s*(?:→|->)\s*/u);
  const reportedChain = first && rest.length > 0 && rest.every(Boolean);
  const pathTitle = reportedChain ? rest.join(" → ") : use.location;
  const sentences = Array.from(
    sentenceSegmenter.segment(use.reason),
    ({ segment }) => segment.trim(),
  ).filter(Boolean);
  const preferredResult =
    use.verdict === "ruled_out"
      ? [exclusion, control]
      : use.verdict === "unknown"
        ? [gap]
        : use.verdict === "potentially_exploitable"
          ? [gap, impact]
          : [impact];
  const resultExcerpt =
    preferredResult
      .map((pattern) => sentences.find((sentence) => pattern.test(sentence)))
      .find((sentence) => sentence !== undefined) ??
    sentences.at(-1) ??
    "";
  const remaining = sentences.filter((sentence) => sentence !== resultExcerpt);
  const used = new Set<string>();
  function excerpt(matches: (sentence: string) => boolean) {
    const sentence = remaining.find(
      (value) => !used.has(value) && matches(value),
    );
    if (sentence) used.add(sentence);
    return sentence ?? "";
  }
  function matchesPath(sentence: string, label: string) {
    return use.evidence.some(
      ({ path }) => mentionsPath(label, path) && mentionsPath(sentence, path),
    );
  }
  const steps: DependencyReportStep[] = [];
  if (reportedChain) {
    const sourceExcerpt = excerpt(
      (sentence) =>
        matchesPath(sentence, first) ||
        /\b(?:input|requests?|caller|bytes?|payload|stream|response|dataset|receives?|reads?)\b/iu.test(
          sentence,
        ),
    );
    steps.push({
      kind: "source",
      title: first,
      excerpt: sourceExcerpt,
      evidence: indices(
        use.evidence,
        ({ path }) =>
          mentionsPath(first, path) || mentionsPath(sourceExcerpt, path),
      ),
      observations: [],
    });
  }
  const pathExcerpt = excerpt(
    (sentence) =>
      matchesPath(sentence, pathTitle) ||
      /\b(?:calls?|passes|forwards?|invokes?|routes?|pipes?|feeds?)\b/iu.test(
        sentence,
      ),
  );
  const sinkExcerpt = excerpt(
    (sentence) =>
      mentionsPath(sentence, use.component) ||
      (!!use.version && mentionsPath(sentence, use.version)),
  );
  const positive =
    use.verdict === "exploitable" || use.verdict === "potentially_exploitable";

  steps.push(
    {
      kind: "path",
      title: pathTitle,
      excerpt: pathExcerpt,
      evidence: indices(
        use.evidence,
        ({ path, supports }) =>
          mentionsPath(pathTitle, path) ||
          mentionsPath(pathExcerpt, path) ||
          supports.includes("affected_use"),
      ),
      observations: [],
    },
    {
      kind: "sink",
      title: use.version ? `${use.component} ${use.version}` : use.component,
      excerpt: sinkExcerpt,
      evidence: indices(
        use.evidence,
        ({ path, supports }) =>
          mentionsPath(sinkExcerpt, path) ||
          supports.includes("affected_copy") ||
          supports.includes("affected_use"),
      ),
      observations: indices(use.observations, ({ supports }) =>
        supports.includes("affected_copy"),
      ),
    },
    {
      kind: "result",
      title: verdictTitles[use.verdict],
      excerpt: resultExcerpt,
      evidence: indices(
        use.evidence,
        ({ path, supports }) =>
          mentionsPath(resultExcerpt, path) ||
          (use.verdict === "ruled_out" &&
            (supports.includes("affected_use") ||
              supports.includes("affected_copy"))),
      ),
      observations: positive
        ? indices(
            use.observations,
            ({ supports }) =>
              supports.includes("running") || supports.includes("access"),
          )
        : [],
    },
  );
  return steps;
}
