import { sourceReader } from "./grade.mjs";

// The CLI sometimes describes the investigation process in its limitations.
// Remove explicit mode announcements while retaining conclusions and gaps.
const modeAnnouncements = [
  /\bindependent (?:(?:assessment|ledger|host) )?(?:grading|review) (?:was )?(?:disabled|enabled)\b/iu,
  /\b(?:unreviewed|host checks (?:passed|accepted)|passed host checks)\b/iu,
  /\bhost (?:explicitly )?(?:permits|permitted|instructed|authorized|designated these submissions|accepted the submitted)\b/iu,
];
function neutralProse(text) {
  return text
    .split(/(?<=[.;])\s+/u)
    .filter((part) => !modeAnnouncements.some((pattern) => pattern.test(part)))
    .join(" ")
    .replace(/\breview clarification:\s*/giu, "")
    .replace(/\breviewed (?=premise|claim|assessment)/giu, "")
    .replace(/\bassessment review\b/giu, "assessment")
    .replace(
      /\b(?:was |were )?submitted and (?:independently )?approved\b/giu,
      "recorded",
    )
    .replace(
      /\b(?:independent (?:(?:assessment|ledger|host) )?review|the reviewer|the grader)\b/giu,
      "the investigation",
    )
    .replace(/\b(?:independently )?approved\b/giu, "recorded")
    .trim();
}

const omitted = new Set([
  "candidateId",
  "conclusionClaim",
  "decidingEvidence",
  "supportingClaims",
  "receiptId",
  "originalPayloadSha256",
]);
const citationKey = (path, start, end) =>
  path + ":" + start + (end === start ? "" : "-" + end);

function reportView(report, read, sha) {
  const sources = Object.create(null);
  const receipts = [];
  const receiptIndexes = new Map();
  const claims = new Map(
    (report.claims ?? []).map((claim) => [claim.hash, claim]),
  );
  const premises = [...claims.values()].filter(
    (c) => c.payload?.kind === "premise",
  );

  function sourceRef(source) {
    const { path, startLine, endLine, commit = sha } = source;
    const key =
      (commit === sha ? "" : commit + "@") +
      citationKey(path, startLine, endLine);
    if (!Object.hasOwn(sources, key)) {
      try {
        sources[key] = read({ ...source, commit }).excerpt;
      } catch {
        sources[key] = {
          error: "Range could not be verified at the pinned revision.",
        };
      }
    }
    return key;
  }

  function receiptRef(id) {
    const item = report.claimEvidence?.receipts?.[id];
    if (!item) return null;
    if (!receiptIndexes.has(id)) {
      const reply = item.result?.structuredContent ?? item.result;
      const tool = item.tool ?? item.origin?.tool;
      const result =
        tool === "read_dependency_source" && reply?.text !== undefined
          ? {
              url: reply.url,
              request: reply.request,
              startLine: reply.startLine,
              endLine: reply.endLine,
              text: reply.text,
            }
          : reply;
      receiptIndexes.set(id, receipts.length);
      receipts.push({ server: item.server, tool, result });
    }
    return receiptIndexes.get(id);
  }

  function view(value, field) {
    if (typeof value === "string") {
      return [
        "record",
        "quote",
        "path",
        "argument",
        "component",
        "version",
        "location",
      ].includes(field)
        ? value
        : neutralProse(value);
    }
    if (Array.isArray(value))
      return value.map((v) => view(v, field)).filter((v) => v !== "");
    if (!value || typeof value !== "object") return value;
    if (
      value.path &&
      Number.isInteger(value.startLine) &&
      Number.isInteger(value.endLine)
    )
      return value.supports?.length
        ? { range: sourceRef(value), supports: value.supports }
        : sourceRef(value);
    return Object.fromEntries(
      Object.entries(value)
        .filter(
          ([key, v]) =>
            !omitted.has(key) &&
            v != null &&
            !(Array.isArray(v) && v.length === 0),
        )
        .map(([key, v]) => [key, view(v, key)]),
    );
  }

  function linked(entry) {
    const result = view(entry);
    const claim = claims.get(entry.conclusionClaim?.hash);
    const receiptIds = claim?.evidence?.receiptIds ?? [];
    if (receiptIds.length) result.receiptIndexes = receiptIds.map(receiptRef);
    const premiseIndexes = (entry.supportingClaims ?? [])
      .map((ref) => premises.indexOf(claims.get(ref.hash)))
      .filter((index) => index !== -1);
    if (premiseIndexes.length) result.premiseIndexes = premiseIndexes;
    return result;
  }

  // The CLI repeats automatically generated search leads in limitations and
  // coverage. Keep their locations once, separately from analyst dispositions.
  const leads = new Set();
  const coverage = [];
  for (const entry of report.coverage ?? []) {
    if (
      entry.kind === "unresolved" &&
      !entry.conclusionClaim &&
      /^Unassessed caller in /u.test(entry.reason)
    )
      leads.add(entry.reason);
    else coverage.push(linked(entry));
  }
  const searches = (report.searches ?? []).map(
    ({ tool, scope, result, completeness, details }) => ({
      tool,
      scope,
      result,
      completeness,
      details,
    }),
  );
  return {
    advisoryId: report.advisoryId ?? report.cve,
    advisories: report.advisoryDetails?.map(({ id, summary, body }) => ({
      id,
      summary,
      body,
    })),
    uses: (report.uses ?? []).map(linked),
    coverage,
    unassessedLeads: [...leads],
    assumptions: view(report.assumptions ?? []),
    limitations: view((report.limitations ?? []).filter((s) => !leads.has(s))),
    searches: view(searches),
    premises: premises.map(({ payload, evidence }) => ({
      statement: neutralProse(payload.statement),
      evidence: payload.sources.map(sourceRef),
      receiptIndexes: (evidence.receiptIds ?? []).map(receiptRef),
    })),
    sources,
    receipts,
  };
}

export function buildReportPacket({ report, reference, repo, sha }) {
  const read = sourceReader(repo, sha);
  const one = (check) => reportView(check, read, sha);
  const content = report.checks
    ? { checks: report.checks.map(one) }
    : one(report);
  return { reference, report: content };
}
