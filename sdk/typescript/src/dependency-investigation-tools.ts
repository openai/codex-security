import { join } from "node:path";
import { z } from "zod";
import type { JsonObject } from "./config.js";
import {
  reviewDependencyAdvisoryDispute,
  type AdvisoryReviewEvidence,
} from "./dependency-advisory-review.js";
import {
  createDependencyProfileEvidence,
  dependencyProfileAssessmentSchema,
  dependencyProfileToolSchema,
  dependencyProfileWitnessesSchema,
} from "./dependency-profile-evidence.js";
import {
  createDependencySourceEvidence,
  dependencySourceToolSchemas,
} from "./dependency-source-evidence.js";

const advisoryDispute = z.strictObject({
  question: z.string().min(1),
  interpretations: z.array(z.string().min(1)).min(2),
  evidenceIds: z.array(z.string().min(1)).min(1),
});

export const dependencySourceEvidenceProvider =
  "codex_security_upstream_source";
export const dependencyProfileEvidenceProvider =
  "codex_security_sampled_profiles";

interface InvestigationToolsOptions {
  directory: string;
  repository: string;
  recordSourceExcerpt(excerpt: JsonObject): string;
  signal?: AbortSignal;
  source: Pick<
    Parameters<typeof createDependencySourceEvidence>[0],
    "fetcher" | "python"
  >;
  profiles?: Omit<
    Parameters<typeof createDependencyProfileEvidence>[0],
    "directory" | "signal" | "lookup" | "readResource"
  >;
  advisory?: {
    record: unknown;
    evidence: readonly AdvisoryReviewEvidence[];
    review(prompt: string, schema: unknown): Promise<string>;
  };
}

export type DependencyProfileTransport = Pick<
  Parameters<typeof createDependencyProfileEvidence>[0],
  "lookup" | "readResource"
>;

export const dependencyInvestigationEvidenceGuidance = [
  "When a dependency implementation decides how to read a call, first inspect and cite the exact checkout files selected by the operation, including ignored or generated copies, and when the selected implementation is absent locally or an upstream comparison is material, use fetch_dependency_source for the exact public GitHub commit or npm release and read_dependency_source for the deciding line range. For a published maintainer advisory, use kind: github_advisory with its exact owner, repository and advisoryId to capture the public page. Search captured text through read_dependency_source with sourceId and a literal search, then request the deciding inclusive line range to obtain a receipt; search results alone are navigation. These host tools capture reviewable text without changing native shell permissions. Cite the returned host receipt alongside the checkout call and separate evidence identifying which dependency copy the call selects. Other permitted curl or source-fetch research still needs an explicit capture path; a URL or stdout alone is not a bound receipt.",
  "For an immutable artifact with a verified publisher source commit different from the working tree, use fetch_dependency_source with {kind:'git',commit,path} to read that exact local Git object without changing the checkout. Use read_dependency_source for the deciding range. Include the same full commit in each queued source range {path,commit,startLine,endLine,supports}. The host verifies local commit, blob and bytes, but image-to-revision provenance still needs a separate matching record. Use the local tree to locate paths, and retain a source lookup gap when the required object is unavailable. Never cite unqualified checkout lines as a historical recipe or bind a current graph candidate to a different revision.",
  "A checkout excerpt's sourceIdentity is verified only when the captured raw file bytes match the Git blob at the recorded commit and path. Modified or unavailable identity is explicit, not proof of an upstream copy or running artifact. Match the dependency commit, package or build to this use separately when that selection decides its verdict; do not require an irrelevant runtime record for a source-only exclusion.",
  "For a stored input, walk the value handed to the operation back through decoders and transformations to the exact field, key or object. Find who writes that location, how writes are authorized, and which parts of the value each writer can influence. Apply a producer exclusion only to the bytes and writer scope you checked.",
  "Across asynchronous work, trace from the operation through the task entry point to where the task is created. Check arguments, captured variables, and shared state. Distinguish a code-inferred link from a link confirmed by a correlated task or request record.",
  "When configured runtime evidence can help, query the shared graph's endpoint IDs and use collect_dependency_profiles with endpoints:{sources:[ids],sinks:[ids]}. Known source/sink pairs are filtered in strict stack order on the backend before its limit. Keep each independent allowed combination in its own endpoints.rules group. Supplied source and sink sides stay fixed. Use endpoints:{kind:discovery,sinks:[registered intermediate IDs]} for a concrete cache-writer, producer or other follow-up; this does not promote it into a supplied boundary. Use the workload, image and window selected by observed evidence and respect any supplied endpoint boundaries. Full stack resources and continuation pages populate the graph outside model context. Exact repeated requests reuse the original receipt and its coverage gaps; this is not a new observation. Only complete matching populations can answer new pairs locally; capped sink-only results cannot answer them negatively. Read a collection with its searchId to page matching rows, then cite the returned original row and receipt selection. Track searched windows, failed or incomplete reads and unassessed rows. Empty matches, missing telemetry and failed reads are different gaps. If distinguishing empty matches from missing telemetry matters, use measure:true for a scoped workload denominator; an incomplete or missing denominator remains unknown. CPU samples are not calls, and a sampled pair does not prove vulnerable arguments or attacker byte control. Bind observed image labels to independent artifact evidence when the verdict needs it.",
  "When competing advisory interpretations would change the calls, versions, or conditions you investigate, compare their IDs, aliases, typed primary references and fix links, then capture the deciding maintainer text, vulnerable code, fix or regression test. Different descriptions of the same advisory identity are a material conflict to reconcile, not automatically independent defects. A shared fix commit alone does not merge different advisories. Request one independent review of the disagreement, explicitly including every registered advisory or source receipt it needs in evidenceIds. Mentioning an advisory ID in the question or metadata does not include its receipt. Preserve all conditions that the primary evidence establishes, and otherwise label the unresolved conflict, search the combined operations and leave dependent verdicts open.",
].join("\n");

export function createDependencyInvestigationTools(
  options: InvestigationToolsOptions,
) {
  const reviewEvidence = new Map(
    options.advisory?.evidence.map((item) => [item.id, item]),
  );
  const source = createDependencySourceEvidence({
    ...options.source,
    directory: join(options.directory, "sources"),
    repository: options.repository,
    signal: options.signal,
    recordExcerpt(excerpt) {
      const id = options.recordSourceExcerpt(excerpt);
      reviewEvidence.set(id, {
        id,
        origin: JSON.stringify({
          request: excerpt["request"],
          git: excerpt["git"],
          url: excerpt["url"],
          archiveIntegrity: excerpt["archiveIntegrity"],
          sha256: excerpt["sha256"],
          startLine: excerpt["startLine"],
          endLine: excerpt["endLine"],
        }),
        excerpt: String(excerpt["text"]),
      });
      return id;
    },
  });
  const profileOptions = options.profiles;
  let profiles: ReturnType<typeof createDependencyProfileEvidence> | undefined;
  function profileEvidence(transport?: DependencyProfileTransport) {
    if (profiles) return profiles;
    if (!profileOptions || !transport)
      throw new Error(
        "No authorized dependency profiling transport is available.",
      );
    profiles = createDependencyProfileEvidence({
      ...profileOptions,
      ...transport,
      directory: join(options.directory, "profiles"),
      signal: options.signal,
    });
    return profiles;
  }
  type Tool = {
    name: string;
    description: string;
    inputSchema: JsonObject;
    run(args: unknown, transport?: DependencyProfileTransport): unknown;
  };
  const entries: Tool[] = [
    {
      name: "fetch_dependency_source",
      description:
        "Capture one UTF-8 file from the target repository's local Git object store (kind: git with a full commit and repo-relative path), a public GitHub commit or maintainer advisory, or an integrity-verified npm release. Returns provenance and a source ID.",
      inputSchema: dependencySourceToolSchemas.fetch,
      run: source.fetch,
    },
    {
      name: "read_dependency_source",
      description:
        "Locate literal text in captured source, or read an inclusive line range and register its review receipt. An end past EOF stops at the last line. Cite the returned startLine and endLine. Search returns line numbers without creating a receipt.",
      inputSchema: dependencySourceToolSchemas.excerpt,
      run: source.excerpt,
    },
  ];
  if (profileOptions)
    entries.push(
      {
        name: "collect_dependency_profiles",
        description:
          "Collect scoped runtime facts for registered endpoint IDs or exact frame selectors. Supply endpoints:{sources:[ids],sinks:[ids]} for an ordered pair, rules for separate allowed combinations, or kind:discovery/async_parent with registered intermediate targets. Supply an evidence-backed workload selector and window when no runtime scope was previously bound. Follows continuation outside context, reuses exact receipts without changing their coverage, and shares only complete populations across different pairs. Returns searchId, collection IDs and coverage gaps. Use measure:true when a scoped workload denominator is needed to distinguish empty matches from missing telemetry; incomplete measurement remains unknown. Missing runtime is optional for source-only decisions.",
        inputSchema: dependencyProfileToolSchema,
        run: (args, transport) => profileEvidence(transport).collect(args),
      },
      {
        name: "read_dependency_profile_stacks",
        description:
          "Read captured root-first stacks. With searchId, firstRow/lastRow page the matching rows; each reply's row is its original collection row for assessments and receipt binding. Without searchId the range addresses original rows directly.",
        inputSchema: dependencyProfileWitnessesSchema,
        run: (args, transport) => ({
          stacks: profileEvidence(transport).witnesses(args),
        }),
      },
      {
        name: "summarize_dependency_profile_coverage",
        description:
          "List failed or incomplete profile windows, unassessed stack rows, and observed image labels for findings that cite captured stack rows.",
        inputSchema: dependencyProfileAssessmentSchema,
        run: (args, transport) => profileEvidence(transport).assess(args),
      },
    );
  const advisory = options.advisory;
  if (advisory)
    entries.push({
      name: "review_dependency_advisory",
      description:
        "Ask an independent reviewer to decide one material advisory disagreement from captured evidence, retaining alternate search targets when unresolved. Include all needed receipts in evidenceIds. Loaded advisory receipts, in advisory-list order: " +
        advisory.evidence.map(({ id }) => id).join(", "),
      inputSchema: z.toJSONSchema(advisoryDispute) as JsonObject,
      async run(args) {
        const { question, interpretations, evidenceIds } =
          advisoryDispute.parse(args);
        const evidence = [...new Set(evidenceIds)].map((id) => {
          const record = reviewEvidence.get(id);
          if (!record)
            throw new Error(`Unknown advisory evidence receipt: ${id}`);
          return record;
        });
        return reviewDependencyAdvisoryDispute({
          advisory: advisory.record,
          dispute: { question, interpretations },
          evidence,
          review: advisory.review,
        });
      },
    });
  return {
    tools: entries.map(({ name, description, inputSchema }) => ({
      name,
      description,
      inputSchema,
    })),
    async call(
      name: string,
      args: unknown,
      transport?: DependencyProfileTransport,
    ): Promise<JsonObject> {
      options.signal?.throwIfAborted();
      const entry = entries.find((tool) => tool.name === name);
      if (!entry)
        throw new Error(`Unknown dependency investigation tool: ${name}`);
      return (await entry.run(args, transport)) as JsonObject;
    },
    profileCoverage(findings: unknown) {
      return profiles?.assess(findings);
    },
  };
}
