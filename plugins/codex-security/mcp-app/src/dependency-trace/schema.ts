import * as z from "zod/v4";

const text = z.string().trim().min(1);

export const traceInputSchema = z
  .strictObject({
    package: text.describe("Affected component, not its parent artifact."),
    version: text.optional().describe("Affected component version, if known."),
    symbol: text.optional().describe("Affected operation or symbol, if known."),
    source_symbol: z
      .string()
      .regex(/^[A-Za-z_][A-Za-z0-9_]*$/u)
      .optional()
      .describe(
        "Known bare name of a local input-producing call; with symbol, check candidate flow to that sink within one file.",
      ),
    paths: z
      .array(text)
      .min(1)
      .optional()
      .describe(
        "Checkout-relative directories to search recursively. Defaults to the checkout when neither paths nor files is supplied.",
      ),
    source_terms: z
      .array(text)
      .min(1)
      .max(16)
      .optional()
      .describe(
        "Literal source import or wrapper names. Search directories for any term and the operation, then pass those files to OpenGrep in batches. This is initial source discovery even at zero hops.",
      ),
    files: z
      .array(text)
      .min(1)
      .optional()
      .describe(
        "Exact checkout-relative source files or dependency manifests to analyze directly. With a symbol, start structural call or flow matching in these files even at zero hops.",
      ),
    rules: z
      .array(z.record(z.string(), z.unknown()))
      .optional()
      .describe(
        "Model-authored standard OpenGrep rule objects, required for every call or flow scan. Package/manifest/catalog-only lookups may omit rules. Missing rules never invoke OpenGrep; no built-in fallback is generated. The native parser validates fields and patterns. Capture $CALLER/$ALIAS/$RECEIVER when useful; optional metadata.evidence_kind=unresolved_lead records text leads rather than calls. Use native focus-metavariable for a precise match range.",
      ),
    source_only: z
      .boolean()
      .optional()
      .describe(
        "Record source evidence and candidates without requesting service or runtime lookups. Resolve selected consumers separately.",
      ),
    time_budget_ms: z
      .number()
      .int()
      .positive()
      .max(600_000)
      .describe("Wall-clock budget for this invocation in milliseconds."),
    max_hops: z
      .number()
      .int()
      .min(0)
      .max(8)
      .describe(
        "Maximum follow-up depth. Zero performs only the initial lookups.",
      ),
  })
  .refine((request) => !request.source_terms || !!request.symbol, {
    path: ["source_terms"],
    message: "An operation symbol is required with source_terms.",
  })
  .refine((request) => !request.source_terms || !request.files, {
    path: ["source_terms"],
    message: "Use source_terms with directories, or supply exact files.",
  })
  .refine((request) => !request.source_symbol || !!request.symbol, {
    path: ["symbol"],
    message: "A sink symbol is required with source_symbol.",
  });

export type TraceRequest = z.output<typeof traceInputSchema>;

const graphName = text.max(4096);
export const serviceInputSchema = z
  .strictObject({
    project: graphName
      .optional()
      .describe(
        "Checkout-relative project directory or build file. With paths, provide context for the catalog lookup. On its own, search local configuration for references to the project.",
      ),
    paths: z
      .array(graphName)
      .min(1)
      .max(64)
      .optional()
      .describe(
        "Checkout-relative consumer or launch files to resolve through the configured service catalogs.",
      ),
  })
  .refine(({ project, paths }) => project || paths, {
    message: "Supply paths to resolve or a project to search.",
  });

export const graphQuerySchema = z.strictObject({
  node: graphName
    .optional()
    .describe(
      "Exact node name or graph ID. Omit for counts, services, and sampled witness summaries.",
    ),
  witness: graphName
    .optional()
    .describe(
      "Graph witness ID (summary.id, not native_id). With a node, return only that witness's adjacent observed calls; alone, return its root-first frames.",
    ),
  search: graphName
    .optional()
    .describe(
      "Case-sensitive substring of a node name. Returns matching scoped nodes and their sampled witness IDs.",
    ),
});
