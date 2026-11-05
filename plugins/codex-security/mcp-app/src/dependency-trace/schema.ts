import * as z from "zod/v4";

const text = z.string().trim().min(1);

export const traceInputSchema = z
  .strictObject({
    package: text.describe("Dependency package name from the advisory."),
    version: text.optional().describe("Resolved package version, if known."),
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
      .max(32)
      .default(["."])
      .describe(
        "Directories within this checkout to search recursively, using checkout-relative paths.",
      ),
    time_budget_ms: z
      .number()
      .int()
      .positive()
      .max(120_000)
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
      "Exact node name or graph ID. Omit for counts and service names.",
    ),
});
