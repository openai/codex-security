import type * as z from "zod/v4";
import definitions from "../../schemas/definitions/discovery-candidate.schema.json";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";

export interface DiscoveryCandidate extends Record<string, unknown> {
  candidate_id: string;
  cwe_ids: string[];
  locations: Array<{
    path: string;
    start_line: number;
    end_line: number;
    role: string;
  }>;
  summary: string;
  evidence: string;
  context?: string;
  instance?: string;
}

const candidate = loadArtifactZodSchema(
  [definitions] as SchemaDocument[],
  definitions.$id,
  "discoveryCandidate",
) as z.ZodObject;

function validLocations(value: DiscoveryCandidate): boolean {
  return value.locations.every(
    (location) => location.end_line >= location.start_line,
  );
}

/** Exact discovery rows; enriched ledger rows share the same field definitions. */
export const candidateSchemaV1 = (
  candidate.strict() as unknown as z.ZodType<DiscoveryCandidate>
).refine(
  validLocations,
  "end_line must be greater than or equal to start_line",
);
export const candidateLedgerRowSchema = (
  candidate as unknown as z.ZodType<DiscoveryCandidate>
).refine(
  validLocations,
  "end_line must be greater than or equal to start_line",
);
