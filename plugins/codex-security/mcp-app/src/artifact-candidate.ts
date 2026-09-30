import type { z } from "zod";
import definitions from "../../schemas/definitions/discovery-candidate.schema.json";
import type {
  RawDiscoveryCandidate,
  RawDiscoveryLocation,
} from "./artifact-discovery.js";
import { loadArtifactZodSchema } from "./artifact-schema-loader.js";

type CandidateShape = {
  [K in keyof RawDiscoveryCandidate]-?: K extends "locations"
    ? z.ZodArray<z.ZodType<Required<RawDiscoveryLocation>>>
    : z.ZodType<RawDiscoveryCandidate[K]>;
} & { candidate_id: z.ZodString };

const candidate = loadArtifactZodSchema(
  [definitions],
  definitions.$id,
  "discoveryCandidate",
) as z.ZodObject<CandidateShape>;

/** Exact discovery rows emitted by the shared candidate normalizer. */
export const candidateSchemaV1 = candidate
  .strict()
  .extend({
    candidate_id: candidate.shape.candidate_id
      .min(1)
      .regex(/\S/u, "Must contain non-whitespace text"),
    locations: candidate.shape.locations.element
      .refine((location) => location.end_line >= location.start_line, {
        message: "end_line must be greater than or equal to start_line",
        path: ["end_line"],
      })
      .array()
      .min(1),
  })
  .meta({
    id: "codex-security-standard-scan-candidate-v1",
    title: "Codex Security discovery candidate v1",
  });
