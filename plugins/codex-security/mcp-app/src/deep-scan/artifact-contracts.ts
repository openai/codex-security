import { z } from "zod";

const nonEmptyString = z.string().min(1).regex(/\S/u, "Must contain non-whitespace text");
const candidateLocationSchemaV1 = z.object({
  path: nonEmptyString,
  start_line: z.number().int().positive(),
  end_line: z.number().int().positive(),
  role: z.enum([
    "entrypoint",
    "entrypoint/wrapper",
    "source",
    "root_control",
    "sink",
    "concrete_implementation",
    "evidence"
  ])
}).strict().refine((location) => location.end_line >= location.start_line, {
  message: "end_line must be greater than or equal to start_line",
  path: ["end_line"]
});

/** Exact discovery rows emitted by the shared candidate normalizer. */
export const candidateSchemaV1 = z.object({
  candidate_id: nonEmptyString.regex(/^(?!\.{1,2}$)[^/\\]+$/u),
  cwe_ids: z.array(z.string().regex(/^CWE-[1-9]\d*$/u)),
  locations: z.array(candidateLocationSchemaV1).min(1),
  summary: nonEmptyString,
  evidence: nonEmptyString,
  context: nonEmptyString.optional(),
  instance: nonEmptyString.optional()
}).strict().meta({
  id: "codex-security-standard-scan-candidate-v1",
  title: "Codex Security discovery candidate v1"
});
