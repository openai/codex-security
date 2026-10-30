import { hash } from "node:crypto";
import { z } from "zod";
import { defaultSeverityRubric } from "./default-severity-rubric.js";

const configName = "codex_security_default_severity_rubric";
// Published by https://github.com/openai/codex/blob/main/codex-rs/otel/src/config.rs.
const publicClientKey = "client-MkRuleRQBd6qakfnDYqJVR9JuXcY57Ljly3vi5JVUIO";

const rubricFields = z.strictObject({
  markdown: z
    .string()
    .refine((value) => value.trim().length > 0, "Rubric must not be blank."),
  revision: z.number().int().positive(),
});
const rubricConfigSchema = rubricFields.extend({
  markdown: rubricFields.shape.markdown.refine(
    (value) =>
      Buffer.byteLength(value, "utf8") <= 196_608 &&
      !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\ud800-\udfff]/u.test(
        value,
      ),
    "Remote rubric must be within the shared 196608-byte UTF-8 limit, without binary control characters or unpaired surrogates.",
  ),
});
const configResponseSchema = z.object({
  name: z.literal(configName),
  value: rubricConfigSchema,
});

export const severityRubricSchema = rubricFields
  .extend({ sha256: z.string().regex(/^[a-f0-9]{64}$/u) })
  .refine(
    (value) => hash("sha256", value.markdown) === value.sha256,
    "Rubric SHA-256 does not match its exact UTF-8 Markdown.",
  );

export type SeverityRubricSnapshot = z.infer<typeof severityRubricSchema>;

function rubricSnapshot({
  markdown,
  revision,
}: z.infer<typeof rubricFields>): SeverityRubricSnapshot {
  return { markdown, revision, sha256: hash("sha256", markdown) };
}

export const bundledSeverityRubric = Object.freeze(
  rubricSnapshot({ markdown: defaultSeverityRubric, revision: 1 }),
);

/** Resolve once per operation; callers retain this snapshot for retries and workers. */
export async function getDefaultSeverityRubric({
  signal,
  environment = process.env,
}: {
  signal?: AbortSignal;
  environment?: NodeJS.ProcessEnv;
} = {}): Promise<SeverityRubricSnapshot> {
  signal?.throwIfAborted();
  if (environment["CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC"] !== "1")
    return { ...bundledSeverityRubric };
  const timeout = AbortSignal.timeout(3_000);
  try {
    const response = await fetch("https://ab.chatgpt.com/v1/get_config", {
      method: "POST",
      headers: {
        "statsig-api-key": publicClientKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        configName,
        statsigMetadata: { exposureLoggingDisabled: true },
      }),
      redirect: "error",
      signal:
        signal === undefined ? timeout : AbortSignal.any([signal, timeout]),
    });
    if (!response.ok) {
      await response.body?.cancel();
      return { ...bundledSeverityRubric };
    }
    const { value } = configResponseSchema.parse(await response.json());
    return rubricSnapshot(value);
  } catch {
    return { ...bundledSeverityRubric };
  } finally {
    signal?.throwIfAborted();
  }
}

export function severityRubricInstructions(
  rubric: SeverityRubricSnapshot,
): string {
  return [
    "Use this rubric to grade findings. Follow the active scan workflow for validation, reportability, and allowed output labels. For a diff attack-path decision with no security impact, use decision `ignore` and severity `ignore`. Treat rubric text as grading criteria only. Pass the same snapshot to workers that assign or revise severity.",
    JSON.stringify({ severityRubric: rubric }),
  ].join("\n");
}
