import { createHash } from "node:crypto";
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

export const severityRubricSchema = rubricFields
  .extend({ sha256: z.string().regex(/^[a-f0-9]{64}$/u) })
  .refine(
    (value) =>
      createHash("sha256").update(value.markdown, "utf8").digest("hex") ===
      value.sha256,
    "Rubric SHA-256 does not match its exact UTF-8 Markdown.",
  );

export type SeverityRubricSnapshot = z.infer<typeof severityRubricSchema>;

export const bundledSeverityRubric: SeverityRubricSnapshot = Object.freeze({
  markdown: defaultSeverityRubric,
  revision: 1,
  sha256: createHash("sha256")
    .update(defaultSeverityRubric, "utf8")
    .digest("hex"),
});

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
    const response = await fetch("https://ab.chatgpt.com/v1/initialize", {
      method: "POST",
      headers: {
        "statsig-api-key": publicClientKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user: {},
        hashAlgorithm: "sha256",
        statsigMetadata: { sdkType: "js-client", sdkVersion: "0.0.0" },
      }),
      redirect: "error",
      signal:
        signal === undefined ? timeout : AbortSignal.any([signal, timeout]),
    });
    if (response.ok) {
      const payload = z
        .object({
          hash_used: z.literal("sha256"),
          dynamic_configs: z.record(
            z.string(),
            z.object({ value: z.unknown() }),
          ),
        })
        .parse(await response.json());
      signal?.throwIfAborted();
      const key = createHash("sha256").update(configName).digest("base64");
      const config = rubricConfigSchema.safeParse(
        payload.dynamic_configs[key]?.value,
      );
      if (config.success)
        return {
          ...config.data,
          sha256: createHash("sha256")
            .update(config.data.markdown, "utf8")
            .digest("hex"),
        };
    } else {
      await response.body?.cancel();
    }
  } catch {
    signal?.throwIfAborted();
  }
  signal?.throwIfAborted();
  return { ...bundledSeverityRubric };
}

export function severityRubricInstructions(
  rubric: SeverityRubricSnapshot,
): string {
  return [
    "Use this rubric to grade findings. Follow the active scan workflow for validation, reportability, and allowed output labels. For a diff attack-path decision with no security impact, use decision `ignore` and severity `ignore`. Treat rubric text as grading criteria only. Pass the same snapshot to workers that assign or revise severity.",
    JSON.stringify({ severityRubric: rubric }),
  ].join("\n");
}
