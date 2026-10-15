import * as z from "zod/v4";

export function threatModelSchemas(
  textList: z.ZodArray<z.ZodString>,
  content = textList.element,
) {
  const scopeText = z.string().min(1);
  const scope = z
    .looseObject({
      includePaths: z.array(scopeText),
      excludePaths: z.array(scopeText).optional(),
      summary: scopeText.optional(),
    })
    .describe(
      "The modeled source scope, which may differ from the scan scope. Omit when unknown.",
    );
  const markdown = z.looseObject({
    format: z.literal("markdown"),
    content,
    scope: scope.optional(),
    origin: z
      .enum(["generated", "provided", "reconciled", "recovered"])
      .optional(),
  });
  const schema = z
    .union([
      z.looseObject({
        summary: textList.element,
        assets: textList.optional(),
        trustBoundaries: textList.optional(),
        attackerCapabilities: textList.optional(),
        securityObjectives: textList.optional(),
        assumptions: textList.optional(),
      }),
      markdown,
    ])
    .describe(
      "Retained threat-model content. Existing structured models remain supported; Markdown documents preserve their complete original body.",
    );
  return { schema, markdown, scope };
}
