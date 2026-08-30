import { z } from "zod";
import {
  DeepScanSettingsSchema,
  FailureSeveritySchema,
  ScanSettingsSchema,
} from "./scan-settings.js";

const nonempty = z.string().min(1);

export const ProjectScopeSchema = z.union([
  z.strictObject({
    paths: z
      .array(nonempty)
      .min(1)
      .describe("Literal paths relative to the selected repository."),
  }),
  z.strictObject({
    diff: z.strictObject({
      base: nonempty,
      head: nonempty.optional().meta({ default: "HEAD" }),
    }),
  }),
  z.strictObject({
    workingTree: z.strictObject({
      base: nonempty.optional().meta({ default: "HEAD" }),
    }),
  }),
]);

export const ProjectConfigInputSchema = z.strictObject({
  $schema: nonempty
    .optional()
    .describe(
      "Editor schema URI or relative path. The CLI does not fetch or select a validator from this value.",
    ),
  auth: ScanSettingsSchema.shape.auth.describe(
    "Credential-source choice only; never a credential value.",
  ),
  scan: z
    .strictObject({
      mode: ScanSettingsSchema.shape.mode,
      scope: ProjectScopeSchema.optional().describe(
        "One scope variant. Omit for the whole repository. Mode compatibility is checked after overrides.",
      ),
      knowledgeBase: ScanSettingsSchema.shape.knowledgeBasePaths.describe(
        "Context files or directories, relative to this file. An empty list selects no additional context.",
      ),
      instructionsFile: ScanSettingsSchema.shape.scanPromptFile.describe(
        "Additional scan instructions, relative to this file.",
      ),
      validationFile: ScanSettingsSchema.shape.validationPromptFile.describe(
        "Custom validation instructions, relative to this file; not supported in active deep scans.",
      ),
      deep: DeepScanSettingsSchema.omit({ subagents: true })
        .extend({
          subagentsPerWorker: DeepScanSettingsSchema.shape.subagents,
        })
        .optional()
        .describe(
          "Deep defaults; a valid block may be retained while standard mode is selected.",
        ),
    })
    .optional(),
  codex: z
    .object({
      model: nonempty.optional(),
      model_reasoning_effort: nonempty.optional(),
      model_provider: nonempty.optional(),
    })
    .catchall(z.json())
    .optional()
    .describe(
      "Native Codex overrides. Common key types are checked here; existing native and wrapper restrictions still apply.",
    ),
  limits: z
    .strictObject({
      maxCostUsdPerScan: ScanSettingsSchema.shape.maxCostUsd.describe(
        "Estimated USD limit per launched scan attempt, not a total batch budget. Omit for no limit.",
      ),
    })
    .optional(),
  policy: z
    .strictObject({
      failOnSeverity: FailureSeveritySchema.optional().describe(
        "Exit threshold; does not filter retained findings. Omit for report-only behavior.",
      ),
    })
    .optional(),
  output: z
    .strictObject({
      directory: ScanSettingsSchema.shape.outputDir.describe(
        "Artifact directory relative to this file; existing outside-worktree checks still apply.",
      ),
    })
    .optional(),
});

export type ProjectConfigInput = z.infer<typeof ProjectConfigInputSchema>;
export type ProjectScope = z.infer<typeof ProjectScopeSchema>;

export function projectConfigJsonSchema() {
  return {
    ...z.toJSONSchema(ProjectConfigInputSchema, {
      target: "draft-07",
      io: "input",
      unrepresentable: "throw",
    }),
    title: "Codex Security project configuration",
    description:
      "Input schema for explicitly selected YAML or JSON project files. Filesystem, active scan combinations, native configuration, and runtime availability are checked separately.",
    $comment:
      "Generated from ProjectConfigInputSchema. Defaults are annotations; apply defaults only after merging input layers.",
  };
}
