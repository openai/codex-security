import { isRecord } from "../record.js";
import { z } from "zod";

const requiredString = z.string().min(1);
// The workbench accepts integer numbers outside JavaScript's safe integer range.
const nonNegativeInteger = z.number().refine(Number.isInteger).nonnegative();
const positiveInteger = z.number().refine(Number.isInteger).positive();
const optionalValue = <T extends z.ZodType>(schema: T) =>
  schema.optional().catch(undefined);
// Keep absent optional fields as own properties, matching persisted run/worker records.
const responseObject = <T extends z.ZodRawShape>(shape: T) =>
  z.object(shape).transform((value) => {
    for (const key of Object.keys(shape)) {
      if (!(key in value)) Object.assign(value, { [key]: undefined });
    }
    return value;
  });
const optionalString = optionalValue(requiredString);

export const workerSchema = responseObject({
  id: requiredString,
  kind: z.enum(["setup", "discovery", "dedup"]),
  status: z.enum(["queued", "running", "succeeded", "failed", "canceled"]),
  mergeState: z.enum(["none", "buffered", "merging", "merged"]),
  promptPath: requiredString,
  artifactDir: requiredString,
  attempt: nonNegativeInteger,
  sdkThreadId: optionalString,
  resultManifestPath: optionalString,
  completionSequence: optionalValue(positiveInteger),
  error: optionalString,
}).transform(
  ({ sdkThreadId, ...worker }): typeof worker & { threadId?: string } => ({
    ...worker,
    threadId: sdkThreadId,
  }),
);

export const dedupInputSchema = z.object({
  dedupWorkerId: requiredString,
  discoveryWorkerId: requiredString,
  inputOrder: nonNegativeInteger,
});

export const configSchema = z
  .object({
    stopAfterNoNew: positiveInteger,
    workers: positiveInteger,
    subagents: nonNegativeInteger,
    stopAfterConsecutiveErrors: positiveInteger.nullish(),
    maxDiscoveryRuns: positiveInteger,
    maxTimeHours: z.number().positive().max(96).optional(),
  })
  .transform(({ stopAfterConsecutiveErrors, maxTimeHours, ...config }) => ({
    ...config,
    stopAfterConsecutiveErrors:
      stopAfterConsecutiveErrors ?? config.stopAfterNoNew,
    ...(maxTimeHours === undefined ? {} : { maxTimeHours }),
  }));

// Check the config object before status, then its fields before the run fields.
export const runSchema = z
  .looseObject({ config: z.looseObject({}) })
  .pipe(
    responseObject({
      status: z.enum(
        ["running", "succeeded", "canceled", "failed", "interrupted"],
        {
          error: ({ input }) =>
            typeof input === "string" && input
              ? `Unsupported Deep Scan status: ${input}`
              : undefined,
        },
      ),
      config: configSchema,
      includePaths: z.array(z.string()).optional(),
      filePaths: z.array(z.string()).optional(),
      scanId: requiredString,
      coordinatorGeneration: optionalValue(positiveInteger),
      createdAt: optionalString,
      updatedAt: optionalString,
      targetPath: requiredString,
      scope: requiredString,
      userContext: optionalString,
      scanDir: requiredString,
      dispatchedCount: nonNegativeInteger,
      noNewStreak: nonNegativeInteger,
      consecutiveErrors: nonNegativeInteger
        .nullish()
        .transform((value) => value ?? 0),
      manifestPath: optionalString,
      evidenceRepairRequired: z.literal(true).optional(),
      terminalReason: optionalValue(z.enum(["saturated", "capped"])),
      error: optionalString,
      workers: z
        .array(workerSchema)
        .nullish()
        .transform((value) => value ?? []),
      dedupInputs: z
        .array(dedupInputSchema)
        .nullish()
        .transform((value) => value ?? []),
    }),
  )
  .transform(({ workers, dedupInputs, evidenceRepairRequired, ...run }) => ({
    ...run,
    ...(evidenceRepairRequired ? { evidenceRepairRequired } : {}),
    persistedWorkers: workers,
    persistedDedupInputs: dedupInputs,
  }));

function parseResponse<T extends z.ZodType>(
  schema: T,
  value: unknown,
  field = "deepScan",
): z.output<T> {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  const issue = result.error.issues[0];
  if (issue.path[0] === "includePaths" || issue.path[0] === "filePaths")
    throw new Error(`deepScan.${issue.path[0]} must be an array of paths.`);
  const path = [field, ...issue.path]
    .join(".")
    .replace(/workers\.\d+/g, "worker")
    .replace(/dedupInputs\.\d+/g, "dedupInput");
  throw new Error(
    issue.message.startsWith("Unsupported Deep Scan status:")
      ? issue.message
      : `Codex Security workbench ${issue.code === "invalid_type" && issue.expected === "object" ? "did not return" : "returned invalid"} ${path}.`,
  );
}

export function parseDeepScan(result: Record<string, unknown>) {
  return parseResponse(runSchema, result.deepScan);
}

export function parseWorker(result: Record<string, unknown>, workerId: string) {
  const deepScan = parseResponse(z.looseObject({}), result.deepScan);
  if (!Array.isArray(deepScan.workers)) {
    throw new Error(
      "Codex Security workbench did not return deepScan.workers.",
    );
  }
  const value = deepScan.workers.find(
    (candidate) => isRecord(candidate) && candidate.id === workerId,
  );
  if (!value) {
    throw new Error(
      `Codex Security workbench did not return Deep Scan worker ${workerId}.`,
    );
  }
  const worker = parseResponse(workerSchema, value, "deepScan.worker");
  return deepScan.consecutiveErrors === undefined
    ? worker
    : {
        ...worker,
        consecutiveErrors: parseResponse(
          nonNegativeInteger,
          deepScan.consecutiveErrors,
          "deepScan.consecutiveErrors",
        ),
      };
}
