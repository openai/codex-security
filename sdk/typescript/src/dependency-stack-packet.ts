import { createHash, randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { z } from "zod";
import {
  frozenDependencyAdvisorySchema,
  lookupDependencyAdvisory,
  type FrozenDependencyAdvisory,
} from "./dependency-advisory.js";
import type { DependencyProgressSink } from "./dependency-check-output.js";
import { errorMessage } from "./errors.js";
import {
  stackTriggerAnalysisSchema,
  validateStackTriggerAnalysis,
} from "./dependency-stack-advisory.js";
import { stackJsonValue } from "./dependency-stack-evidence.js";
import { dependencyGitCommitSchema } from "./dependency-source-identity.js";
import { readRegularInputFileBytes } from "./prompt-files.js";
import { canonicalJson } from "./record.js";
import { repositoryRevision } from "./targets.js";
import { compareTimestamps } from "./timestamps.js";

const text = z.string().min(1);
const timestamp = z.string().regex(z.regexes.datetime({ offset: true }));
const runtimeWindowSchema = z
  .strictObject({ start: timestamp, end: timestamp })
  .refine(
    ({ start, end }) => compareTimestamps(start, end) < 0,
    "Runtime scope start must precede end.",
  );

const cveId = z.string().regex(/^CVE-\d{4}-\d{4,}$/u);
const sha256 = z.string().regex(/^[0-9a-f]{64}$/u);
const target = z.strictObject({
  repository: text,
  sha: dependencyGitCommitSchema,
});
// Producers may attach further JSON metadata. The investigator addresses each
// endpoint by its stable ID and uses its named function to validate the sink.
const endpoint = z
  .object({ id: text, function: text })
  .catchall(stackJsonValue);
const advisory = z.strictObject({
  url: text,
  summary: text,
  revision: text.optional(),
});
const provenance = z.strictObject({
  source: text,
  revision: text.optional(),
  sha256: sha256.optional(),
});

export const stackSourcesSchema = z.strictObject({
  format: z.literal("codex-security.stack-sources/v1"),
  sources: z.array(endpoint),
  provenance: provenance.optional(),
});

// Optional replay fields. The catalog's advisory, version ranges and selectors
// remain intact regardless of what the public lookup or trigger review finds.
const frozenFields = {
  advisoryDetails: z.array(frozenDependencyAdvisorySchema).min(1).optional(),
  triggerAnalysis: stackTriggerAnalysisSchema.optional(),
};

export const stackSinksSchema = z.strictObject({
  format: z.literal("codex-security.stack-sinks/v1"),
  cve: cveId,
  advisory,
  ...frozenFields,
  sinks: z
    .array(
      endpoint.extend({
        package: text,
        versionScheme: text,
        affectedVersions: z.array(text).min(1),
        preconditions: z.array(text),
      }),
    )
    .min(1),
  provenance: provenance.optional(),
});

const workload = z.strictObject({
  environment: text.optional(),
  cluster: text.optional(),
  service: text.optional(),
  container: text.optional(),
  image_name: text.optional(),
  image_tag: text.nullish(),
  image_tags: z.array(text).optional(),
  image_digest: text.optional(),
});

const frame = z.strictObject({
  name: z.string(),
  type: z.string(),
  location: z.string().optional(),
  line: z.int().positive().optional(),
  binary: z.string().optional(),
  buildId: z.string().optional(),
  buildHash: z.string().optional(),
  offset: z
    .union([z.int().nonnegative(), z.string().regex(/^\d+$/u)])
    .optional()
    .describe(
      "Use a decimal string for offsets above the safe JSON integer range.",
    ),
});

const sourceRange = z
  .strictObject({
    path: text,
    startLine: z.int().positive(),
    endLine: z.int().positive(),
  })
  .refine(
    (range) => range.endLine >= range.startLine,
    "Reversed evidence range.",
  );

const observation = z
  .strictObject({
    id: text,
    stackHash: text.describe("Opaque producer stack reference."),
    provenance: provenance.optional(),
    sourceIndex: z.int().nonnegative().optional(),
    sinkIndex: z.int().nonnegative().nullable(),
    sinkIds: z
      .array(text)
      .optional()
      .describe("Catalog sinks matched at the queried sinkIndex."),
    sinkMatches: z
      .array(
        z.strictObject({
          sinkId: text,
          rawIndex: z.int().nonnegative(),
        }),
      )
      .optional()
      .describe(
        "Catalog sink matches at their original zero-based leaf-first indices.",
      ),
    framesTruncated: z.boolean().nullable(),
    frames: z.array(frame),
    scope: workload.optional(),
    observedAt: z.iso.datetime({ offset: true }).optional(),
    bindings: z
      .array(
        z.strictObject({
          package: text,
          version: text,
          provenance: text,
          frameIndices: z
            .array(z.int().nonnegative())
            .optional()
            .describe(
              "Original zero-based frames executed by this package copy, as established by the capture producer. Omit or leave empty when only the workload or build is known.",
            ),
          imageDigest: text.optional(),
          sourceSha: dependencyGitCommitSchema.optional(),
          evidence: z.array(sourceRange).optional(),
        }),
      )
      .optional(),
  })
  .superRefine((value, ctx) => {
    for (const [i, binding] of (value.bindings ?? []).entries()) {
      for (const [j, rawIndex] of (binding.frameIndices ?? []).entries()) {
        if (rawIndex >= value.frames.length)
          ctx.addIssue({
            code: "custom",
            path: ["bindings", i, "frameIndices", j],
            message: "Package binding index is outside the captured frames.",
          });
      }
    }
    if (value.sinkIndex === null && value.sinkIds?.length) {
      ctx.addIssue({
        code: "custom",
        path: ["sinkIds"],
        message:
          "A shorthand catalog match requires a captured query sink index.",
      });
    }
    for (const [index, match] of (value.sinkMatches ?? []).entries()) {
      if (match.rawIndex >= value.frames.length) {
        ctx.addIssue({
          code: "custom",
          path: ["sinkMatches", index, "rawIndex"],
          message: "Catalog sink index is outside the captured frames.",
        });
      }
      if (
        value.sinkIds?.includes(match.sinkId) &&
        match.rawIndex !== value.sinkIndex
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["sinkMatches", index],
          message:
            "Shorthand and explicit catalog indices disagree. List the matches explicitly.",
        });
      }
    }
    if (!value.frames.length && value.framesTruncated === false) {
      ctx.addIssue({
        code: "custom",
        path: ["frames"],
        message: "A complete observed stack must contain a frame.",
      });
    }
    if (value.sinkIndex !== null && value.sinkIndex >= value.frames.length) {
      ctx.addIssue({
        code: "custom",
        path: ["sinkIndex"],
        message: "Sink index is outside the captured frames.",
      });
    }
    if (
      value.sourceIndex !== undefined &&
      ((value.sinkIndex !== null && value.sourceIndex <= value.sinkIndex) ||
        value.sourceIndex >= value.frames.length)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["sourceIndex"],
        message:
          "A leaf-first source must follow the sink within the captured frames.",
      });
    }
  });

const captureStatus = z.enum(["observed", "no_match", "no_coverage"]);

export const sampledStacksSchema = z.strictObject({
  format: z.literal("codex-security.sampled-stacks/v1"),
  target,
  origin: provenance,
  frameOrder: z.literal("leaf_first"),
  queries: z
    .array(
      z.strictObject({
        id: text,
        provenance: provenance.optional(),
        scope: workload.extend({
          window: runtimeWindowSchema,
        }),
        selectors: z.strictObject({
          sources: z.array(stackJsonValue),
          sinks: z.array(stackJsonValue).min(1),
        }),
        groups: z
          .array(
            z
              .strictObject({
                id: text,
                scope: workload.optional(),
                status: captureStatus,
                truncated: z.boolean().nullable(),
                observations: z.array(observation),
              })
              .refine(
                (group) =>
                  (group.status === "observed") ===
                  group.observations.length > 0,
                "Observed groups require observations. Use an empty list for no_match or no_coverage.",
              ),
          )
          .min(1),
      }),
    )
    .min(1),
});

const roles = ["sources", "sinks", "stacks"] as const;
type Role = (typeof roles)[number];
const file = z.strictObject({ byteLength: z.int().nonnegative(), sha256 });
const manifestContent = z.strictObject({
  format: z.literal("codex-security.stack-manifest/v1"),
  cve: cveId,
  advisory,
  ...frozenFields,
  advisoryLookupError: text.optional(),
  target,
  toolRevision: text,
  files: z.strictObject({ sources: file, sinks: file, stacks: file }),
});

export const stackManifestSchema = manifestContent.extend({
  inputDigest: sha256,
  runId: text,
  attemptId: text,
});

export type StackManifest = z.infer<typeof stackManifestSchema>;
export type StackObservation = z.infer<typeof observation>;
export type StackFrame = z.infer<typeof frame>;
export interface StackPacket {
  manifest: StackManifest;
  sources: z.infer<typeof stackSourcesSchema>;
  sinks: z.infer<typeof stackSinksSchema>;
  stacks: z.infer<typeof sampledStacksSchema>;
}
type CaptureScope = StackPacket["stacks"]["queries"][number]["scope"];
type Workload = z.infer<typeof workload>;
export interface StackWorkItem {
  id: string;
  queryId: string;
  groupId: string;
  status: z.infer<typeof captureStatus>;
  scope: CaptureScope;
  queryScope: CaptureScope;
  groupScope?: Workload;
  scopeConflicts: string[];
  selectors: StackPacket["stacks"]["queries"][number]["selectors"];
  origin: StackPacket["stacks"]["origin"];
  queryProvenance?: StackPacket["stacks"]["origin"];
  truncated: boolean | null;
  observation: StackObservation | null;
}

function pointerPart(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

/** Effective catalog matches retain the producer's raw frame indices. */
export function stackSinkMatches(observation: StackObservation) {
  const matches = new Map<string, { sinkId: string; rawIndex: number }>();
  const add = (sinkId: string, rawIndex: number) => {
    matches.set(rawIndex + ":" + sinkId, { sinkId, rawIndex });
  };
  for (const match of observation.sinkMatches ?? [])
    add(match.sinkId, match.rawIndex);
  if (observation.sinkIndex !== null)
    for (const sinkId of observation.sinkIds ?? [])
      add(sinkId, observation.sinkIndex);
  return [...matches.values()];
}

function scopeConflicts(
  query: CaptureScope,
  group?: Workload,
  captured?: StackObservation | null,
): string[] {
  const layers = [
    { name: "query", scope: query },
    { name: "group", scope: group },
    { name: "observation", scope: captured?.scope },
  ];
  const conflicts: string[] = [];
  const observedAt = captured?.observedAt;
  if (
    observedAt &&
    (compareTimestamps(observedAt, query.window.start) < 0 ||
      compareTimestamps(observedAt, query.window.end) > 0)
  ) {
    conflicts.push(
      `observedAt: ${observedAt} falls outside the query window ${query.window.start} to ${query.window.end}.`,
    );
  }
  for (const field of [
    "environment",
    "cluster",
    "service",
    "container",
    "image_name",
    "image_digest",
  ] as const) {
    const bound = layers.flatMap(({ name, scope }) =>
      scope?.[field] === undefined ? [] : [{ name, value: scope[field] }],
    );
    if (new Set(bound.map((b) => b.value)).size > 1) {
      conflicts.push(
        `${field}: ${bound.map((b) => `${b.name}=${JSON.stringify(b.value)}`).join(", ")}`,
      );
    }
  }
  const tagFilters: { name: string; tags: string[] }[] = [];
  for (const { name, scope } of layers) {
    if (!scope) continue;
    const tag = scope.image_tag;
    const allowed = scope.image_tags ?? [];
    if (tag && allowed.length && !allowed.includes(tag)) {
      conflicts.push(
        `image_tag: ${name} tag ${JSON.stringify(tag)} is outside its tag set ${JSON.stringify(allowed)}.`,
      );
    }
    const tags = tag ? [tag] : allowed;
    if (!tags.length) continue;
    for (const outer of tagFilters) {
      if (tags.some((t) => !outer.tags.includes(t))) {
        conflicts.push(
          `image_tag: ${name} identifies ${JSON.stringify(tags)} outside ${outer.name} selection ${JSON.stringify(outer.tags)}.`,
        );
      }
    }
    tagFilters.push({ name, tags });
  }
  return conflicts;
}

export function stackPacketWorkItems(packet: StackPacket): StackWorkItem[] {
  return packet.stacks.queries.flatMap((query) =>
    query.groups.flatMap((group) => {
      const groupId = [query.id, group.id].map(pointerPart).join("/");
      const observations = group.observations.length
        ? group.observations
        : [null];
      return observations.map((observation): StackWorkItem => ({
        id: observation ? groupId + "/" + pointerPart(observation.id) : groupId,
        queryId: query.id,
        groupId: group.id,
        selectors: query.selectors,
        origin: packet.stacks.origin,
        ...(query.provenance && { queryProvenance: query.provenance }),
        queryScope: query.scope,
        ...(group.scope && { groupScope: group.scope }),
        scope: { ...query.scope, ...group.scope, ...observation?.scope },
        scopeConflicts: scopeConflicts(query.scope, group.scope, observation),
        status: group.status,
        truncated: group.truncated,
        observation,
      }));
    }),
  );
}

export function stackFramesRootFirst(observation: StackObservation) {
  return observation.frames
    .map((frame, rawIndex) => ({ frame, rawIndex }))
    .reverse();
}

function uniqueIds(values: readonly { id: string }[], kind: string) {
  const ids = new Set<string>();
  for (const { id } of values) {
    if (ids.has(id)) throw new Error(`Duplicate ${kind} ID: ${id}.`);
    ids.add(id);
  }
}

type Paths = Record<Role, string>;
type Bytes = Record<Role, Buffer>;

async function loadFiles(paths: Paths, repository: string): Promise<Bytes> {
  const read = (path: string) =>
    readRegularInputFileBytes(resolve(path), repository);
  const [sources, sinks, stacks] = await Promise.all([
    read(paths.sources),
    read(paths.sinks),
    read(paths.stacks),
  ]);
  return { sources, sinks, stacks };
}

function parseJson(bytes: Buffer, name: string): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(
      `Invalid JSON in ${name}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

/** These packet schemas validate the wire input without defaults or coercion.
 * Keep the decoded document so opaque metadata retains every original JSON key. */
function readDocument<T>(schema: z.ZodType<T>, bytes: Buffer, name: string): T {
  const original = parseJson(bytes, name);
  schema.parse(original);
  return original as T;
}

function hash(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function fileIdentity(bytes: Buffer) {
  return { byteLength: bytes.length, sha256: hash(bytes) };
}

async function decodeFiles(
  bytes: Bytes,
  cve: string,
  repository: string,
  signal?: AbortSignal,
) {
  const sources = readDocument(
    stackSourcesSchema,
    bytes.sources,
    "sources.json",
  );
  const sinks = readDocument(stackSinksSchema, bytes.sinks, "sinks.json");
  const stacks = readDocument(sampledStacksSchema, bytes.stacks, "stacks.json");
  if (sinks.cve !== cve)
    throw new Error(
      `The supplied sinks describe ${sinks.cve}, expected ${cve}.`,
    );
  uniqueIds([...sources.sources, ...sinks.sinks], "endpoint");
  const sinkIds = new Set(sinks.sinks.map((sink) => sink.id));
  uniqueIds(stacks.queries, "query");
  for (const query of stacks.queries) {
    uniqueIds(query.groups, "group");
    for (const group of query.groups) {
      uniqueIds(group.observations, "observation");
      for (const row of group.observations) {
        for (const { sinkId: id } of stackSinkMatches(row)) {
          if (!sinkIds.has(id))
            throw new Error(
              `Unknown catalog sink on observation ${row.id}: ${id}.`,
            );
        }
      }
    }
  }
  const actual = await repositoryRevision(repository, signal);
  if (actual !== stacks.target.sha)
    throw new Error(
      `Target checkout HEAD is ${actual ?? "unavailable"}, expected ${stacks.target.sha}.`,
    );
  return { sources, sinks, stacks };
}

type AdvisorySnapshot = Pick<
  StackManifest,
  "advisoryDetails" | "advisoryLookupError" | "triggerAnalysis"
>;

function validateSnapshot(
  sinks: StackPacket["sinks"],
  snapshot: AdvisorySnapshot,
) {
  const { advisoryDetails, triggerAnalysis, advisoryLookupError } = snapshot;
  if (advisoryDetails) {
    if (advisoryLookupError)
      throw new Error("Cannot supply advisory records and a failed lookup.");
    uniqueIds(advisoryDetails, "advisory");
    for (const record of advisoryDetails)
      if (record.id !== sinks.cve && !record.aliases?.includes(sinks.cve))
        throw new Error(
          `Advisory ${record.id} does not identify ${sinks.cve}.`,
        );
  }
  if (triggerAnalysis) {
    if (!advisoryDetails)
      throw new Error("Trigger analysis requires the frozen advisory records.");
    validateStackTriggerAnalysis(
      { cve: sinks.cve, sinks: sinks.sinks, advisoryDetails },
      triggerAnalysis,
    );
  }
}

interface StackAdvisoryHost {
  analyze(
    sinks: StackPacket["sinks"],
    advisoryDetails: FrozenDependencyAdvisory[],
  ): Promise<NonNullable<StackManifest["triggerAnalysis"]>>;
  emit?: DependencyProgressSink;
  lookupCve?: typeof lookupDependencyAdvisory;
}

async function resolveSnapshot(
  sinks: StackPacket["sinks"],
  host: StackAdvisoryHost,
  signal?: AbortSignal,
): Promise<AdvisorySnapshot> {
  const { cve, triggerAnalysis } = sinks;
  let { advisoryDetails } = sinks;
  if (!advisoryDetails) {
    host.emit?.("advisory", cve, { stage: "osv" });
    try {
      // Only the CVE identifier leaves the host. Never follow a catalog URL,
      // or include source code, workload metadata or sampled frames in lookup.
      const issue = await (host.lookupCve ?? lookupDependencyAdvisory)(
        cve,
        signal,
      );
      advisoryDetails = issue.advisories;
    } catch (error) {
      signal?.throwIfAborted();
      const advisoryLookupError = errorMessage(error);
      host.emit?.("advisory_lookup_failed", cve, {
        error: advisoryLookupError,
      });
      return { advisoryLookupError };
    }
  }
  signal?.throwIfAborted();
  host.emit?.("advisories_loaded", cve, { count: advisoryDetails.length });
  return {
    advisoryDetails,
    triggerAnalysis:
      triggerAnalysis ?? (await host.analyze(sinks, advisoryDetails)),
  };
}

function manifestFields(
  packet: Omit<StackPacket, "manifest">,
  toolRevision: string,
  files: StackManifest["files"],
  snapshot: AdvisorySnapshot,
) {
  validateSnapshot(packet.sinks, snapshot);
  const fields = manifestContent.parse({
    format: "codex-security.stack-manifest/v1",
    cve: packet.sinks.cve,
    advisory: packet.sinks.advisory,
    ...(snapshot.advisoryDetails && {
      advisoryDetails: snapshot.advisoryDetails,
    }),
    ...(snapshot.advisoryLookupError && {
      advisoryLookupError: snapshot.advisoryLookupError,
    }),
    ...(snapshot.triggerAnalysis && {
      triggerAnalysis: snapshot.triggerAnalysis,
    }),
    target: packet.stacks.target,
    toolRevision,
    files,
  });
  for (const field of ["advisoryDetails", "triggerAnalysis"] as const)
    if (
      packet.sinks[field] &&
      canonicalJson(fields[field]) !== canonicalJson(packet.sinks[field])
    )
      throw new Error(`Frozen ${field} does not match the supplied sinks.`);
  return fields;
}

export async function prepareStackPacket(options: {
  cve: string;
  sourcesPath: string;
  sinksPath: string;
  stacksPath: string;
  inputsDir: string;
  repository: string;
  toolRevision: string;
  runId?: string;
  attemptId?: string;
  signal?: AbortSignal;
}): Promise<StackPacket> {
  // The public packet API and run init must remain usable without any model
  // or network access. Only high-level checks opt in to fresh resolution.
  return prepareStackCheckPacket(options);
}

export async function prepareStackCheckPacket(
  options: Parameters<typeof prepareStackPacket>[0],
  host?: StackAdvisoryHost,
): Promise<StackPacket> {
  const bytes = await loadFiles(
    {
      sources: options.sourcesPath,
      sinks: options.sinksPath,
      stacks: options.stacksPath,
    },
    options.repository,
  );
  const documents = await decodeFiles(
    bytes,
    cveId.parse(options.cve),
    options.repository,
    options.signal,
  );
  options.signal?.throwIfAborted();
  const files = {
    sources: fileIdentity(bytes.sources),
    sinks: fileIdentity(bytes.sinks),
    stacks: fileIdentity(bytes.stacks),
  };
  // Verify that the supplied snapshot survives manifest parsing before any
  // lookup or analysis. Reopening the packet performs the same comparison.
  let fields = manifestFields(
    documents,
    options.toolRevision,
    files,
    documents.sinks,
  );
  if (host) {
    const snapshot = await resolveSnapshot(
      documents.sinks,
      host,
      options.signal,
    );
    options.signal?.throwIfAborted();
    fields = manifestFields(documents, options.toolRevision, files, snapshot);
  }
  const manifest = stackManifestSchema.parse({
    ...fields,
    inputDigest: hash(canonicalJson(fields)),
    runId: options.runId ?? randomUUID(),
    attemptId: options.attemptId ?? randomUUID(),
  });
  await mkdir(options.inputsDir, { mode: 0o700 });
  try {
    for (const role of roles) {
      await writeFile(join(options.inputsDir, role + ".json"), bytes[role], {
        flag: "wx",
        mode: 0o400,
        signal: options.signal,
      });
    }
    // Publish the manifest after all of the original documents are present.
    await writeFile(
      join(options.inputsDir, "manifest.json"),
      JSON.stringify(manifest, null, 2) + "\n",
      { flag: "wx", mode: 0o400, signal: options.signal },
    );
  } catch (error) {
    await rm(options.inputsDir, { recursive: true, force: true });
    throw error;
  }
  return { manifest, ...documents };
}

export async function readStackPacket(
  inputsDir: string,
  repository: string,
  signal?: AbortSignal,
): Promise<StackPacket> {
  const read = await readRegularInputFileBytes(
    join(resolve(inputsDir), "manifest.json"),
    repository,
  );
  const manifest = stackManifestSchema.parse(parseJson(read, "manifest.json"));
  const bytes = await loadFiles(
    {
      sources: join(inputsDir, "sources.json"),
      sinks: join(inputsDir, "sinks.json"),
      stacks: join(inputsDir, "stacks.json"),
    },
    repository,
  );
  for (const role of roles) {
    if (
      bytes[role].length !== manifest.files[role].byteLength ||
      hash(bytes[role]) !== manifest.files[role].sha256
    ) {
      throw new Error(`Packet size or SHA-256 mismatch for ${role}.json.`);
    }
  }
  const documents = await decodeFiles(bytes, manifest.cve, repository, signal);
  const fields = manifestFields(
    documents,
    manifest.toolRevision,
    manifest.files,
    manifest,
  );
  if (
    manifest.inputDigest !== hash(canonicalJson(fields)) ||
    canonicalJson(manifest.target) !== canonicalJson(fields.target) ||
    canonicalJson(manifest.advisory) !== canonicalJson(fields.advisory)
  )
    throw new Error(
      "Manifest does not match the supplied investigation inputs.",
    );
  return { manifest, ...documents };
}

/** Published schema for the four independently versioned packet documents. */
export function stackPacketJsonSchema() {
  return z.toJSONSchema(
    z.union([
      stackSourcesSchema,
      stackSinksSchema,
      sampledStacksSchema,
      stackManifestSchema,
    ]),
    { reused: "ref", io: "input" },
  );
}
