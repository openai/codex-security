import { z } from "zod";
import { createHash } from "node:crypto";
import type { DependencyAttemptStore } from "./dependency-attempt-store.js";
import {
  dependencyGitCommitSchema,
  readDependencySourceCitation,
} from "./dependency-source-identity.js";
import { isRecord } from "./record.js";
import { CodexSecurityError } from "./errors.js";

// z.json() validates all JSON types, but its parsed records drop the literal
// "__proto__" key. Keep the original JSON when recording immutable evidence.
const jsonTypes = z.json();
export const stackJsonValue = z
  .unknown()
  .refine(
    (value): value is import("./config.js").JsonValue =>
      jsonTypes.safeParse(value).success,
    "Expected a JSON value.",
  );

function receiptSelection(receiptId: z.ZodString) {
  return z.strictObject({
    receiptId,
    textBlock: z.number().int().nonnegative().nullable(),
    record: z.array(z.union([z.string(), z.number().int().nonnegative()])),
  });
}

// Inventory imports normalize IDs. Graph selections retain the original ID.
export const dependencyReceiptSelectionSchema = receiptSelection(
  z.string().min(1),
);
export const inventoryReceiptSelectionSchema = receiptSelection(
  z.string().trim().min(1),
);
export type DependencyReceiptSelection = z.infer<
  typeof dependencyReceiptSelectionSchema
>;
export type DependencyInventoryReceiptSelection = z.infer<
  typeof inventoryReceiptSelectionSchema
>;

export interface BoundDependencyInventoryReceipt {
  receiptId: string;
  key: string;
  server: string;
  originalPayloadSha256: string;
  origin: { tool: string; arguments: Record<string, unknown> };
  selection?: Omit<DependencyInventoryReceiptSelection, "receiptId">;
  result: unknown;
}

export function inventoryJsonField(
  value: unknown,
  path: readonly (string | number)[],
): unknown {
  for (const key of path) {
    if (typeof key === "number" && Array.isArray(value)) value = value[key];
    else if (
      typeof key === "string" &&
      isRecord(value) &&
      Object.hasOwn(value, key)
    )
      value = value[key];
    else return undefined;
  }
  return value;
}
export const dependencySourceNoteSchema = z.strictObject({
  question: z.string().trim().min(1),
  scope: z.string().trim().min(1),
  claim: z.string().trim().min(1),
  evidence: z
    .array(
      z.strictObject({
        path: z.string().trim().min(1),
        commit: dependencyGitCommitSchema.optional(),
        startLine: z.number().int().positive(),
        endLine: z.number().int().positive(),
      }),
    )
    .min(1),
});
export const dependencySourceNoteQuerySchema = z.strictObject({
  id: z.string().trim().min(1).optional(),
  search: z.string().trim().min(1).optional(),
});

interface Range {
  path: string;
  commit?: string | undefined;
  startLine: number;
  endLine: number;
}
export interface DependencyExcerpt extends Range {
  text: string;
  sourceIdentity: {
    kind: "git";
    status: "verified";
    repositoryRoot: null;
    repositoryPath: string;
    commit: string;
    blob: string;
    contentSha256: string;
  };
}

export async function readDependencyClaimExcerpts(
  ranges: readonly Range[],
  repository: string,
  signal?: AbortSignal,
  warnings?: string[],
): Promise<DependencyExcerpt[]> {
  const excerpts = new Map<string, DependencyExcerpt>();
  for (const range of ranges) {
    if (!range.commit)
      throw new CodexSecurityError(
        "A source citation requires a pinned Git revision.",
      );
    const citation = await readDependencySourceCitation(
      repository,
      range.commit,
      range,
      signal,
    );
    const { path, commit, blob, contentSha256, startLine, endLine } = citation;
    if (endLine !== range.endLine) {
      if (!warnings)
        throw new CodexSecurityError(
          `Invalid evidence range ${path}:${startLine}-${range.endLine}.`,
        );
      warnings.push(
        `Source note range ${path}:${startLine}-${range.endLine} ended at line ${endLine}. Use the captured ranges.`,
      );
    }
    excerpts.set(JSON.stringify([path, commit, startLine, endLine]), {
      path,
      commit,
      startLine,
      endLine,
      text: citation.excerpt.replace(/\n$/u, ""),
      sourceIdentity: {
        kind: "git",
        status: "verified",
        repositoryRoot: null,
        repositoryPath: path,
        commit,
        blob,
        contentSha256,
      },
    });
  }
  return [...excerpts.values()];
}

export async function prepareDependencySourceNote(
  repository: string,
  input: unknown,
  options: {
    targetSha: string;
    logicalRepository?: string;
    signal?: AbortSignal;
  },
) {
  const { question, scope, claim, evidence } =
    dependencySourceNoteSchema.parse(input);
  const ranges = evidence.map((range) => {
    if (range.commit && range.commit !== options.targetSha)
      throw new CodexSecurityError(
        "Source note commit differs from the investigation target.",
      );
    return { ...range, commit: options.targetSha };
  });
  const warnings: string[] = [];
  const excerpts = await readDependencyClaimExcerpts(
    ranges,
    repository,
    options.signal,
    warnings,
  );
  const note = {
    ...(options.logicalRepository !== undefined && {
      repository: options.logicalRepository,
    }),
    investigator_assertion: { question, scope, claim },
    excerpts,
  };
  const id =
    "source-evidence-" +
    createHash("sha256").update(JSON.stringify(note)).digest("hex");
  return {
    note: { id, ...note },
    acknowledgement: {
      id,
      ...(warnings.length
        ? {
            warnings,
            ranges: excerpts.map(({ path, commit, startLine, endLine }) => ({
              path,
              commit,
              startLine,
              endLine,
            })),
          }
        : {}),
    },
  };
}

export function saveDependencySourceNote(
  store: DependencyAttemptStore,
  saved: Awaited<ReturnType<typeof prepareDependencySourceNote>>,
) {
  store.set("source-note", saved.note.id, saved.note);
  return saved.acknowledgement;
}

export function queryDependencySourceNotes(
  store: DependencyAttemptStore,
  raw: unknown,
) {
  const { id, search } = dependencySourceNoteQuerySchema.parse(raw);
  type Note = Awaited<ReturnType<typeof prepareDependencySourceNote>>["note"];
  const matches = (note: Note) =>
    search === undefined || JSON.stringify(note).includes(search);
  if (id !== undefined) {
    const note = store.get<Note>("source-note", id);
    return note && matches(note) ? note : null;
  }
  return store
    .values<Note>("source-note")
    .filter(matches)
    .map(({ id, investigator_assertion }) => ({
      id,
      ...investigator_assertion,
    }));
}
