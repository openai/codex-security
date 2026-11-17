import { createHash } from "node:crypto";
import { z } from "zod";
import type { JsonObject } from "./config.js";
import type { DependencyAttemptStore } from "./dependency-attempt-store.js";
import {
  readDependencyEvidence,
  type DependencyExcerpt,
} from "./dependency-reachability.js";
import {
  dependencyGitCommitSchema,
  type DependencySourceIdentityReader,
} from "./dependency-source-identity.js";
import { CodexSecurityError } from "./errors.js";

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

/** Capture the cited ranges before committing the note and its operation receipt. */
export async function prepareDependencySourceNote(
  repository: string,
  value: unknown,
  options: {
    signal?: AbortSignal;
    readSourceIdentity?: DependencySourceIdentityReader;
    targetSha?: string;
    logicalRepository?: string;
  } = {},
) {
  const { question, scope, claim, evidence } =
    dependencySourceNoteSchema.parse(value);
  const excerpts: (Omit<DependencyExcerpt, "sourceIdentity"> & {
    sourceIdentity?: JsonObject;
  })[] = [];
  const warnings: string[] = [];
  const ranges = evidence.map((range) => {
    if (options.targetSha && range.commit && range.commit !== options.targetSha)
      throw new CodexSecurityError(
        "Source note commit differs from the investigation target.",
      );
    return {
      ...range,
      commit: range.commit ?? options.targetSha,
      supports: [],
    };
  });
  await readDependencyEvidence(
    ranges,
    repository,
    options.signal,
    ({ sourceIdentity, ...range }) => {
      excerpts.push({
        ...range,
        ...(sourceIdentity && {
          sourceIdentity: {
            ...sourceIdentity,
            // The same pinned blob can be checked out at different local paths.
            ...(options.targetSha && { repositoryRoot: null }),
          },
        }),
      });
    },
    options.readSourceIdentity,
    (path, startLine, requestedEnd, endLine) =>
      warnings.push(
        `Source note range ${path}:${startLine}-${requestedEnd} ended at line ${endLine}. Use the captured ranges.`,
      ),
  );
  options.signal?.throwIfAborted();
  const note = {
    ...(options.logicalRepository && { repository: options.logicalRepository }),
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
      ...(warnings.length && {
        ranges: excerpts.map(({ path, commit, startLine, endLine }) => ({
          path,
          ...(commit && { commit }),
          startLine,
          endLine,
        })),
        warnings,
      }),
    },
  };
}

type PreparedSourceNote = Awaited<
  ReturnType<typeof prepareDependencySourceNote>
>;

export function saveDependencySourceNote(
  attempt: DependencyAttemptStore,
  captured: PreparedSourceNote,
) {
  attempt.set("source-note", captured.note.id, captured.note);
  return captured.acknowledgement;
}

export function queryDependencySourceNotes(
  attempt: DependencyAttemptStore,
  value: unknown,
) {
  const { id, search } = dependencySourceNoteQuerySchema.parse(value);
  type Note = PreparedSourceNote["note"];
  const matches = (note: Note) =>
    search === undefined || JSON.stringify(note).includes(search);
  if (id !== undefined) {
    const note = attempt.get<Note>("source-note", id);
    return note && matches(note) ? note : null;
  }
  return attempt
    .values<Note>("source-note")
    .filter(matches)
    .map(({ id, investigator_assertion }) => ({
      id,
      ...investigator_assertion,
    }));
}
