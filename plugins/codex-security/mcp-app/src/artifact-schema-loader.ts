import * as z from "zod/v4";

export type ArtifactSchemaObject = Record<string, unknown>;

export type SchemaDocument = ArtifactSchemaObject & {
  $id: string;
  $defs: Record<string, unknown>;
};

/**
 * Bundle checked-in Draft 2020-12 definitions for the existing MCP registry.
 */
export function bundleArtifactSchema(
  documents: readonly SchemaDocument[],
  documentId: string,
  definition: string
): ArtifactSchemaObject {
  const documentsById = new Map<string, SchemaDocument>();
  for (const document of documents) {
    if (documentsById.has(document.$id)) {
      throw new Error("Duplicate Codex Security schema document: " + document.$id);
    }
    documentsById.set(document.$id, document);
  }

  const document = documentsById.get(documentId);
  if (!document) {
    throw new Error("Unknown Codex Security schema document: " + documentId);
  }
  const source = document.$defs[definition];
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    throw new Error("Unknown Codex Security schema definition: " + definition);
  }
  return dereferenceArtifactSchema(
    source,
    document,
    documentsById,
    new Set<string>()
  ) as ArtifactSchemaObject;
}

/**
 * Keep checked-in JSON Schema, tool validation, and tools/list in agreement.
 */
export function loadArtifactZodSchema(
  documents: readonly SchemaDocument[],
  documentId: string,
  definition: string
): z.ZodType {
  return z.fromJSONSchema(
    bundleArtifactSchema(
      documents,
      documentId,
      definition
    ) as z.core.JSONSchema.JSONSchema
  );
}

function dereferenceArtifactSchema(
  value: unknown,
  document: SchemaDocument,
  documentsById: ReadonlyMap<string, SchemaDocument>,
  activeReferences: ReadonlySet<string>
): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => dereferenceArtifactSchema(
      item,
      document,
      documentsById,
      activeReferences
    ));
  }
  if (!value || typeof value !== "object") return value;

  const object = value as ArtifactSchemaObject;
  if (typeof object.$ref !== "string") {
    return Object.fromEntries(
      Object.entries(object).map(([name, child]) => [
        name,
        dereferenceArtifactSchema(child, document, documentsById, activeReferences)
      ])
    );
  }

  const reference = object.$ref;
  const separator = reference.indexOf("#");
  const referencedDocumentId = separator < 0
    ? reference
    : reference.slice(0, separator);
  const pointer = separator < 0 ? "" : reference.slice(separator + 1);
  const referencedDocument = referencedDocumentId
    ? documentsById.get(referencedDocumentId)
    : document;
  if (!referencedDocument) {
    throw new Error("Unknown Codex Security schema reference: " + reference);
  }

  const referenceKey = referencedDocument.$id + "#" + pointer;
  if (activeReferences.has(referenceKey)) {
    throw new Error("Cyclic Codex Security schema reference: " + reference);
  }
  const nextReferences = new Set(activeReferences);
  nextReferences.add(referenceKey);
  const resolved = dereferenceArtifactSchema(
    readSchemaPointer(referencedDocument, pointer),
    referencedDocument,
    documentsById,
    nextReferences
  );
  const siblings = Object.fromEntries(
    Object.entries(object).filter(([name]) => name !== "$ref")
  );
  if (Object.keys(siblings).length === 0) return resolved;
  if (!resolved || typeof resolved !== "object" || Array.isArray(resolved)) {
    throw new Error(
      "Codex Security schema reference cannot have sibling fields: " + reference
    );
  }
  return {
    ...resolved,
    ...dereferenceArtifactSchema(
      siblings,
      document,
      documentsById,
      activeReferences
    ) as ArtifactSchemaObject
  };
}

function readSchemaPointer(document: SchemaDocument, pointer: string): unknown {
  if (!pointer) return document;
  if (!pointer.startsWith("/")) {
    throw new Error("Invalid Codex Security schema pointer: #" + pointer);
  }

  let value: unknown = document;
  for (const encoded of pointer.slice(1).split("/")) {
    const key = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (
      !value
      || typeof value !== "object"
      || !Object.hasOwn(value, key)
    ) {
      throw new Error("Unknown Codex Security schema pointer: #" + pointer);
    }
    value = (value as ArtifactSchemaObject)[key];
  }
  return value;
}
