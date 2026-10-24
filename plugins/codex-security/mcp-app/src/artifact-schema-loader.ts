import * as z from "zod/v4";

export type ArtifactSchemaObject = Record<string, unknown>;

/** Project a native contract for tools/list while preserving its validator and type. */
export function projectArtifactToolSchema<Schema extends z.ZodType>(
  schema: Schema,
): Schema {
  return schema.meta(
    modelFacingSchema(z.toJSONSchema(schema, { io: "input" })),
  );
}

/** Keep forbidden fields out of native tool declarations without allowing them. */
function modelFacingSchema(schema: ArtifactSchemaObject): ArtifactSchemaObject {
  function visit(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(visit);
    if (!value || typeof value !== "object") return value;
    const object = Object.fromEntries(
      Object.entries(value).map(([key, child]) => [
        key,
        ["const", "enum", "default", "examples"].includes(key)
          ? child
          : visit(child),
      ]),
    );
    const properties = object.properties;
    if (
      !properties ||
      typeof properties !== "object" ||
      Array.isArray(properties)
    )
      return object;
    const forbidden = Object.entries(properties)
      .filter(([, property]) => forbiddenProperty(property))
      .map(([name]) => name);
    if (forbidden.length === 0) return object;

    // Zod renders false properties as {not:{}}, which the native declaration
    // projects as optional unknown fields. Exclude their names instead. This
    // is equivalent JSON Schema; the original validator remains unchanged.
    object.properties = Object.fromEntries(
      Object.entries(properties).filter(
        ([, property]) => !forbiddenProperty(property),
      ),
    );
    const names = { not: { enum: forbidden } };
    object.propertyNames =
      object.propertyNames === undefined
        ? names
        : { allOf: [object.propertyNames, names] };
    return object;
  }
  return visit(schema) as ArtifactSchemaObject;
}

function forbiddenProperty(property: unknown): boolean {
  if (property === false) return true;
  if (!property || typeof property !== "object" || Array.isArray(property))
    return false;
  const not = (property as ArtifactSchemaObject).not;
  return (
    Object.keys(property).length === 1 &&
    not !== null &&
    typeof not === "object" &&
    !Array.isArray(not) &&
    Object.keys(not).length === 0
  );
}
