import * as z from "zod/v4";
import { isRecord } from "./record.js";

/** Project a native contract for tools/list while preserving its validator and type. */
export function projectArtifactToolSchema<Schema extends z.ZodType>(
  schema: Schema,
): Schema {
  // Zod exports fresh JSON. Copy the root to omit its non-enumerable ~standard.
  const declaration = { ...z.toJSONSchema(schema, { io: "input" }) };
  hideForbiddenProperties(declaration);
  return schema.meta(declaration);
}

function hideForbiddenProperties(value: unknown): void {
  if (Array.isArray(value)) return value.forEach(hideForbiddenProperties);
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (!["const", "enum", "default", "examples"].includes(key))
      hideForbiddenProperties(child);
  }

  // Native tool declarations treat Zod's {not:{}} as an optional unknown field.
  // Forbid the name without advertising the property.
  const properties = value.properties;
  if (!isRecord(properties)) return;
  const forbidden = Object.keys(properties).filter((key) =>
    forbiddenProperty(properties[key]),
  );
  if (!forbidden.length) return;
  for (const key of forbidden) delete properties[key];
  const names = { not: { enum: forbidden } };
  value.propertyNames =
    value.propertyNames === undefined
      ? names
      : { allOf: [value.propertyNames, names] };
}

export function forbiddenProperty(value: unknown): boolean {
  return (
    value === false ||
    (isRecord(value) &&
      isRecord(value.not) &&
      Object.keys(value).length === 1 &&
      Object.keys(value.not).length === 0)
  );
}
