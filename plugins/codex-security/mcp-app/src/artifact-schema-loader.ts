import { isDeepStrictEqual } from "node:util";
import * as z from "zod/v4";
import { isRecord } from "./record.js";

/** Project a native contract for tools/list while preserving its validator and type. */
export function projectArtifactToolSchema<Schema extends z.ZodType>(
  schema: Schema,
): Schema {
  const declaration = z.toJSONSchema(schema, { io: "input" });
  hideForbiddenFields(declaration);
  return schema.meta({ ...declaration });
}

/** Keep forbidden fields out of native tool declarations without allowing them. */
function hideForbiddenFields(value: unknown): void {
  if (Array.isArray(value)) return value.forEach(hideForbiddenFields);
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (!["const", "enum", "default", "examples"].includes(key))
      hideForbiddenFields(child);
  }
  const properties = value.properties;
  if (!isRecord(properties)) return;

  // Zod renders false properties as {not:{}}, which the native declaration
  // projects as optional unknown fields. Exclude their names instead. This
  // is equivalent JSON Schema; the original validator remains unchanged.
  const forbidden: string[] = [];
  for (const [name, property] of Object.entries(properties)) {
    if (forbiddenProperty(property)) {
      forbidden.push(name);
      delete properties[name];
    }
  }
  if (!forbidden.length) return;
  const names = { not: { enum: forbidden } };
  value.propertyNames =
    value.propertyNames === undefined
      ? names
      : { allOf: [value.propertyNames, names] };
}

export function forbiddenProperty(value: unknown): boolean {
  return value === false || isDeepStrictEqual(value, { not: {} });
}
