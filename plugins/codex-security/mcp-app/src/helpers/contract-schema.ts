import { JsonFloat, object, objectEntries, pythonRepr } from "./python-json";

type SchemaType =
  | "array"
  | "boolean"
  | "integer"
  | "number"
  | "object"
  | "string"
  | "null";
export interface ContractSchema {
  $ref?: string;
  type?: SchemaType | SchemaType[];
  const?: unknown;
  enum?: unknown[];
  minLength?: number;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  items?: ContractSchema;
  required?: string[];
  minProperties?: number;
  properties?: Record<string, ContractSchema>;
  additionalProperties?: boolean | ContractSchema;
  [key: string]: unknown;
}

const numeric = (value: unknown): value is number | bigint | JsonFloat =>
  typeof value === "number" ||
  typeof value === "bigint" ||
  value instanceof JsonFloat;
const number = (value: number | bigint | JsonFloat) =>
  value instanceof JsonFloat ? Number(value.source) : value;

function equal(left: unknown, right: unknown): boolean {
  if (numeric(left) && numeric(right)) {
    const a = number(left),
      b = number(right);
    if (typeof a === typeof b) return a === b;
    const integer = typeof a === "bigint" ? a : b;
    const floating = typeof a === "number" ? a : (b as number);
    return (
      Number.isFinite(floating) &&
      Number.isInteger(floating) &&
      integer === BigInt(floating)
    );
  }
  return left === right;
}

function matches(value: unknown, expected: SchemaType): boolean {
  switch (expected) {
    case "array":
      return Array.isArray(value);
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return (
        typeof value === "bigint" ||
        (typeof value === "number" && Number.isInteger(value))
      );
    case "number":
      return numeric(value);
    case "object":
      return object(value);
    case "string":
      return typeof value === "string";
    case "null":
      return value === null;
  }
}

/** The assessment schema uses the same structural rules as the scan contract. */
export function validateAgainstSchema(
  value: unknown,
  schema: ContractSchema,
  context: string,
  root: ContractSchema = schema,
): void {
  const fail: (message: string) => never = (message) => {
    throw new Error(`${context}: ${message}`);
  };
  if (schema.$ref !== undefined) {
    const reference = schema.$ref;
    if (typeof reference !== "string")
      fail("schema reference must be a string");
    let target: unknown = root;
    if (reference !== "#") {
      if (!reference.startsWith("#/"))
        fail(`unsupported schema reference ${pythonRepr(reference)}`);
      for (const part of reference.slice(2).split("/")) {
        const key = part.replaceAll("~1", "/").replaceAll("~0", "~");
        if (!object(target) || !Object.hasOwn(target, key))
          fail(`unresolved schema reference ${pythonRepr(reference)}`);
        target = target[key];
      }
    }
    if (!object(target))
      fail(`schema reference ${pythonRepr(reference)} is not an object`);
    validateAgainstSchema(value, target as ContractSchema, context, root);
  }
  const expected = schema.type;
  if (Array.isArray(expected)) {
    if (!expected.some((type) => matches(value, type)))
      fail(`does not match schema type ${pythonRepr(expected)}`);
  } else if (typeof expected === "string" && !matches(value, expected)) {
    fail(`expected schema type ${expected}`);
  }
  if (Object.hasOwn(schema, "const") && !equal(value, schema.const))
    fail(`expected ${pythonRepr(schema.const)}`);
  if (schema.enum && !schema.enum.some((candidate) => equal(value, candidate)))
    fail(`unsupported value ${pythonRepr(value)}`);
  if (typeof value === "string") {
    if (schema.minLength && Array.from(value).length < schema.minLength)
      fail("string is too short");
    if (
      schema.pattern !== undefined &&
      !new RegExp(`^(?:${schema.pattern})$(?![\\s\\S])`, "u").test(value)
    )
      fail("string does not match schema pattern");
  }
  if (numeric(value)) {
    if (schema.minimum !== undefined && number(value) < schema.minimum)
      fail("value is below schema minimum");
    if (schema.maximum !== undefined && number(value) > schema.maximum)
      fail("value is above schema maximum");
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems)
      fail("array has too few items");
    if (schema.maxItems !== undefined && value.length > schema.maxItems)
      fail("array has too many items");
    if (schema.items)
      value.forEach((item, index) =>
        validateAgainstSchema(
          item,
          schema.items!,
          `${context}[${index}]`,
          root,
        ),
      );
    if (schema.uniqueItems === true && new Set(value).size !== value.length)
      fail("array items must be unique");
  }
  if (object(value)) {
    for (const key of schema.required ?? [])
      if (!Object.hasOwn(value, key))
        throw new Error(`${context}.${key}: missing required schema property`);
    if (
      schema.minProperties !== undefined &&
      Object.keys(value).length < schema.minProperties
    )
      fail("object has too few properties");
    for (const [key, item] of objectEntries(value)) {
      const child = Object.hasOwn(schema.properties ?? {}, key)
        ? schema.properties![key]
        : undefined;
      if (child) validateAgainstSchema(item, child, `${context}.${key}`, root);
      else if (schema.additionalProperties === false)
        throw new Error(`${context}.${key}: unexpected schema property`);
      else if (object(schema.additionalProperties))
        validateAgainstSchema(
          item,
          schema.additionalProperties,
          `${context}.${key}`,
          root,
        );
    }
  }
}
