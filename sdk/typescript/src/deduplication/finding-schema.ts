import { readFileSync } from "node:fs";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import type { Finding } from "../models.js";

let schema: object | undefined;
let validator: ValidateFunction<Finding> | undefined;

export function findingSchema(): object {
  return (schema ??= JSON.parse(
    readFileSync(
      new URL(
        "../../_bundled_plugin/schemas/findings.schema.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ).properties.findings.items);
}

export function requireFinding(value: unknown): Finding {
  validator ??= new Ajv2020({ strict: false }).compile<Finding>(
    findingSchema(),
  );
  if (!validator(value))
    throw new Error(
      "Record must satisfy the Finding schema, including provenance.",
    );
  return value;
}
