import { readFileSync } from "node:fs";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import type { Finding } from "./models.js";

export type FindingSearchScope =
  | { repositoryId: string; allRepositories?: never }
  | { allRepositories: true; repositoryId?: never };

export interface FindingNeighborhood {
  finding: Finding;
  potentialDuplicates: Finding[];
}

let validateFinding: ValidateFunction<Finding> | undefined;

export function isFinding(value: unknown): value is Finding {
  if (validateFinding === undefined) {
    const schema = JSON.parse(
      readFileSync(
        new URL(
          "../_bundled_plugin/schemas/findings.schema.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    validateFinding = new Ajv2020({ strict: false }).compile<Finding>(
      schema.properties.findings.items,
    );
  }
  return validateFinding(value);
}
