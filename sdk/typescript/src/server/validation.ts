import { readFile } from "node:fs/promises";
import { join } from "node:path";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import type { Finding } from "../models.js";
import type { FindingSearchScope } from "../finding-retrieval.js";
import { bundledPluginRoot } from "../runtime.js";
import { FindingsError } from "./errors.js";

export type FindingsRequest = { findings: Finding[]; repositoryId?: string };

export const validateDedupeGroups = new Ajv2020().compile<{
  groups: string[][];
}>({
  type: "object",
  required: ["groups"],
  properties: {
    groups: {
      type: "array",
      items: {
        type: "array",
        minItems: 2,
        uniqueItems: true,
        items: { type: "string", minLength: 1 },
      },
    },
  },
});

export async function findingsRequestValidator(): Promise<
  ValidateFunction<FindingsRequest>
> {
  const root = await bundledPluginRoot();
  const schema = JSON.parse(
    await readFile(join(root, "schemas", "findings.schema.json"), "utf8"),
  );
  return new Ajv2020({ strict: false }).compile<FindingsRequest>({
    type: "object",
    required: ["findings"],
    properties: {
      findings: schema.properties.findings,
      repositoryId: { type: "string", minLength: 1 },
    },
  });
}

export function findingSearchScope(
  parameters: URLSearchParams,
): FindingSearchScope {
  const repositoryId = parameters.get("repositoryId");
  const allRepositories = parameters.get("allRepositories");
  if (allRepositories === "true" && repositoryId === null)
    return { allRepositories: true };
  if (repositoryId && (allRepositories === null || allRepositories === "false"))
    return { repositoryId };
  throw new FindingsError(
    "invalid_request",
    "Specify repositoryId or allRepositories=true, not both.",
  );
}

export function pagination(parameters: URLSearchParams): {
  limit: number;
  offset: number;
} {
  const limit = Number(parameters.get("limit") ?? 50);
  const offset = Number(parameters.get("offset") ?? 0);
  if (
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    !Number.isSafeInteger(offset) ||
    offset < 0
  ) {
    throw new FindingsError(
      "invalid_request",
      "limit must be a positive integer and offset must be a non-negative integer.",
    );
  }
  return { limit, offset };
}
