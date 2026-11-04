import { randomUUID } from "node:crypto";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { format } from "prettier";
import * as z from "zod/v4";

const bundled = await build({
  stdin: {
    contents: `export * from "../src/artifact-contracts.ts";
      export * from "./canonical-schemas.mts";`,
    resolveDir: fileURLToPath(new URL(".", import.meta.url)),
  },
  bundle: true,
  platform: "node",
  format: "esm",
  write: false,
});
const {
  artifactSchemaDocuments,
  artifactJsonMetadata,
  canonicalSchemaDocuments,
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`
);
const registry = z.registry();
const documentId = (path) => `codex-security://schemas/${path}.schema.json`;
for (const [path, { $defs }] of Object.entries(artifactSchemaDocuments)) {
  for (const [name, schema] of Object.entries($defs)) {
    if (!schema._zod || registry.has(schema)) continue;
    const id = `${documentId(path)}#/$defs/${name}`;
    registry.add(schema, { id });
  }
}
const artifactJsonOptions = {
  io: "input",
  override: ({ zodSchema, jsonSchema }) => {
    if (jsonSchema.const !== undefined || jsonSchema.enum)
      delete jsonSchema.type;
    Object.assign(jsonSchema, artifactJsonMetadata.get(zodSchema));
    if (JSON.stringify(jsonSchema.additionalProperties) === "{}")
      jsonSchema.additionalProperties = true;
  },
};
const { schemas } = z.toJSONSchema(registry, {
  ...artifactJsonOptions,
  uri: (id) => id,
});
function body({ $schema, $id, ...schema }) {
  return schema;
}
function definition(schema, id) {
  const registeredId = registry.get(schema)?.id;
  if (registeredId !== id) return { $ref: registeredId };
  return body(schemas[id] ?? z.toJSONSchema(schema, artifactJsonOptions));
}
for (const [path, { $defs, ...header }] of Object.entries(
  artifactSchemaDocuments,
)) {
  const id = documentId(path);
  const definitions = Object.fromEntries(
    Object.entries($defs).map(([name, schema]) => [
      name,
      schema._zod
        ? definition(schema, `${id}#/$defs/${name}`)
        : // attackPathFields is a field map retained for existing JSON pointers.
          Object.fromEntries(
            Object.entries(schema).map(([field, value]) => [
              field,
              definition(value),
            ]),
          ),
    ]),
  );
  await save(
    path,
    {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      $id: id,
      ...header,
      $defs: definitions,
    },
    (_key, schema) =>
      JSON.stringify(schema) === '{"not":{}}' ? false : schema,
  );
}
for (const [path, { title, schema, definitions = {} }] of Object.entries(
  canonicalSchemaDocuments,
)) {
  const previousMetadata = new Map(
    Object.values(definitions).map((definition) => [
      definition,
      z.globalRegistry.get(definition),
    ]),
  );
  for (const [id, definition] of Object.entries(definitions))
    z.globalRegistry.add(definition, {
      ...z.globalRegistry.get(definition),
      id,
    });
  await save(
    path,
    {
      $id: `https://openai.com/codex-security/schemas/${path}.schema.json`,
      title,
      ...z.toJSONSchema(schema, {
        io: "input",
        override: ({ jsonSchema }) => {
          if (jsonSchema.const !== undefined || jsonSchema.enum)
            delete jsonSchema.type;
          if (JSON.stringify(jsonSchema.additionalProperties) === "{}")
            delete jsonSchema.additionalProperties;
        },
      }),
    },
    legacyTypeArrays,
  );
  for (const [definition, metadata] of previousMetadata) {
    z.globalRegistry.remove(definition);
    if (metadata) z.globalRegistry.add(definition, metadata);
  }
}
// Run after Zod resolves reused branches. Only explicitly marked canonical
// unions use this historical representation; other anyOf schemas stay intact.
function legacyTypeArrays(_key, schema) {
  if (!Array.isArray(schema?.type) || !schema.anyOf) return schema;
  const { anyOf, ...rest } = schema;
  return Object.assign(
    {},
    ...anyOf.map((part) => legacyTypeArrays("", part)),
    rest,
  );
}
async function save(path, schema, replacer) {
  const contents = await format(JSON.stringify(schema, replacer), {
    parser: "json",
  });
  const output = new URL(`../../schemas/${path}.schema.json`, import.meta.url);
  if (process.argv.includes("--check")) {
    if ((await readFile(output, "utf8")).replaceAll("\r\n", "\n") !== contents)
      throw new Error(
        `Artifact schema ${path} is out of date. Run node scripts/generate-artifact-schemas.mjs from mcp-app.`,
      );
  } else {
    // Concurrent runtime builds must always read a complete schema document.
    const temporary = `${fileURLToPath(output)}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, contents);
      await rename(temporary, output);
    } finally {
      await rm(temporary, { force: true });
    }
  }
}
