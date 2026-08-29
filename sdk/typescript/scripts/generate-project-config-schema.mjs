import { mkdir, writeFile } from "node:fs/promises";
import { format } from "prettier";
import { projectConfigJsonSchema } from "../dist/project-config-schema.js";

const directory = new URL("../schemas/", import.meta.url);
await mkdir(directory, { recursive: true });
await writeFile(
  new URL("project-config.schema.json", directory),
  await format(JSON.stringify(projectConfigJsonSchema()), { parser: "json" }),
);
