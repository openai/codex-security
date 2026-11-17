import { writeFile } from "node:fs/promises";
import { format } from "prettier";
import { z } from "zod";
import { stackInvestigationReportSchema } from "../dist/dependency-stack-assessment.js";
import { stackPacketJsonSchema } from "../dist/dependency-stack-packet.js";

const schemas = {
  "dependency-stack-inputs-v1.schema.json": stackPacketJsonSchema(),
  "stack-investigation-report-v1.schema.json": z.toJSONSchema(
    stackInvestigationReportSchema,
    { reused: "ref" },
  ),
};
for (const [filename, schema] of Object.entries(schemas)) {
  await writeFile(
    new URL("../schemas/" + filename, import.meta.url),
    await format(JSON.stringify(schema), { parser: "json" }),
  );
}
