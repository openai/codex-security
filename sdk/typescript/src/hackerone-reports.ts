import { randomUUID } from "node:crypto";
import { link, open, readFile, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { z } from "zod";

const id = z.string().regex(/^[1-9][0-9]*$/u);
const timestamp = z.iso.datetime({ offset: true }).nullish();
const severity = z.object({
  attributes: z.object({ rating: z.string().min(1).max(64) }),
});
const scope = z.object({
  id,
  attributes: z.object({ asset_type: z.string().min(1).max(128) }),
});
const detail = z.object({
  id,
  type: z.literal("report"),
  attributes: z.object({
    title: z.string().trim().min(1).max(1024),
    state: z.string().min(1).max(128),
    created_at: timestamp,
    submitted_at: timestamp,
    last_activity_at: timestamp,
    cve_ids: z
      .array(z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,}$/u))
      .max(100)
      .nullish(),
  }),
  relationships: z.object({
    program: z.object({ data: z.object({ id, type: z.literal("program") }) }),
    severity: z.object({ data: severity.nullable() }).optional(),
    structured_scope: z.object({ data: scope.nullable() }).optional(),
  }),
});

function project(raw: unknown, program: string, report: string) {
  const parsed = z.object({ data: detail }).safeParse(raw);
  if (!parsed.success)
    throw new Error(
      `Report ${report} is missing required fields or contains an invalid field.`,
    );
  const { id, attributes, relationships } = parsed.data.data;
  if (id !== report || relationships.program.data.id !== program)
    throw new Error(
      `Report ${report} did not match the selected report and program.`,
    );
  const target = relationships.structured_scope?.data;
  return {
    program_id: program,
    id,
    title: attributes.title,
    state: attributes.state,
    severity_rating: relationships.severity?.data?.attributes.rating,
    created_at: attributes.created_at ?? undefined,
    submitted_at: attributes.submitted_at ?? undefined,
    last_activity_at: attributes.last_activity_at ?? undefined,
    cve_ids: attributes.cve_ids?.length
      ? [...new Set(attributes.cve_ids)].sort()
      : undefined,
    scope: target
      ? { id: target.id, asset_type: target.attributes.asset_type }
      : undefined,
  };
}

// Report detail may include free text and attachment metadata. Bound it before decoding.
async function readDetail(
  response: Response,
  report: string,
): Promise<unknown> {
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new Error(
      `HackerOne could not read report ${report} (HTTP ${response.status}).`,
    );
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 2 * 1024 * 1024) {
        await reader.cancel();
        throw new Error(`Report ${report} exceeds the 2 MiB detail limit.`);
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error(`Report ${report} did not contain a JSON response.`);
  }
}

export async function exportHackerOneReports(options: {
  programId: string;
  reportIds: string;
  output: string;
  capture?: string;
  environment: NodeJS.ProcessEnv;
  fetch?: (url: string, options: RequestInit) => Promise<Response>;
}) {
  const ids = options.reportIds.split(",").map((item) => item.trim());
  if (
    !id.safeParse(options.programId).success ||
    !z.array(id).min(1).max(100).safeParse(ids).success ||
    new Set(ids).size !== ids.length
  )
    throw new Error(
      "Select one program ID and 1–100 distinct decimal report IDs.",
    );
  const username = options.environment["HACKERONE_API_USERNAME"];
  const token = options.environment["HACKERONE_API_TOKEN"];
  if (!username || username.includes(":") || !token)
    throw new Error(
      "Set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN to the authorized token identifier and value.",
    );

  // Read the optional advance capture before fetching any reports.
  const capture =
    options.capture === undefined
      ? undefined
      : (await readFile(options.capture, "utf8")).trim();
  if (
    capture !== undefined &&
    (!capture || capture.length > 32768 || /\s/u.test(capture))
  )
    throw new Error("The capture file must contain one signed capture ticket.");
  const authorization =
    "Basic " + Buffer.from(`${username}:${token}`, "utf8").toString("base64");
  const reports = [];
  for (const report of ids.sort()) {
    const response = await (options.fetch ?? fetch)(
      `https://api.hackerone.com/v1/reports/${report}`,
      {
        method: "GET",
        redirect: "error",
        cache: "no-store",
        signal: AbortSignal.timeout(30_000),
        headers: { Accept: "application/json", Authorization: authorization },
      },
    );
    reports.push(
      project(await readDetail(response, report), options.programId, report),
    );
  }
  const projection = {
    format: "hackerone.reports_json.v1",
    program_id: options.programId,
    reports,
  };
  const contents = capture ? { capture, projection } : projection;
  const temp = join(dirname(options.output), `.${randomUUID()}.json`);
  const file = await open(temp, "wx", 0o600);
  try {
    try {
      await file.writeFile(JSON.stringify(contents) + "\n");
    } finally {
      await file.close();
    }
    await link(temp, options.output);
  } finally {
    await unlink(temp);
  }
  return { reports: reports.length, output: options.output };
}
