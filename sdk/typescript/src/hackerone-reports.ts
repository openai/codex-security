import { randomUUID } from "node:crypto";
import {
  link,
  mkdir,
  open,
  readFile,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { z } from "zod";
import {
  createWindowsOutputDirectory,
  requireSecureCredentialHome,
  requireSecureOutputAncestry,
} from "./runtime.js";

const id = z
  .string()
  .max(100)
  .regex(/^[1-9][0-9]*$/u);
const display = (limit: number) =>
  z
    .string()
    .refine(
      (value) =>
        value.trim().length > 0 &&
        !value.includes("\0") &&
        [...value].length <= limit,
    );
const timestamp = z.iso
  .datetime({ offset: true })
  .max(128)
  .refine((value) => Date.parse(value) >= 0)
  .nullish();
const severity = z.object({
  attributes: z.object({ rating: display(64) }).optional(),
});
const scope = z.object({
  id,
  attributes: z.object({ asset_type: display(128) }).optional(),
});
const detail = z.object({
  id,
  type: z.literal("report"),
  attributes: z.object({
    title: display(512),
    state: display(128),
    created_at: timestamp,
    submitted_at: timestamp,
    last_activity_at: timestamp,
    cve_ids: z
      .array(
        z
          .string()
          .max(512)
          .regex(/^CVE-[0-9]{4}-[0-9]{4,}$/u),
      )
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
    severity_rating: relationships.severity?.data?.attributes?.rating,
    created_at: attributes.created_at ?? undefined,
    submitted_at: attributes.submitted_at ?? undefined,
    last_activity_at: attributes.last_activity_at ?? undefined,
    cve_ids: attributes.cve_ids?.length
      ? [...new Set(attributes.cve_ids)].sort()
      : undefined,
    scope: target?.attributes
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
  if (capture !== undefined && (!capture || /\s/u.test(capture)))
    throw new Error("The capture file must contain one signed capture ticket.");
  const parent = await realpath(dirname(options.output));
  const destination = join(parent, basename(options.output));
  await requireSecureOutputAncestry(destination);
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
  const staging = join(parent, `.hackerone-${randomUUID()}`);
  if (process.platform === "win32")
    await createWindowsOutputDirectory(staging, false);
  else await mkdir(staging, { mode: 0o700 });
  const temp = join(staging, "reports.json");
  let createdFile = false;
  let warning: string | undefined;
  try {
    // Check the staging directory and its ancestors before it receives any report bytes.
    await requireSecureCredentialHome(staging);
    const file = await open(temp, "wx", 0o600);
    createdFile = true;
    try {
      await file.writeFile(JSON.stringify(contents) + "\n");
    } finally {
      await file.close();
    }
    await link(temp, destination);
  } finally {
    try {
      if (createdFile) await unlink(temp);
      await rmdir(staging);
    } catch {
      // Preserve the original write error, or the successful exclusive link.
      warning = `Could not remove temporary export at ${staging}.`;
    }
  }
  return {
    reports: reports.length,
    output: options.output,
    ...(warning ? { warnings: [warning] } : {}),
  };
}
