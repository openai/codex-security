import { z } from "zod";
import { CodexSecurityError, errorMessage } from "./errors.js";

const goImports = z.object({
  imports: z.array(
    z.object({
      path: z.string(),
      symbols: z.array(z.string()).optional(),
      goos: z.array(z.string()).optional(),
      goarch: z.array(z.string()).optional(),
    }),
  ),
});

// Keep OSV's ordered events and explicit versions. A single package may have
// several affected intervals, and a GIT range may have no package coordinates.
const affected = z
  .object({
    package: z.object({ ecosystem: z.string(), name: z.string() }).optional(),
    ranges: z
      .array(
        z.object({
          type: z.string(),
          repo: z.string().optional(),
          events: z.array(
            z.union([
              z.object({ introduced: z.string() }),
              z.object({ fixed: z.string() }),
              z.object({ last_affected: z.string() }),
              z.object({ limit: z.string() }),
            ]),
          ),
        }),
      )
      .optional(),
    versions: z.array(z.string()).optional(),
    ecosystem_specific: z.unknown().optional(),
  })
  .transform(({ ecosystem_specific, ...entry }) => {
    if (entry.package?.ecosystem === "Go") {
      const metadata = goImports.safeParse(ecosystem_specific);
      if (metadata.success)
        return { ...entry, ecosystem_specific: metadata.data };
    }
    return entry;
  });

const osvRecord = z.object({
  id: z.string(),
  aliases: z
    .array(z.string())
    .nullish()
    .transform((ids) => ids ?? []),
  withdrawn: z.string().optional(),
  summary: z.string().optional(),
  details: z.string().optional(),
  affected: z
    .array(affected)
    .nullish()
    .transform((entries) => entries ?? []),
});

type Advisory = Pick<z.infer<typeof osvRecord>, "summary" | "affected"> & {
  url: string;
  overview?: string;
};

/** Keep opening prose, excluding code blocks and later sections. */
function openingOverview(details: string | undefined): string | undefined {
  const [paragraph] = (details ?? "")
    .trimStart()
    .replace(
      /^#{1,6} +(summary|overview|impact)[ \t]*\r?\n(?:[ \t]*\r?\n)*/iu,
      "",
    )
    .split(/\r?\n(?:[ \t]*\r?\n|(?=#))/u, 1);
  if (
    !paragraph ||
    paragraph.length > 800 ||
    /^(?:\s|[<>#~]|[-*+] |\d+\. )/mu.test(paragraph)
  )
    return;
  if (paragraph.replace(/`[\w.:-]+(?:\(\))?`/gu, "").includes("`")) return;
  return paragraph.trim().replaceAll(/\r?\n/gu, " ");
}

// GetVulnById returns gRPC NOT_FOUND with space-separated IDs when only an
// alias exists. Confirm the CVE on the fetched records before using them.
const aliasHint = "Vulnerability not found, but the following aliases were: ";

export async function lookupDependencyAdvisory(
  input: string,
  signal?: AbortSignal,
  fetcher: (url: string, init: RequestInit) => Promise<Response> = fetch,
) {
  const cve = input.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/u.test(cve))
    throw new CodexSecurityError(
      "Expected a CVE ID, for example CVE-2023-4863.",
    );

  const advisories: Advisory[] = [];
  const ids = new Set([cve]);
  for (const id of ids) {
    signal?.throwIfAborted();
    const key = encodeURIComponent(id);
    if (!key || key === "." || key === "..") continue;
    let response: Response;
    try {
      response = await fetcher(`https://api.osv.dev/v1/vulns/${key}`, {
        redirect: "error",
        signal,
      });
    } catch (error) {
      signal?.throwIfAborted();
      throw new CodexSecurityError(
        `OSV lookup failed for ${id}: ${errorMessage(error)}`,
        { cause: error },
      );
    }
    if (response.status === 404) {
      if (id === cve) {
        const missing = await response.json();
        if (
          missing?.code === 5 &&
          typeof missing.message === "string" &&
          missing.message.startsWith(aliasHint)
        ) {
          const aliases = missing.message.slice(aliasHint.length).split(/\s+/u);
          for (const alias of aliases) ids.add(alias);
        }
      }
      continue;
    }
    if (!response.ok)
      throw new CodexSecurityError(
        `OSV returned HTTP ${response.status} for ${id}.`,
      );

    const record = osvRecord.parse(await response.json());
    if (record.id !== id) continue;
    if (id === cve) {
      for (const alias of record.aliases) ids.add(alias);
    }
    if (record.withdrawn || (id !== cve && !record.aliases.includes(cve)))
      continue;

    const overview = openingOverview(record.details);
    advisories.push({
      url: `https://osv.dev/vulnerability/${key}`,
      ...(record.summary && { summary: record.summary }),
      ...(overview && { overview }),
      affected: record.affected,
    });
  }
  if (!advisories.length)
    throw new CodexSecurityError(
      `No active public OSV advisory was found for ${cve}.`,
    );
  return { cve, advisories };
}
