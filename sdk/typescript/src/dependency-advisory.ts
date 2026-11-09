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

const rustAffects = z.object({
  affects: z.object({
    functions: z.array(z.string()).optional(),
    arch: z.array(z.string()).optional(),
    os: z.array(z.string()).optional(),
  }),
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
    const schema =
      entry.package?.ecosystem === "crates.io"
        ? rustAffects
        : entry.package?.ecosystem === "Go"
          ? goImports
          : undefined;
    const metadata = schema?.safeParse(ecosystem_specific);
    if (metadata?.success)
      return { ...entry, ecosystem_specific: metadata.data };
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

type OsvRecord = z.infer<typeof osvRecord>;
type Fetcher = (url: string, init: RequestInit) => Promise<Response>;
const cvePattern = /^CVE-\d{4}-\d{4,}$/u;

type Advisory = Pick<OsvRecord, "summary" | "affected"> & {
  url: string;
  overview?: string;
  applicability?: string;
};

export interface DependencyPackage {
  ecosystem: string;
  name: string;
}

export interface PackageAdvisory {
  id: string;
  advisories: Advisory[];
}

export type DependencyIssue =
  | Awaited<ReturnType<typeof lookupDependencyAdvisory>>
  | (PackageAdvisory & { package: DependencyPackage })
  | { package: DependencyPackage; vulnDescription: string };

export function parseDependencyPackage(subject: string): DependencyPackage {
  const parts = subject.trim().split(":");
  const [base = ""] = parts;
  // Ecosystems can include a distribution release (Debian:12). Maven names
  // have two parts, and Android identifiers and Git URLs can contain colons.
  const maven = base === "Maven" || parts.at(-3) === "Maven";
  let nameIndex = parts.length - 1;
  if (["npm", "Android", "GIT", "SwiftURL"].includes(base)) nameIndex = 1;
  else if (maven) nameIndex--;
  const name = parts.slice(nameIndex).join(":");
  if (
    nameIndex < 1 ||
    (nameIndex > 1 && !parts[1]?.trim()) ||
    parts[1]?.startsWith("//") ||
    !/^[A-Za-z][A-Za-z0-9.-]*(?: [A-Za-z0-9.-]+)*$/u.test(base) ||
    !name ||
    name.startsWith("/") ||
    /[\s\\]/u.test(name) ||
    (maven && !/^[^:]+:[^:]+$/u.test(name))
  ) {
    throw new CodexSecurityError(
      "Expected a CVE ID or ecosystem:package, for example npm:example-package or PyPI:example-package.",
    );
  }
  if (base === "npm" && !/^(?:@[^@/:]+\/)?[^@/:]+$/u.test(name)) {
    throw new CodexSecurityError(
      "Expected an unversioned npm package, for example npm:example-package or npm:@scope/example-package.",
    );
  }
  return { ecosystem: parts.slice(0, nameIndex).join(":"), name };
}

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

/** Include prose and lists under the advisory's applicability headings. */
function applicabilityText(details: string | undefined): string | undefined {
  const lines: string[] = [];
  let collecting = false;
  let fence = "";
  for (const line of (details ?? "").split(/\r?\n/u)) {
    const marker = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/u);
    if (fence) {
      if (marker?.[1]?.startsWith(fence) && !marker[2]?.trim()) fence = "";
      continue;
    }
    if (marker) {
      fence = marker[1]!;
      continue;
    }
    const heading = line.match(/^ {0,3}#{1,6}[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$/u);
    if (heading) {
      collecting =
        /^(?:am i affected\??|who is affected\??|affected (?:configurations|environments|deployments)|applicability|prerequisites)$/iu.test(
          heading[1]!,
        );
      if (collecting) lines.push("");
    } else if (collecting) {
      lines.push(line);
    }
  }

  const prose = lines
    .join("\n")
    .split(/\n[ \t]*\n/u)
    .filter(
      (block) =>
        // Omit indented code, HTML/media, and inline code other than symbols
        // or configuration settings (e.g. `enabled = true`).
        block.trim() &&
        !/^(?: {4}|\t| {0,3}[<>]| {0,3}!\[)/mu.test(block) &&
        !block
          .replace(/`[\w.:\[\]-]+(?:\(\))?(?:[ \t]*=[ \t]*[\w.-]+)?`/gu, "")
          .includes("`"),
    )
    .join("\n\n")
    .trim();
  return prose || undefined;
}

function projectAdvisory(record: OsvRecord): Advisory {
  const overview = openingOverview(record.details);
  const applicability = applicabilityText(record.details);
  return {
    url: `https://osv.dev/vulnerability/${encodeURIComponent(record.id)}`,
    ...(record.summary && { summary: record.summary }),
    ...(overview && { overview }),
    ...(applicability && { applicability }),
    affected: record.affected,
  };
}

async function requestOsv(
  url: string,
  subject: string,
  signal: AbortSignal | undefined,
  fetcher: Fetcher,
  init?: RequestInit,
) {
  signal?.throwIfAborted();
  try {
    return await fetcher(url, { ...init, redirect: "error", signal });
  } catch (error) {
    signal?.throwIfAborted();
    throw new CodexSecurityError(
      `OSV lookup failed for ${subject}: ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

// GetVulnById returns gRPC NOT_FOUND with space-separated IDs when only an
// alias exists. Confirm the CVE on the fetched records before using them.
const aliasHint = "Vulnerability not found, but the following aliases were: ";

export async function lookupDependencyAdvisory(
  input: string,
  signal?: AbortSignal,
  fetcher: Fetcher = fetch,
) {
  const cve = input.trim().toUpperCase();
  if (!cvePattern.test(cve))
    throw new CodexSecurityError(
      "Expected a CVE ID, for example CVE-2023-4863.",
    );

  const advisories: Advisory[] = [];
  const ids = new Set([cve]);
  for (const id of ids) {
    const key = encodeURIComponent(id);
    if (!key || key === "." || key === "..") continue;
    const response = await requestOsv(
      `https://api.osv.dev/v1/vulns/${key}`,
      id,
      signal,
      fetcher,
    );
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

    advisories.push(projectAdvisory(record));
  }
  if (!advisories.length)
    throw new CodexSecurityError(
      `No active public OSV advisory was found for ${cve}.`,
    );
  return { cve, advisories };
}

const queryPage = z.object({
  vulns: z.array(osvRecord).default([]),
  next_page_token: z.string().optional(),
});

export async function lookupPackageAdvisories(
  { ecosystem, name }: DependencyPackage,
  signal?: AbortSignal,
  fetcher: Fetcher = fetch,
): Promise<PackageAdvisory[]> {
  const subject = `${ecosystem}:${name}`;
  const records = new Map<string, Advisory>();
  const groups = new Map<string, Set<string>>();
  const tokens = new Set<string>();
  let pageToken: string | undefined;
  do {
    const response = await requestOsv(
      "https://api.osv.dev/v1/query",
      subject,
      signal,
      fetcher,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          package: { ecosystem, name },
          page_token: pageToken,
        }),
      },
    );
    if (!response.ok)
      throw new CodexSecurityError(
        `OSV returned HTTP ${response.status} for ${subject}.`,
      );
    const page = queryPage.parse(await response.json());
    for (const record of page.vulns) {
      if (record.withdrawn) continue;
      records.set(record.id, projectAdvisory(record));
      // OSV aliases identify the same issue, even when discovered on different pages.
      const ids = [record.id, ...record.aliases];
      const group = new Set(ids);
      for (const id of ids)
        for (const member of groups.get(id) ?? []) group.add(member);
      for (const member of group) groups.set(member, group);
    }
    pageToken = page.next_page_token;
    if (pageToken && tokens.has(pageToken))
      throw new CodexSecurityError(`OSV repeated a page token for ${subject}.`);
    if (pageToken) tokens.add(pageToken);
  } while (pageToken);

  return Array.from(new Set(groups.values()), (group) => {
    const ids = [...group].sort();
    const published = ids.filter((id) => records.has(id));
    return {
      id: ids.find((id) => cvePattern.test(id)) ?? published[0]!,
      advisories: published.map((id) => records.get(id)!),
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
}
