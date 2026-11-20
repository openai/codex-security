import { createHash } from "node:crypto";
import { z } from "zod";
import { canonicalJson } from "./record.js";
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
const affected = z.object({
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
});
const osvAffected = affected
  .extend({ ecosystem_specific: z.unknown().optional() })
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

const advisoryReference = z.object({ type: z.string(), url: z.string() });
const githubVulnerability = z.object({
  package: z.object({ ecosystem: z.string(), name: z.string().nullable() }),
  vulnerable_version_range: z.string().nullish(),
  patched_versions: z.string().nullish(),
  first_patched_version: z.string().nullish(),
  vulnerable_functions: z.array(z.string()).nullish(),
});
const githubAdvisory = z.object({
  ghsa_id: z.string(),
  cve_id: z.string().nullish(),
  html_url: z.string(),
  summary: z.string(),
  description: z.string(),
  type: z.string().optional(),
  state: z.string().optional(),
  withdrawn_at: z.string().nullish(),
  identifiers: z.array(
    z.object({ type: z.string(), value: z.string().nullable() }),
  ),
  references: z.array(z.string()).default([]),
  vulnerabilities: z.array(githubVulnerability).default([]),
});
const advisoryLookupError = z.object({ url: z.string(), message: z.string() });

const osvRecord = z.object({
  id: z.string(),
  aliases: z
    .array(z.string())
    .nullish()
    .transform((ids) => ids ?? []),
  withdrawn: z.string().optional(),
  modified: z.string().optional(),
  summary: z.string().optional(),
  details: z.string().optional(),
  references: z
    .array(advisoryReference)
    .nullish()
    .transform((references) => references ?? []),
  affected: z
    .array(osvAffected)
    .nullish()
    .transform((entries) => entries ?? []),
});

type OsvRecord = z.infer<typeof osvRecord>;
type Fetcher = (url: string, init: RequestInit) => Promise<Response>;
const cvePattern = /^CVE-\d{4}-\d{4,}$/u;

const advisoryFields = {
  aliases: z.array(z.string()).optional(),
  url: z.string(),
  references: z.array(advisoryReference).optional(),
  source: advisoryReference.optional(),
  type: z.string().optional(),
  summary: z.string().optional(),
  body: z.string().optional(),
  vulnerabilities: z.array(githubVulnerability).optional(),
  lookupErrors: z.array(advisoryLookupError).optional(),
  affected: z.array(
    affected.extend({
      ecosystem_specific: z.union([goImports, rustAffects]).optional(),
    }),
  ),
  vulnerableFunctions: z.array(z.string()).optional(),
};

export const dependencyAdvisoryDetailsSchema = z.object({
  id: z.string().optional(),
  ...advisoryFields,
  overview: z.string().optional(),
  applicability: z.string().optional(),
});

// The normalized record emitted by OSV/GitHub lookup, also accepted when
// replaying a captured-stack investigation without a network lookup.
const advisoryRecord = z.strictObject({
  id: z.string().min(1),
  ...advisoryFields,
  modified: z.string().optional(),
});
type Advisory = z.infer<typeof advisoryRecord>;

export interface DependencyPackage {
  ecosystem: string;
  name: string;
}

export interface PackageAdvisory {
  id: string;
  advisories: FrozenDependencyAdvisory[];
}

export const advisoryTriggerInstructions = [
  "Describe what an attacker must control, how the affected operation must be used, and which downstream behavior is required for impact. Include only necessary conditions grounded in the vulnerability evidence. Make each condition concise and independently checkable.",
  "For a given affected operation, combine alternative ways to meet the same requirement into one condition joined by OR. Treat example payloads, optional configurations, and example impacts as illustrations unless the evidence establishes a requirement.",
] as const;

export const frozenDependencyAdvisorySchema = advisoryRecord
  .extend({
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  })
  .refine(({ sha256, ...record }) => freezeAdvisory(record).sha256 === sha256, {
    message: "Frozen advisory SHA-256 mismatch.",
  });
export type FrozenDependencyAdvisory = z.infer<
  typeof frozenDependencyAdvisorySchema
>;

/** Hash the exact advisory fields retained for the investigator, including version events. */
function freezeAdvisory(advisory: Advisory) {
  return {
    ...advisory,
    sha256: createHash("sha256").update(canonicalJson(advisory)).digest("hex"),
  };
}

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

function* unfencedDetailsLines(details: string | undefined) {
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
    yield line;
  }
}

function vulnerableFunctions(details: string | undefined): string[] {
  const label =
    /^ {0,3}(?:(?:[-*+]|\d+[.)])[ \t]+)?(?:\*\*|__)?(?:vulnerable|affected) (?:functions?|methods?|symbols?)(?:\*\*|__)?[ \t]*:(?:\*\*|__)?[ \t]*(.*)$/iu;
  const symbol =
    /^`([\p{L}_$][\p{L}\p{N}_$]*(?:(?:\.|::|#|\\)[\p{L}_$][\p{L}\p{N}_$]*)*(?:\(\))?)`/u;
  const separator =
    /^(?:[ \t]*[,/][ \t]*(?:(?:and|or)[ \t]+)?|[ \t]+(?:and|or)[ \t]+)/iu;
  const functions = new Set<string>();
  for (const line of unfencedDetailsLines(details)) {
    let rest = label.exec(line)?.[1] ?? "";
    for (let match = symbol.exec(rest); match; match = symbol.exec(rest)) {
      functions.add(match[1]!);
      rest = rest.slice(match[0].length);
      const next = separator.exec(rest);
      if (!next) break;
      rest = rest.slice(next[0].length);
    }
  }
  return [...functions];
}

function projectAdvisory(record: OsvRecord): Advisory {
  const symbols = new Set(vulnerableFunctions(record.details));
  for (const entry of record.affected) {
    const specific =
      "ecosystem_specific" in entry ? entry.ecosystem_specific : undefined;
    if (specific && "imports" in specific) {
      for (const mod of specific.imports)
        for (const symbol of mod.symbols ?? []) symbols.add(symbol);
    } else if (specific && "affects" in specific) {
      for (const symbol of specific.affects.functions ?? [])
        symbols.add(symbol);
    }
  }
  return {
    id: record.id,
    ...(record.aliases.length && { aliases: record.aliases }),
    url: `https://osv.dev/vulnerability/${encodeURIComponent(record.id)}`,
    ...(record.references.length && { references: record.references }),
    ...(record.summary && { summary: record.summary }),
    ...(record.details && { body: record.details }),
    ...(record.modified && { modified: record.modified }),
    affected: record.affected,
    ...(symbols.size && { vulnerableFunctions: [...symbols].sort() }),
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
const ghsaPattern = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/iu;

function repositoryAdvisory(url: string) {
  const match =
    /^https:\/\/github\.com\/([\w-]+)\/([\w.-]+)\/security\/advisories\/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\/?(?:[?#].*)?$/iu.exec(
      url,
    );
  if (!match || match[2] === "." || match[2] === "..") return;
  const [, owner, repository, id] = match;
  return {
    id: id!,
    url: `https://api.github.com/repos/${encodeURIComponent(owner!)}/${encodeURIComponent(repository!)}/security-advisories/${encodeURIComponent(id!)}`,
  };
}

async function lookupGithubAdvisory(
  id: string,
  cve: string,
  advisories: Advisory[],
  signal: AbortSignal | undefined,
  fetcher: Fetcher,
) {
  const primary = advisories
    .flatMap(({ references }) => references ?? [])
    .map(({ url }) => repositoryAdvisory(url))
    .find((reference) => reference?.id === id);
  const url =
    primary?.url ??
    `https://api.github.com/advisories/${encodeURIComponent(id)}`;
  try {
    signal?.throwIfAborted();
    const response = await fetcher(url, {
      redirect: "error",
      credentials: "omit",
      signal,
      headers: { Accept: "application/vnd.github+json" },
    });
    if (!response.ok)
      throw new Error(
        `GitHub returned HTTP ${response.status}: ${await response.text()}`,
      );
    const record = githubAdvisory.parse(await response.json());
    if (
      record.ghsa_id !== id ||
      !(
        record.cve_id === cve ||
        record.identifiers.some(
          ({ type, value }) => type === "CVE" && value === cve,
        )
      ) ||
      record.withdrawn_at ||
      (record.state !== undefined && record.state !== "published")
    )
      throw new Error(
        "GitHub did not return an active published advisory matching the requested GHSA and CVE.",
      );
    const result: Advisory = {
      ...projectAdvisory(
        osvRecord.parse({
          id,
          aliases: [
            ...new Set([
              cve,
              ...record.identifiers.flatMap(({ value }) =>
                value && value !== id ? [value] : [],
              ),
            ]),
          ],
          summary: record.summary,
          details: record.description,
        }),
      ),
      url: record.html_url,
      source: {
        type: primary ? "github_repository_advisory" : "github_global_advisory",
        url,
      },
      ...(record.type && { type: record.type }),
      body: record.description,
      vulnerabilities: record.vulnerabilities,
      references: [
        { type: "ADVISORY", url: record.html_url },
        ...record.references.map((url) => ({ type: "WEB", url })),
      ],
    };
    const functions = [
      ...new Set([
        ...(result.vulnerableFunctions ?? []),
        ...record.vulnerabilities.flatMap((v) => v.vulnerable_functions ?? []),
      ]),
    ].sort();
    if (functions.length) result.vulnerableFunctions = functions;
    return { advisory: result };
  } catch (error) {
    signal?.throwIfAborted();
    return { error: { url, message: errorMessage(error) } };
  }
}

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
  const lookupErrors: z.infer<typeof advisoryLookupError>[] = [];
  const missingGhsas = new Set<string>();
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
      } else if (ghsaPattern.test(id)) {
        missingGhsas.add(id);
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
      for (const { url } of record.references) {
        const primary = repositoryAdvisory(url);
        if (primary) ids.add(primary.id);
      }
    }
    if (record.withdrawn || (id !== cve && !record.aliases.includes(cve)))
      continue;

    advisories.push(projectAdvisory(record));
  }
  for (const id of missingGhsas) {
    const result = await lookupGithubAdvisory(
      id,
      cve,
      advisories,
      signal,
      fetcher,
    );
    if (result.advisory) advisories.push(result.advisory);
    if (result.error) lookupErrors.push(result.error);
  }
  if (!advisories.length)
    throw new CodexSecurityError(
      `No active public OSV advisory was found for ${cve}.${lookupErrors.length ? ` Primary advisory lookups failed: ${JSON.stringify(lookupErrors)}` : ""}`,
    );
  if (lookupErrors.length)
    for (const advisory of advisories) advisory.lookupErrors = lookupErrors;
  return { cve, advisories: advisories.map(freezeAdvisory) };
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
      advisories: published.map((id) => freezeAdvisory(records.get(id)!)),
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
}
