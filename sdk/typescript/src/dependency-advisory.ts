import { Octokit } from "@octokit/core";
import { CodexSecurityError } from "./errors.js";
import { nextGitHubAdvisoryCursor } from "./github-advisories.js";
import { githubImportError } from "./github.js";

export interface DependencyAdvisory {
  cve: string;
  advisories: {
    url: string;
    summary: string;
    overview?: string;
    packages: {
      ecosystem: string;
      name: string;
      vulnerableRange: string | null;
      fixedVersion: string | null;
      vulnerableFunctions?: readonly string[];
    }[];
  }[];
}

/** Keep a short, labeled opening paragraph, excluding code blocks and later sections. */
function openingOverview(description: string | null): string | undefined {
  const body = description?.trimStart();
  const heading = body?.match(
    /^#{1,6} +(summary|overview|impact)[ \t]*\r?\n(?:[ \t]*\r?\n)*/iu,
  );
  if (!body || !heading) return;
  const [paragraph] = body
    .slice(heading[0].length)
    .split(/\r?\n(?:[ \t]*\r?\n|(?=#))/u, 1);
  if (
    !paragraph ||
    paragraph.length > 800 ||
    /^(?:\s|[<>#~]|[-*+] |\d+\. )/mu.test(paragraph)
  )
    return;
  // Inline function names are useful applicability evidence. Leave code samples out.
  if (paragraph.replace(/`[\w.:-]+(?:\(\))?`/gu, "").includes("`")) return;
  return paragraph.trim().replaceAll(/\r?\n/gu, " ");
}

/** Look up the public CVE without sending the checkout location or credentials. */
export async function lookupDependencyAdvisory(
  input: string,
  signal?: AbortSignal,
  github = new Octokit(),
): Promise<DependencyAdvisory> {
  const cve = input.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/u.test(cve)) {
    throw new CodexSecurityError(
      "Expected a CVE ID, for example CVE-2023-4863.",
    );
  }
  const advisories: DependencyAdvisory["advisories"] = [];
  try {
    let after: string | undefined;
    const cursors = new Set<string>();
    do {
      signal?.throwIfAborted();
      const response = await github.request("GET /advisories", {
        cve_id: cve,
        per_page: 100,
        after,
        request: { signal, redirect: "error" },
      });
      for (const entry of response.data) {
        if (entry.cve_id !== cve || entry.withdrawn_at) continue;
        const overview = openingOverview(entry.description);
        advisories.push({
          url: entry.html_url,
          summary: entry.summary,
          ...(overview && { overview }),
          packages: (entry.vulnerabilities ?? []).flatMap((record) =>
            record.package?.name
              ? [
                  {
                    ecosystem: record.package.ecosystem,
                    name: record.package.name,
                    vulnerableRange: record.vulnerable_version_range,
                    fixedVersion: record.first_patched_version,
                    ...(record.vulnerable_functions?.length && {
                      vulnerableFunctions: record.vulnerable_functions,
                    }),
                  },
                ]
              : [],
          ),
        });
      }
      after = nextGitHubAdvisoryCursor(response.headers.link, cursors);
    } while (after !== undefined);
  } catch (error) {
    throw githubImportError(error, signal, {
      operation: "public advisory",
      denied:
        "GitHub denied the public advisory request. Check the API rate limit and retry.",
      notFound: `GitHub could not find a public advisory for ${cve}.`,
    });
  }
  if (!advisories.length) {
    throw new CodexSecurityError(
      `No active public GitHub advisory was found for ${cve}.`,
    );
  }
  return { cve, advisories };
}
