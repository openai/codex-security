import { Octokit } from "@octokit/core";
import { expect, mock, test } from "bun:test";
import { lookupDependencyAdvisory } from "../src/dependency-advisory.js";

const cve = "CVE-2000-1234";
const entry = {
  cve_id: cve,
  html_url: "https://github.com/advisories/GHSA-2345-6789-cfgh",
  withdrawn_at: null,
  summary: "Example advisory",
  description: "Provider body omitted from the model input.",
  vulnerabilities: [
    {
      package: { ecosystem: "npm", name: "fixture-package" },
      vulnerable_version_range: "< 2.0.0",
      first_patched_version: "2.0.0",
      vulnerable_functions: ["Parser.read"],
    },
  ],
};

test("looks up the exact public CVE anonymously and returns advisory facts", async () => {
  const requests: URL[] = [];
  const github = new Octokit({
    request: {
      fetch: async (
        resource: Parameters<typeof fetch>[0],
        init?: RequestInit,
      ) => {
        const url = new URL(
          resource instanceof Request ? resource.url : resource,
        );
        expect(url.origin + url.pathname).toBe(
          "https://api.github.com/advisories",
        );
        expect(url.searchParams.get("cve_id")).toBe(cve);
        expect(new Headers(init?.headers).has("authorization")).toBe(false);
        expect(init?.redirect).toBe("error");
        requests.push(url);
        return requests.length === 1
          ? Response.json([{ ...entry, withdrawn_at: "2001-01-01" }], {
              headers: {
                link: '<https://example.invalid/elsewhere?after=next>; rel="next"',
              },
            })
          : Response.json([
              {
                ...entry,
                description:
                  "## Summary\n\nOnly `Parser.read` uses the affected mode.\n\n## Reproduction\n\nExcluded details.",
              },
              { ...entry, cve_id: "CVE-2000-9999" },
            ]);
      },
    },
  });
  expect(
    await lookupDependencyAdvisory(cve.toLowerCase(), undefined, github),
  ).toEqual({
    cve,
    advisories: [
      {
        url: entry.html_url,
        summary: entry.summary,
        overview: "Only `Parser.read` uses the affected mode.",
        packages: [
          {
            ecosystem: "npm",
            name: "fixture-package",
            vulnerableRange: "< 2.0.0",
            fixedVersion: "2.0.0",
            vulnerableFunctions: ["Parser.read"],
          },
        ],
      },
    ],
  });
  expect(requests.map((url) => url.searchParams.get("after"))).toEqual([
    null,
    "next",
  ]);
});

test("leaves oversized paragraphs and code samples out of the overview", async () => {
  const records = [
    "### Impact\n\n" + "Example. ".repeat(100),
    "### Summary\n\n```js\nexample()\n```",
    "### Summary\n\nExample: `call(arg, value)`.",
  ].map((description) => ({ ...entry, description }));
  const github = new Octokit({
    request: { fetch: async () => Response.json(records) },
  });
  const result = await lookupDependencyAdvisory(cve, undefined, github);
  expect(result.advisories.map((record) => record.overview)).toEqual([
    undefined,
    undefined,
    undefined,
  ]);
});

test("public advisories with no package coordinates remain usable", async () => {
  const github = new Octokit({
    request: {
      fetch: async () => Response.json([{ ...entry, vulnerabilities: null }]),
    },
  });
  const result = await lookupDependencyAdvisory(cve, undefined, github);
  expect(result.advisories).toEqual([
    { url: entry.html_url, summary: entry.summary, packages: [] },
  ]);
});

test("errors for missing records, invalid IDs and cancellation", async () => {
  const read = mock(async () => Response.json([]));
  const github = new Octokit({ request: { fetch: read } });
  await expect(
    lookupDependencyAdvisory("path/private-repo", undefined, github),
  ).rejects.toThrow("Expected a CVE ID");
  const signal = AbortSignal.abort(new Error("cancelled"));
  await expect(lookupDependencyAdvisory(cve, signal, github)).rejects.toThrow(
    "cancelled",
  );
  expect(read).not.toHaveBeenCalled();
  await expect(
    lookupDependencyAdvisory(cve, undefined, github),
  ).rejects.toThrow("No active public GitHub advisory");
});
