import { git, mixedRecords, reviewedCve } from "./fixtures.mjs";
import { sourceExcerpts } from "./report-reference.mjs";

// The records available at the server and its actual replies are independent
// of what the investigator chose to report.
export function mixedReportReference(id, { repo, sha }, calls = []) {
  const packageCheck = id === "mixed-package";
  const advisories = [
    {
      cve: reviewedCve,
      url: "https://github.com/advisories/GHSA-22p9-wv53-3rq4",
      condition:
        "linkify-it before 5.0.1. LinkifyIt.match can take quadratic CPU time when repeatedly scanning caller input with many fuzzy links or emails.",
    },
  ];
  if (packageCheck)
    advisories.push({
      cve: "CVE-2026-59887",
      url: "https://github.com/advisories/GHSA-v245-v573-v5vm",
      condition:
        "linkify-it before 5.0.2. Repeated mailto: validation in the match/test scan loop on caller text can take quadratic CPU time.",
    });
  const files = git(repo, "ls-tree", "--name-only", "-r", sha)
    .split("\n")
    .map((path) => ({ path }));
  return {
    question: packageCheck
      ? "Assess the known npm:linkify-it advisories in this repository for each service."
      : `Assess ${reviewedCve} in this repository for each service.`,
    sourceSha: sha,
    advisories,
    targets: advisories.flatMap(({ cve }) =>
      ["notes", "reviews"].map(
        (service) =>
          `Does ${cve} apply to the ${service} service's POST /preview handler, given its selected build, caller input and available runtime observations?`,
      ),
    ),
    sources: sourceExcerpts(repo, sha, files),
    notes: [
      "Both builds run server.mjs. Trace each Compose build argument to the manifests the Dockerfile copies and installs with npm ci. The selected locks differ.",
      "Trace caller text from POST /preview to the shared parser. Evaluate the installed version for each service against each advisory and distinguish a configured path from an observed running build and caller access.",
      "The report schema defines inputSource.exposure as Internet exposure of the actual input source. An anonymous request shows access by that caller. Establishing Internet exposure also requires the origin or network path.",
      "The availableRecords keys identify the query arguments. For each reply, check which service and revision its text actually describes. Match claims to the recorded replies and explain any material gaps in the observations. The fixture records are synthetic.",
    ],
    availableRecords: mixedRecords(id, sha),
    recordedReplies: calls,
  };
}
