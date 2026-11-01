import {
  gradeFailures,
  outputText as textFor,
  hasTriageJson,
} from "./output.mts";
import type { AssertionContext } from "../types.ts";

function repositoryName(value: string) {
  const path = value.includes("://")
    ? new URL(value).pathname
    : value.replace(/^(?:[^@/]+@)?[^/:]+:/, "");
  return path.replace(/^\/|\/$/g, "").replace(/\.git$/, "");
}

function endpointPattern(path: string, queryParts: string[] = []) {
  return (text: string, context: AssertionContext) => {
    const repository = repositoryName(context.vars.target_repo as string);
    const paths = [path, path.replace("{owner}/{repo}", repository)];
    return (
      paths.some((candidate) =>
        new RegExp(
          escapedLiteralPattern(candidate).source + "\\b(?![/-]|\\.\\w)",
          "i",
        ).test(text),
      ) && queryParts.every((part) => escapedLiteralPattern(part).test(text))
    );
  };
}

function escapedLiteralPattern(value: unknown) {
  return new RegExp(String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
}

function matchesRef(actual: unknown, expected: unknown) {
  return (
    typeof expected === "string" &&
    (actual === expected ||
      (expected.startsWith("refs/heads/") &&
        actual === expected.slice("refs/heads/".length)))
  );
}

function structuredAnswer(text: string) {
  try {
    return JSON.parse(
      text.trim().replace(/^```(?:json)?\s*([\s\S]*?)\s*```$/i, "$1"),
    );
  } catch {
    return null;
  }
}

function normalizesAs(text: string, sourceType: string) {
  const field = `(?:(?:"source_type"|'source_type'|\x60?source_type\x60?)[*_]*\\s*:\\s*|\x60?normalize as\\s+)`;
  const value = `(?:"${sourceType}"|'${sourceType}'|\x60${sourceType}\x60|${sourceType})`;
  const normalization = field + "[*_]*" + value + "\x60?";
  return new RegExp(
    `(?:^|[\\s{,(\\[])[*_]*${normalization}[*_]*(?=$|[\\s\x60,}.;:!?\\)\\]])`,
    "i",
  ).test(text);
}

const checks: Record<
  string,
  (text: string, context: AssertionContext) => string[]
> = {
  choose_source: (text) => {
    const failures = [];
    if (!/choose|specify|which|select/i.test(text)) {
      failures.push("must ask the user to choose or specify a GitHub source");
    }
    for (const pattern of [
      /code scanning/i,
      /Dependabot/i,
      /malware/i,
      /security advisories|advisories/i,
      /private (vulnerability )?reports?|private reports?/i,
      /\ball\b/i,
    ]) {
      if (!pattern.test(text)) {
        failures.push(`missing source option matching ${pattern}`);
      }
    }
    if (hasTriageJson(text)) {
      failures.push(
        "must not emit triage JSON before a GitHub source is selected",
      );
    }
    return failures;
  },

  project_repo_inference: (text, context) => {
    const failures = checks.choose_source(text, context);
    const expectedRepo = String(context.vars.expected_inferred_repo || "");

    if (
      !/Codex project.*(attached|GitHub)|attached.*Codex project|project.*attached.*GitHub/is.test(
        text,
      )
    ) {
      failures.push(
        "must say the GitHub repository is inferred from the attached Codex project",
      );
    }
    if (expectedRepo && !escapedLiteralPattern(expectedRepo).test(text)) {
      failures.push(`must include inferred GitHub repository ${expectedRepo}`);
    }
    if (
      /provide.*(owner\/repo|GitHub repository|repository URL)|ask.*(owner\/repo|GitHub repository|repository URL)/is.test(
        text,
      )
    ) {
      failures.push(
        "must not ask for a GitHub repository when the Codex project attached repo is available",
      );
    }
    return failures;
  },

  dependabot_malware: (text, context) => {
    const hasEndpoint = endpointPattern(
      "/repos/{owner}/{repo}/dependabot/alerts",
      ["classification=malware", "state=open", "per_page=100"],
    )(text, context);
    return [
      ...(!hasEndpoint
        ? [
            "must use Dependabot alerts endpoint with classification=malware, state=open, and per_page=100",
          ]
        : []),
      ...(!normalizesAs(text, "advisory")
        ? ["must say Dependabot malware normalizes as advisory"]
        : []),
    ];
  },

  code_scanning: (text, context) => {
    const answer = structuredAnswer(text);
    const defaultRef = context.vars.expected_default_ref;
    const alertsRef = answer?.alerts?.parameters?.ref;
    const repositories = [
      "{owner}/{repo}",
      repositoryName(context.vars.target_repo as string),
    ];
    const requestMatches = (
      request:
        | { path?: unknown; parameters?: { per_page?: unknown } }
        | null
        | undefined,
      suffix: string,
    ) =>
      request &&
      repositories.some(
        (repository) =>
          request.path === `/repos/${repository}/code-scanning/alerts${suffix}`,
      ) &&
      [100, "100"].some((value) => value === request.parameters?.per_page);
    return [
      ...(!requestMatches(answer?.alerts, "") ||
      answer?.alerts?.parameters?.state !== "open" ||
      !matchesRef(alertsRef, defaultRef)
        ? ["must describe open default-branch alerts with per_page=100"]
        : []),
      ...(!requestMatches(answer?.instances, "/{alert_number}/instances") ||
      !matchesRef(answer?.instances?.parameters?.ref, defaultRef)
        ? [
            "must scope per-alert instances to the default ref with per_page=100",
          ]
        : []),
      ...(answer?.source_type !== "sarif"
        ? ["must normalize code scanning as sarif"]
        : []),
      ...(Object.keys(answer ?? {}).length !== 3 || hasTriageJson(text)
        ? [
            "must return only alerts, instances, and source_type without triage JSON",
          ]
        : []),
    ];
  },

  advisories_private_reports: (text, context) => {
    const hasEndpoint = endpointPattern(
      "/repos/{owner}/{repo}/security-advisories",
      ["per_page=100"],
    )(text, context);
    const hasEachState = ["triage", "draft", "published", "closed"].every(
      (state) => new RegExp(`state=${state}`, "i").test(text),
    );
    return [
      ...(!hasEndpoint
        ? ["must use repository security advisories endpoint with per_page=100"]
        : []),
      ...(!hasEachState
        ? [
            "must include separate triage, draft, published, and closed advisory state requests",
          ]
        : []),
      ...(/state=\{triage\|draft\|published\|closed\}/i.test(text)
        ? [
            "must not combine advisory states in one state={triage|draft|published|closed} request",
          ]
        : []),
      ...(!/triage.*private vulnerability reports?|private vulnerability reports?.*triage/is.test(
        text,
      )
        ? ["must identify state=triage as private vulnerability reports"]
        : []),
      ...(!normalizesAs(text, "advisory")
        ? ["must say advisories/private reports normalize as advisory"]
        : []),
    ];
  },

  transport: (text, { vars }) => {
    const decision = structuredAnswer(text);
    const fields = Object.entries(vars.expected_decision ?? {});
    if (
      !decision ||
      !fields.length ||
      Object.keys(decision).length !== fields.length
    )
      return ["must return only the requested GitHub decision fields"];
    return fields
      .filter(([key, value]) => {
        if (key === "alerts_ref" || key === "instances_ref")
          return !matchesRef(decision[key], value);
        if (key === "account" && typeof value === "string")
          return (
            typeof decision[key] !== "string" ||
            decision[key].toLowerCase() !== value.toLowerCase()
          );
        return decision[key] !== value;
      })
      .map(([key, value]) => `expected ${key} to be ${value}`);
  },

  explicit_issue: (text) => {
    return [
      ...(!/GitHub Issues?.*(explicit|specific)|specific.*GitHub Issues?/is.test(
        text,
      )
        ? [
            "must say GitHub Issues are only used when explicitly/specially provided",
          ]
        : []),
      ...(!/not.*\ball\b|exclude.*\ball\b|do not include.*\ball\b/is.test(text)
        ? [
            "must say GitHub Issues are not included in all/default source selection",
          ]
        : []),
      ...(!normalizesAs(text, "freeform")
        ? ["must say explicit GitHub Issues normalize as freeform"]
        : []),
    ];
  },
};

export default (output: unknown, context: AssertionContext) => {
  const text = textFor(output);
  const behavior = String(context.vars.expected_github_rest_behavior || "");
  const check = Object.hasOwn(checks, behavior) ? checks[behavior] : undefined;
  const failures = check
    ? check(text, context)
    : [`unknown expected_github_rest_behavior: ${behavior}`];

  return gradeFailures(failures, "GitHub intake behavior matched.");
};
