function textFor(output) {
  return typeof output === "string" ? output : JSON.stringify(output);
}

function containsAll(text, patterns) {
  return patterns.every((pattern) => pattern.test(text));
}

function hasTriageJson(text) {
  return (
    /```(?:json)?\s*[\s\S]*?```/i.test(text) ||
    /schema_version\s*["']?\s*:\s*["']?triage-finding\/v0/i.test(text) ||
    /["']findings["']\s*:/i.test(text) ||
    /["']verdict["']\s*:/i.test(text)
  );
}

function endpointPattern(path, queryParts = []) {
  const escapedPath = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const queryPatterns = queryParts.map((part) => new RegExp(part, "i"));
  return (text) => new RegExp(escapedPath, "i").test(text) && containsAll(text, queryPatterns);
}

function escapedLiteralPattern(value) {
  return new RegExp(String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
}

const checks = {
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
      failures.push("must not emit triage JSON before a GitHub source is selected");
    }
    return failures;
  },

  project_repo_inference: (text, context) => {
    const failures = checks.choose_source(text);
    const expectedRepo = String(context.vars.expected_inferred_repo || "");

    if (!/Codex project.*(attached|GitHub)|attached.*Codex project|project.*attached.*GitHub/is.test(text)) {
      failures.push("must say the GitHub repository is inferred from the attached Codex project");
    }
    if (expectedRepo && !escapedLiteralPattern(expectedRepo).test(text)) {
      failures.push(`must include inferred GitHub repository ${expectedRepo}`);
    }
    if (/provide.*(owner\/repo|GitHub repository|repository URL)|ask.*(owner\/repo|GitHub repository|repository URL)/is.test(text)) {
      failures.push("must not ask for a GitHub repository when the Codex project attached repo is available");
    }
    return failures;
  },

  dependabot_malware: (text) => {
    const hasEndpoint = endpointPattern("/repos/{owner}/{repo}/dependabot/alerts", [
      "classification=malware",
      "state=open",
      "per_page=100",
    ])(text);
    return [
      ...(!hasEndpoint
        ? ["must use Dependabot alerts endpoint with classification=malware, state=open, and per_page=100"]
        : []),
      ...(!/source_type:\s*`?advisory`?|normalize as `?advisory`?/i.test(text)
        ? ["must say Dependabot malware normalizes as advisory"]
        : []),
    ];
  },

  code_scanning: (text) => {
    const hasAlerts = endpointPattern("/repos/{owner}/{repo}/code-scanning/alerts", [
      "state=open",
      "per_page=100",
    ])(text);
    const hasInstances = /code-scanning\/alerts\/\{alert_number\}\/instances/i.test(text);
    return [
      ...(!hasAlerts ? ["must use code scanning alerts endpoint with state=open and per_page=100"] : []),
      ...(!hasInstances ? ["must fetch code scanning alert instances per alert"] : []),
      ...(!/source_type:\s*`?sarif`?|normalize as `?sarif`?/i.test(text)
        ? ["must say code scanning normalizes as sarif"]
        : []),
    ];
  },

  advisories_private_reports: (text) => {
    const hasEndpoint = endpointPattern("/repos/{owner}/{repo}/security-advisories", [
      "per_page=100",
    ])(text);
    const hasEachState = ["triage", "draft", "published", "closed"].every((state) =>
      new RegExp(`state=${state}`, "i").test(text),
    );
    return [
      ...(!hasEndpoint ? ["must use repository security advisories endpoint with per_page=100"] : []),
      ...(!hasEachState ? ["must include separate triage, draft, published, and closed advisory state requests"] : []),
      ...(/state=\{triage\|draft\|published\|closed\}/i.test(text)
        ? ["must not combine advisory states in one state={triage|draft|published|closed} request"]
        : []),
      ...(!/triage.*private vulnerability reports?|private vulnerability reports?.*triage/is.test(text)
        ? ["must identify state=triage as private vulnerability reports"]
        : []),
      ...(!/source_type:\s*`?advisory`?|normalize as `?advisory`?/i.test(text)
        ? ["must say advisories/private reports normalize as advisory"]
        : []),
    ];
  },

  connector_rest_only: (text) => {
    return [
      ...(!/GitHub Connector.*token|connector.*auth token|token.*GitHub Connector/is.test(text)
        ? ["must allow GitHub Connector only as an auth token source"]
        : []),
      ...(!/REST/i.test(text) ? ["must state that finding retrieval uses REST"] : []),
      ...(!/do not use.*GitHub Connector.*(fetch|retrieve|data|findings)|GitHub Connector.*not.*(fetch|retrieve|data|findings)/is.test(text)
        ? ["must say not to use the GitHub Connector for finding retrieval"]
        : []),
    ];
  },

  explicit_issue: (text) => {
    return [
      ...(!/GitHub Issues?.*(explicit|specific)|specific.*GitHub Issues?/is.test(text)
        ? ["must say GitHub Issues are only used when explicitly/specially provided"]
        : []),
      ...(!/not.*\ball\b|exclude.*\ball\b|do not include.*\ball\b/is.test(text)
        ? ["must say GitHub Issues are not included in all/default source selection"]
        : []),
      ...(!/source_type:\s*`?freeform`?|normalize as `?freeform`?/i.test(text)
        ? ["must say explicit GitHub Issues normalize as freeform"]
        : []),
    ];
  },
};

module.exports = (output, context) => {
  const text = textFor(output);
  const behavior = String(context.vars.expected_github_rest_behavior || "");
  const check = checks[behavior];
  const failures = check ? check(text, context) : [`unknown expected_github_rest_behavior: ${behavior}`];

  return {
    pass: failures.length === 0,
    score: failures.length === 0 ? 1 : 0,
    reason: failures.length === 0 ? "GitHub REST intake behavior matched." : failures.join("; "),
  };
};
