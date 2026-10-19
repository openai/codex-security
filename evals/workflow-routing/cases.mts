export const cases = [
  {
    id: "repository-default",
    request: "Check this repository for security vulnerabilities.",
    skill: "security-scan",
  },
  {
    id: "working-tree-diff",
    request: "Review my uncommitted changes for security vulnerabilities.",
    skill: "security-diff-scan",
  },
  {
    id: "explicit-deep",
    request: "Do an exhaustive, multi-pass security scan of this repository.",
    skill: "deep-security-scan",
  },
  {
    id: "existing-finding",
    request:
      "Triage this reported vulnerability against this repository: GET /invoices/:id exposes another user's invoice without checking ownership. Assess the claim; do not fix it.",
    skill: "triage-finding",
  },
  {
    id: "explicit-security-fix",
    request:
      "Fix and test this security finding: GET /invoices/:id exposes another user's invoice without checking ownership. Preserve legitimate owner access.",
    skill: "fix-finding",
  },
  {
    id: "explicit-fix-verification",
    request:
      "Verify that the existing security fix closes the reported cross-user invoice access in GET /invoices/:id. Check legitimate owner access too. Do not modify code.",
    skill: "verify-fix",
  },
  {
    id: "ordinary-bug-fix",
    request:
      "Fix the invoice table's incorrect alphabetical sort order and run its tests.",
    skill: null,
  },
  {
    id: "ordinary-test-run",
    request: "Verify that this refactor builds and its unit tests pass.",
    skill: null,
  },
] as const;

export type RoutingCase = (typeof cases)[number];

export function routingPrompt(scenario: RoutingCase) {
  return `${scenario.request}

This is a routing-only evaluation. Use the installed skills as you normally
would for the request above. Read the applicable workflow's SKILL.md, if any,
then stop before executing the workflow. Do not inspect application source,
run tests, edit files, start scans, or contact services. Briefly state the next
step; do not claim that the requested work has been completed.`;
}
