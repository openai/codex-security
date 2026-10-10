# Rich Finding Detail Fields

For every reportable finding in `findings.json`, preserve the validated reasoning and the exact source snippets that prove it. The Codex Security workspace renders these fields directly; it does not recover missing analysis from `report.md` or read source files after the scan.

## Writing Rules

- Lead the title and `summary` with the user action and product impact.
- Use `attackPath.summary` to briefly explain how to reproduce the issue.
- Explain how the code causes that product behavior in `rootCause.summary`. Use plain language and avoid repetition.
- Wrap RPC names, functions, types, fields, parameters, configuration keys, literal identifiers, and short expressions in single backticks. For example: `item/rename`, `itemId`, `title`, and `ItemStore.rename()`.
- Keep code out of prose. Put source snippets in `codeEvidence[].code`, then reference them from the section that explains why the snippet matters. The workspace consolidates those referenced snippets under **Root cause** so the violated invariant and its source proof stay together.
- Root cause must be a source-backed walkthrough, not a verdict paragraph. Start with the code where user-controlled data is declared, decoded, or read; follow each meaningful call, transformation, or state transition; then show the missing control, dangerous operation, and later consumer when it affects impact.
- Give each code-evidence item a stable `id`, a concise `label`, an exact source location, the smallest useful snippet, a `role`, and an `explanation`. Supported roles include `user_input`, `entrypoint`, `propagation`, `root_control`, `sink`, `outcome`, and `expected_control`.
- Write each `explanation` as connective reasoning: identify the attacker-controlled value at this step, say which callee or state receives it next, and explain why the shown lines preserve or violate the expected invariant.
- Order `rootCause.evidenceRefs` from user input to outcome. Put an `expected_control` comparison after the vulnerable call-stack refs; it is supporting context, not a step in the vulnerable stack. Omit incidental helpers that do not carry the value or enforce the relevant boundary.
- Do not use location-only filler such as "the root cause is tied to the broken control at path:line." The source table already records locations. Explain the violated invariant and show the code that violates it.
- Validation must connect attacker-controlled input, the missing or bypassed control, and the security-relevant state change or sink. Do not replace that proof with a list of file names and line numbers.
- Attack-path analysis must be concise. Record the realistic attacker boundary, the minimum trigger sequence, and the concrete outcome. Use code evidence for the important transitions instead of repeating the full validation narrative.
- Populate only evidence-backed fields. Omit unknown values instead of adding placeholders.

## Concise Workspace Projection

The finding detail view is a decision-focused projection of the canonical finding, not a copy of the full `vulnerability-writeup` report. Preserve the parts of that report that a reviewer needs to understand and act on the issue:

- the validation method, direct observations, confidence rationale, and remaining uncertainty;
- dataflow source, meaningful transformations, dangerous sink, and concrete outcome;
- realistic attacker, entry point, access requirements, preconditions, and attacker outcome;
- severity rationale plus the specific evidence that would raise or lower the rating;
- the minimal remediation invariant (`remediation`, a single string), plus `remediationTests` and `preventiveControls`, each an array of short strings with one regression test or preventive control per entry.

Keep background exposition, alternate exploit research, full PoC instructions, representative command output, and long source walkthroughs in the detailed write-up. Do not copy them into canonical fields merely to make the workspace report longer. The workspace should stay self-contained enough to support triage while avoiding duplicated or speculative prose.

The workspace **Evidence** section is an artifact navigator, not another source-proof section. When `writeup.reportPath` is present, the workbench lists that verified scan-local report plus regular files below its sibling `poc/` directory. Each write-up needs a separate parent directory so supporting files belong to one report. Each row opens the exact file in the editor through a host-mediated Codex navigation request. Do not place artifact paths in root-cause prose or add an unvalidated artifact list to the canonical finding merely for display.

## Structured Example

This fictional item-service fixture illustrates the field shape. Its paths, identifiers, snippets and scenario were invented for this example; they are not taken from a scan target or finding. Use the shape with your own validated source evidence.

```json
{
  "summary": "In this fictional item service, an authenticated caller can change another tenant's item title by supplying its item identifier. The write route never checks tenant ownership.",
  "codeEvidence": [
    {
      "id": "request-fields",
      "label": "Caller-controlled item fields",
      "path": "example_service/items.py",
      "startLine": 1,
      "endLine": 2,
      "language": "python",
      "role": "user_input",
      "code": "def rename_fields(body):\n    return body[\"itemId\"], body[\"title\"]",
      "explanation": "The fictional request body selects both the item and its replacement title."
    },
    {
      "id": "route-forward",
      "label": "Write route omits tenant ownership",
      "path": "example_service/items.py",
      "startLine": 7,
      "endLine": 9,
      "language": "python",
      "role": "entrypoint",
      "code": "def rename_item(request, store):\n    item_id, title = rename_fields(request.body)\n    store.rename(item_id, title)",
      "explanation": "The route passes the item identifier and title to the store without binding the authenticated tenant to that item."
    },
    {
      "id": "store-write",
      "label": "Store writes the selected item",
      "path": "example_service/items.py",
      "startLine": 13,
      "endLine": 14,
      "language": "python",
      "role": "root_control",
      "code": "def rename(self, item_id, title):\n    self.items[item_id].title = title",
      "explanation": "The store updates the selected object without an ownership check. A caller can select another tenant's fictional item."
    },
    {
      "id": "item-title",
      "label": "Later reads observe the replacement",
      "path": "example_service/items.py",
      "startLine": 17,
      "endLine": 18,
      "language": "python",
      "role": "outcome",
      "code": "def item_title(self, item_id):\n    return self.items[item_id].title",
      "explanation": "Later reads return the title written through the unchecked update."
    },
    {
      "id": "read-owner-check",
      "label": "Read route checks tenant ownership",
      "path": "example_service/items.py",
      "startLine": 21,
      "endLine": 25,
      "language": "python",
      "role": "expected_control",
      "code": "def read_item(request, store, item_id):\n    item = store.items[item_id]\n    if item.tenant_id != request.tenant_id:\n        raise PermissionError(\"Item belongs to another tenant\")\n    return item",
      "explanation": "The fictional read route compares the stored owner with the authenticated tenant. The write route needs the same invariant."
    }
  ],
  "rootCause": {
    "summary": "The read route enforces tenant ownership, but the rename route forwards caller-selected fields to a store operation that writes the item without that check.",
    "evidenceRefs": [
      "request-fields",
      "route-forward",
      "store-write",
      "item-title",
      "read-owner-check"
    ]
  },
  "validation": {
    "method": "static trace of the fictional fixture",
    "summary": "The illustrated request controls the item identifier. Neither the route nor the store checks its owner before replacing the title.",
    "evidenceRefs": [
      "request-fields",
      "route-forward",
      "store-write"
    ],
    "assertions": [
      "The write route does not compare the authenticated tenant with the item owner.",
      "The store updates the caller-selected item."
    ],
    "limitations": [
      "This example is invented to demonstrate the field shape; it is not a scan result."
    ]
  },
  "attackPath": {
    "summary": "A fictional authenticated caller submits item/rename with another tenant's item identifier and a replacement title.",
    "dataflow": {
      "summary": "request body -> rename_fields() -> rename_item() -> ItemStore.rename() -> item_title()",
      "source": "caller-selected item identifier and title",
      "sink": "the selected item's title",
      "outcome": "the other tenant's item title changes",
      "evidenceRefs": [
        "request-fields",
        "route-forward",
        "store-write",
        "item-title"
      ]
    },
    "reachability": {
      "summary": "The fictional caller needs access to the authenticated rename route and an item identifier belonging to another tenant.",
      "attacker": "authenticated caller in the invented service",
      "entrypoint": "item/rename",
      "outcome": "unauthorized modification of a fictional item"
    },
    "evidenceRefs": [
      "route-forward",
      "store-write",
      "item-title"
    ],
    "impact": {
      "level": "medium",
      "why": "The fictional failure permits cross-tenant modification of an item title."
    },
    "likelihood": {
      "level": "medium",
      "why": "The invented route accepts an item identifier from the caller."
    },
    "limitations": [
      "No real service, repository, scan target or finding is represented."
    ]
  },
  "remediation": "Check the selected item's tenant against the authenticated tenant before writing it; reuse the same ownership check on read and write routes.",
  "remediationTests": [
    "Reject a rename when the selected fictional item belongs to another tenant.",
    "Allow an owner to rename its own fictional item."
  ],
  "preventiveControls": [
    "Keep the tenant ownership invariant in a shared item-access operation."
  ]
}
```

`rootCause.code` and `rootCause.language` remain supported for older producers that can provide only one snippet. New producers should use the shared `codeEvidence` catalog, assign call-stack roles, and order `rootCause.evidenceRefs` from input to outcome so the same exact source can support Root Cause, Validation, and Attack-path analysis without copying it into several fields.
