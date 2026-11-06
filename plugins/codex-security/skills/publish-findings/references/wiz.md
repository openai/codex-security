# Wiz findings

Read [Wiz import formats](wiz-import.md#finding-formats) before preparing input. Use an authorized [Wiz MCP](https://www.wiz.io/blog/introducing-wiz-mcp) or Wiz API connection; a configured plugin may provide it, but do not assume an official Codex plugin is available. Prefer supported native JSON. Inspect actual records, finish the requested pagination, and save only the selected evidence with its original occurrence IDs. A supplied export is also supported. Summaries, Wiz Issues, and local CLI scan results are not automatically supported finding records.

Validate the acquisition path against actual responses from an authorized Wiz tenant; local parser checks do not establish that qualification. Direct CSV input covers repository package vulnerabilities (SCA) only, not SAST or cloud posture findings, and does not provide a complete Wiz code-to-cloud integration.

Use a stable Wiz tenant/finding namespace as `--source-key`; a project filter does not create a new identity. Confirm the selected assets or builds belong to the destination repository. Do not infer source branches or revisions from the current checkout, invent missing evidence, or import vendor credentials, unrelated records, or local assessments as original scanner evidence. Do not retrieve or test credentials or apply suggested fixes.
