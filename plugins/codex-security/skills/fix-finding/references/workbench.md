# Workbench remediation

Follow only the stage authorized by the workbench handoff. Before any stage action, read the matching protocol:

- Generate or Regenerate — [workbench-generate.md](workbench-generate.md)
- Apply — [workbench-apply.md](workbench-apply.md)
- Verify — [workbench-verify.md](workbench-verify.md)

In static mode the workbench setter's checkout snapshot and reverse check must also preserve source-only verification. Rule out executable filters in the applicable working-tree and index attributes, including any attribute changes in the reviewed patch, before requesting such an operation. Stop before the operation if that cannot be established.

Use `set_codex_security_finding_remediation` with the supplied workbench identity to record the stage outcome. If a stage fails, record `failed` with the failing step and error in `summary`. Include the setter's error when registration fails.

When a parent thread delegates a remediation stage, the worker owns that stage through its terminal workbench update. The parent remains an orchestrator and must not duplicate the worker's edits or treat a chat response as completion.
