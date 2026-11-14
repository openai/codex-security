# Workbench remediation

When loading or refreshing an assigned finding, pass the supplied `scanId`, `occurrenceId`, `requestId`, and `actionToken` to `get_codex_security_scan_context`. Follow only the stage authorized by the workbench handoff. Apply the common requirements below and read the matching stage protocol before acting:

- Generate or Regenerate — [workbench-generate.md](workbench-generate.md)
- Apply — [workbench-apply.md](workbench-apply.md)
- Verify — [workbench-verify.md](workbench-verify.md)

In static mode the workbench setter's checkout snapshot and reverse check must also preserve source-only verification. Rule out executable filters in the applicable working-tree and index attributes, including any attribute changes in the reviewed patch, before requesting such an operation. Stop before the operation if that cannot be established.

Use `set_codex_security_finding_remediation` with the supplied workbench identity to record the stage outcome. If a stage fails, record `failed` with the failing step and error in `summary`. Include the setter's error when registration fails.

When a parent thread delegates a remediation stage, give the worker this reference and the stage protocol. The worker owns that stage through its terminal workbench update. The parent remains an orchestrator and must not duplicate the worker's edits or treat a chat response as completion.

## Tool and work copy isolation

Before creating or entering any work copy, select Python and Git from a controlled empty directory outside all checkouts. Verify that each trusted tool's absolute invocation path, resolved parent directory, and resolved executable are outside the selected target, its enclosing checkout, and all capture and rehearsal workspaces. Use the host-selected Python from `CODEX_SECURITY_PYTHON_COMMAND` when supplied. If absent, use a trusted absolute `PYTHON`, a host-managed runtime, or a verified system interpreter. Invoke its quoted absolute path with `-I` to import helpers from the installed plugin's scripts directory. From the same directory call `workbench_target.trusted_git_executable(target)`, which honors `CODEX_SECURITY_GIT` or discovers Git when that variable is absent. Pin the verified absolute invocation path it returns in the helper process's `CODEX_SECURITY_GIT` environment and pass it to child helpers. Stop if either tool cannot be verified. For workbench Generate and Apply Git commands, pass `offline=True` and the real target to `workbench_target.git_command`, use `-C` for the working directory, and set `-c core.hooksPath=<empty private directory>`.

Disable external Git filters for inline capture and any rehearsal in either verification mode. Identify drivers with a nonempty `clean`, `smudge`, or `process` command in the effective Git configuration of the real target and each private command's working directory. Write the overrides with `git config --file <file> <key> <value>` using separate arguments. Clear each driver's `clean`, `smudge`, and `process` commands. For staging and capture diffs, set `filter.<driver>.required` to true only if the driver was already required or had a `clean` or `process` command. For a rehearsal that writes files, use a separate override that also requires drivers with a `smudge` command. Pass `-c include.path=<absolute private config>` for the operation's overrides. Git will fail if it needs the driver, including after edits to `.gitattributes`. If capture requires external conversion, register an existing reviewed scan-local patch by path and digest when available, or record the failure.
