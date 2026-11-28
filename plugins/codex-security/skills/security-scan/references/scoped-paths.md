# Scoped source input

For SDK scans, generate the inventory in the scan shell for both file and directory scopes. Use a prepared inventory when another host supplies one. Run a supplied inventory command as given. For `make-hosted-repo-scope-input`, use the path it reports. Run the supplied recovery command only if that path is missing or unreadable in a later shell.

For an SDK scan with a target-paths file, run the [`scope-inventory` command](../../../references/skill-runtime.md) using the registered environment. Other hosts can pass the bound plugin, repository, scope-file and scan-directory paths as environment values for this command, or invoke the launcher with the same arguments as separate values.

Treat the scope file as data. Do not print, modify, or evaluate it. The inventory includes directly requested files and non-ignored descendants of requested directories. Pass it to reviewers without widening scope. For an SDK scan, immediately after the initial helper succeeds, emit the parent's standalone `CODEX_SECURITY_SCAN_PROGRESS` line with phase `discovery`, zero files completed, and the helper's reported count as the total. Emit it before reviewing any files or dispatching workers. Determine coverage from the registered scope and the files actually reviewed. If resolution fails, surface the error and stop before source review.
