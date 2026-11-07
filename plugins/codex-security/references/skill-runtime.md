# Runtime instructions

Use the instructions supplied by the caller. For a topic you need to resolve, call `get_codex_security_skill_instructions({ topic })` on the executor that will run the command. Run the returned command with the indicated placeholder quoting.

For scans, pass `clientSurface: "desktop"` when the host explicitly identifies itself as the Codex desktop app. The default is headless.

For standalone use or a shell on another host, set the command’s working directory to the installed plugin root and run `node ./scripts/skill_runtime.mjs <topic>`. Append `desktop` for a desktop scan.

For file-only access, read the applicable sections under `<plugin_root>/templates/skill-runtime/`.

- For a shell command, read the quoting instructions and the named topic in `windows.md` (PowerShell) or `posix.md` (POSIX shell).
- In `scans.md`, read the scan topic, using `standard-scan-<surface>` for Standard. Standard and Diff also use `checkpoints`. Desktop scans use `review-comments` for the final response.
