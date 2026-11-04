# Runtime instructions

Use the instructions supplied for this invocation. For a command you will execute on the plugin host, request its topic from `get_codex_security_skill_instructions`. It returns the applicable installed instructions and leaves execution to the caller. Replace its placeholders with the selected arguments using the quoting rules shown.

For scan startup, pass `clientSurface: "desktop"` only when the host explicitly identifies itself as the Codex desktop app. Other callers use the default headless surface. A tool list or the operating system cannot establish that the client renders a desktop UI.

For a standalone skill without the instruction tool, or when the command runs on a different machine from the MCP server, use Node on the command executor to read the same instructions:

```text
node "<plugin_root>/scripts/skill_runtime.mjs" <topic>
```

For desktop scan lifecycle instructions, append `desktop`. The reader uses its own platform for command topics. Use the installed plugin root and the authorized target paths.

When only file reads are available, start at `<plugin_root>/templates/skill-runtime/`. For a command, read `windows/<topic>.md` on a Windows executor or `posix/<topic>.md` on a Unix executor. For a native scan, read the following files in order:

| Topic | Files |
| --- | --- |
| `standard-scan` | `<surface>/standard-scan.md`, then `native-scan.md` |
| `diff-scan` | `diff-scan.md`, then `native-scan.md` |
| `deep-scan` | `deep-scan.md` |

Use the surface established above (`desktop` or `headless`). Desktop scans also read `desktop/review-comments.md` for the final response.

Resolve `external-imports` with the running reader in the import command's environment before acquiring evidence. Static template files cannot establish that environment's opt-in.
