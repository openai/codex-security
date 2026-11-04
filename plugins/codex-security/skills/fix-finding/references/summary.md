# Standalone fix summary

Report `fixed`, `no_change`, or `blocked`. Describe the vulnerable path, security invariant, and legitimate behavior to preserve. Explain why the chosen fix was the narrowest complete repository-native change, or identify the unresolved decision. List changed files, added tests or validation artifacts, and commands with their results. Separate source evidence from observed execution when explaining how the attack path was closed and legitimate behavior preserved. Report skipped checks and remaining uncertainty.

For a standalone summary with an existing scan directory, resolve the fix report path using [scan artifacts](../../../references/scan-artifacts.md) and write the report there. Otherwise return the summary in chat unless the user requests a file.
