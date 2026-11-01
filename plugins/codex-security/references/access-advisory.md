# Daybreak Access Advisory

Use this optional advisory immediately before a scan's first substantive action. For Deep scans, call it before `start_codex_security_deep_scan`. Reuse the result when continuing the same scan.

Call `get_codex_security_daybreak_access` only if it is already available in the session. Skip silently when it is unavailable, or for a selected Amazon Bedrock provider or a known API-key-only session. Identify Bedrock from the selected provider, not the presence of AWS environment variables. Do not probe for another access tool or connector. This checks the connected ChatGPT account/workspace, not Bedrock access or access to local CLI results.

- Failed, `unknown`, or `stale: true`: continue silently without a speculative access warning.
- Fresh `granted`: report the status and available Daybreak programs.
- Fresh `not_granted`: before other scan-start progress, show a separate prominent warning that Daybreak access is not granted and protected scan outputs may not be displayable. Link the returned `enrollmentUrl`, falling back to `https://chatgpt.com/cyber`.

Continue regardless; the advisory never authorizes or gates a scan. Do not poll or repeat it between phases. If the user asks about access, report the result or its uncertainty. Recheck after an account/access change only when the user requests it and the tool is available.
