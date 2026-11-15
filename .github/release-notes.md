<!-- release-version: 0.10.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.10.0 gives clearer guidance when a patch is blocked, lets interrupted Standard scans resume, and adds a budget for batch scans.

- **Blocked patch results.** The patch prompt asks whether any files changed, what stopped the fix, and what to do next. When a fix depends on work outside the checkout, the result explains why the external change is needed and where it belongs when known. [#2609](https://github.com/openai/codex-security/pull/2609)
- **Standard scan setup.** Standard scans start with the vulnerability audit and load host-specific instructions when needed. Focused investigators receive their own briefs, and scan history records the file count from the scan's inventory. [#2046](https://github.com/openai/codex-security/pull/2046)
- **Resume interrupted Standard scans.** Run `codex-security scans resume SCAN_ID` to continue from a saved checkpoint in the original Codex session. The resumed scan retains its usage and budget. [#2610](https://github.com/openai/codex-security/pull/2610)
- **Batch scan budgets.** Set `--max-total-cost` on bulk or component scans to share one estimated budget across repositories or components, including retries and recoveries. In-flight work can exceed the estimate. [#2592](https://github.com/openai/codex-security/pull/2592)
- **Scanner imports and publication.** Import saved ArmorCode SAST findings into the local workbench. SDK callers can publish selected workbench finding versions to Cloud using retained evidence. [#2608](https://github.com/openai/codex-security/pull/2608) · [#2603](https://github.com/openai/codex-security/pull/2603)
- **Hosted remediation.** A hosted patch or verification that ends at a different commit reports `revision_changed` and retains its execution receipt. Retry from the requested revision. [#2583](https://github.com/openai/codex-security/pull/2583)

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

- **POSIX paths through symlinks.** Paths such as `link/../repo` now follow filesystem traversal. To resume an older bulk campaign whose source was normalized differently, enter its exact saved source path in the CSV. Use a new output directory to scan the corrected physical target. [#1709](https://github.com/openai/codex-security/pull/1709)
- **MCP registration scripts.** Pass `--all` if you relied on selecting all clients after automatic detection found none, or pass `--agent NAME` for one client. Use `--package NAME` for bare npm package names previously passed to `--command`. [#2591](https://github.com/openai/codex-security/pull/2591)
- **Archived scanner captures and Cloud retries.** Recollect Semgrep Platform v1 and Snyk REST v1 captures with the current collectors. Finish interrupted Cloud submissions with the client that created them. If the outcome is uncertain, check the inbox job or repository records before submitting again. [#2602](https://github.com/openai/codex-security/pull/2602)
- **Patch follow-ups with scan budgets.** Run patch preparation separately when a scan has a cost limit. The scan rejects an explicit patch follow-up and skips its interactive patch offer. [#2592](https://github.com/openai/codex-security/pull/2592)

<!-- release-section: upgrades:end -->
