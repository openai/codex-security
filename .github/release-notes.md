<!-- release-version: 0.10.0 -->

<!-- release-section: highlights:start -->

## Highlights

<details>
<summary>Changes to review for highlights</summary>

- resolve home-relative project config paths on POSIX ([#2505](https://github.com/openai/codex-security/pull/2505))
- preserve literal paths when loading scan policy ([#2510](https://github.com/openai/codex-security/pull/2510))
- select a SQLite-capable Node runtime on Linux ([#2499](https://github.com/openai/codex-security/pull/2499))
- prevent stale SDK archives on long Windows paths ([#2511](https://github.com/openai/codex-security/pull/2511))
- follow directory links in selected project config paths ([#2514](https://github.com/openai/codex-security/pull/2514))
- report filesystem module failures during output validation ([#2516](https://github.com/openai/codex-security/pull/2516))
- build the bundled plugin in long Windows checkouts ([#2508](https://github.com/openai/codex-security/pull/2508))
- preserve Linux install path case in update notices ([#2521](https://github.com/openai/codex-security/pull/2521))
- resume Deep Scans interrupted before their first artifact ([#2515](https://github.com/openai/codex-security/pull/2515))
- create scan output for long POSIX repository names ([#2527](https://github.com/openai/codex-security/pull/2527))
- retry rolled-back plugin cache activation ([#2528](https://github.com/openai/codex-security/pull/2528))
- correct compressed session prerequisites ([#2546](https://github.com/openai/codex-security/pull/2546))
- save artifacts with long POSIX filenames ([#2533](https://github.com/openai/codex-security/pull/2533))
- explain the Alpine tar prerequisite in release checks ([#2536](https://github.com/openai/codex-security/pull/2536))
- archive long POSIX output directory names ([#2529](https://github.com/openai/codex-security/pull/2529))
- identify replaced checkout parent directories ([#2537](https://github.com/openai/codex-security/pull/2537))
- register nested Windows scans with long Git metadata paths ([#2534](https://github.com/openai/codex-security/pull/2534))
- preserve closed helper stdin under BusyBox ash ([#2540](https://github.com/openai/codex-security/pull/2540))
- preserve Continuum import retries and active sign-in credentials ([#2531](https://github.com/openai/codex-security/pull/2531))
- shorten the npm package README ([#2542](https://github.com/openai/codex-security/pull/2542))
- find system Python for Linux accounts without a home ([#2509](https://github.com/openai/codex-security/pull/2509))
- allow more time for npm package availability ([#2532](https://github.com/openai/codex-security/pull/2532))
- use the singular for one review round in Deep Scan stop reasons ([#2443](https://github.com/openai/codex-security/pull/2443))
- skip DOCX content control placeholder text ([#2490](https://github.com/openai/codex-security/pull/2490))
- publish new patch files on musl without hard links ([#2530](https://github.com/openai/codex-security/pull/2530))
- preserve Windows checkout identity across Python versions ([#2541](https://github.com/openai/codex-security/pull/2541))
- register local marketplaces in Codex homes containing a hash ([#2547](https://github.com/openai/codex-security/pull/2547))
- preserve whitespace in POSIX state directory overrides ([#2548](https://github.com/openai/codex-security/pull/2548))
- record the Wolfi Canvas 1.1.0 source and Skia notice ([#2549](https://github.com/openai/codex-security/pull/2549))
- preserve trailing whitespace in POSIX scan roots ([#2552](https://github.com/openai/codex-security/pull/2552))
- honor literal POSIX executable override paths ([#2551](https://github.com/openai/codex-security/pull/2551))
- preserve explicit usage database paths ([#2556](https://github.com/openai/codex-security/pull/2556))
- grant scan workers explicit source read access ([#2545](https://github.com/openai/codex-security/pull/2545))
- verify assumed-unchanged files for committed diffs ([#2554](https://github.com/openai/codex-security/pull/2554))
- resolve temporary paths before patching a saved checkout ([#2558](https://github.com/openai/codex-security/pull/2558))
- stage knowledge in the selected temporary directory ([#2559](https://github.com/openai/codex-security/pull/2559))
- isolate Git pathspec modes for file inventories ([#2565](https://github.com/openai/codex-security/pull/2565))
- read sealed artifacts in searchable Linux directories ([#2564](https://github.com/openai/codex-security/pull/2564))
- pin Git metadata on another Windows fixed drive ([#2539](https://github.com/openai/codex-security/pull/2539))
- preserve long Git metadata in reviewed patch replay ([#2543](https://github.com/openai/codex-security/pull/2543))
- reuse verified generated plugin cache content ([#2538](https://github.com/openai/codex-security/pull/2538))
- use UTF-8 for workbench responses and diagnostics ([#2566](https://github.com/openai/codex-security/pull/2566))
- report local failures from mock scans ([#2567](https://github.com/openai/codex-security/pull/2567))
- stage validated plugin ZIPs for scan workers ([#2507](https://github.com/openai/codex-security/pull/2507))
- tolerate executable metadata changes on first launch ([#2555](https://github.com/openai/codex-security/pull/2555))
- discover Python for targets when launched from filesystem root ([#2569](https://github.com/openai/codex-security/pull/2569))
- update the Linear SDK to 101.0.0 ([#2563](https://github.com/openai/codex-security/pull/2563))
- read deep sealed artifacts under Linux descriptor limits ([#2570](https://github.com/openai/codex-security/pull/2570))
- update semver to 7.8.6 across SDK and tooling ([#2562](https://github.com/openai/codex-security/pull/2562))
- update install-action to v2.90.0 ([#2561](https://github.com/openai/codex-security/pull/2561))
- isolate Git display settings in content snapshots ([#2568](https://github.com/openai/codex-security/pull/2568))
- preserve native filename bytes in SQLite URIs ([#2571](https://github.com/openai/codex-security/pull/2571))
- inventory policies in list-only POSIX directories ([#2572](https://github.com/openai/codex-security/pull/2572))
- compare ignored policy paths by their Git filename bytes ([#2573](https://github.com/openai/codex-security/pull/2573))
- require thread attachment for legacy scan continuations ([#2428](https://github.com/openai/codex-security/pull/2428))
- report exit status when the scan helper fails ([#2406](https://github.com/openai/codex-security/pull/2406))
- import hosted Semgrep findings locally or in Cloud ([#2576](https://github.com/openai/codex-security/pull/2576))
- reduce setup and tool output in Standard scans ([#2046](https://github.com/openai/codex-security/pull/2046))
- expose identifiers for saved scan follow-up ([#2577](https://github.com/openai/codex-security/pull/2577))
- validate scan inputs and verify hook installation ([#2578](https://github.com/openai/codex-security/pull/2578))
- update the active installation and migrate legacy options ([#2579](https://github.com/openai/codex-security/pull/2579))
- align scan schemas and structured output ([#2580](https://github.com/openai/codex-security/pull/2580))
- inspect integration commands before installation ([#2582](https://github.com/openai/codex-security/pull/2582))
- make command help and discovery reflect runnable workflows ([#2584](https://github.com/openai/codex-security/pull/2584))
- make project setup and authentication easier to inspect ([#2581](https://github.com/openai/codex-security/pull/2581))
- add a guide to security skills ([#2586](https://github.com/openai/codex-security/pull/2586))
- bump node-forge from 1.4.2 to 1.4.3 in /evals/triage-finding ([#2588](https://github.com/openai/codex-security/pull/2588))
- bump fast-xml-parser from 5.11.1 to 5.12.0 in /evals/triage-finding ([#2587](https://github.com/openai/codex-security/pull/2587))
- retain shared history across worktree changes ([#456](https://github.com/openai/codex-security/pull/456))
- update the Linear SDK to 101.1.0 ([#2601](https://github.com/openai/codex-security/pull/2601))
- update the Codex CLI and SDK to 0.167.1 ([#2600](https://github.com/openai/codex-security/pull/2600))
- honor scan budgets across batch attempts and follow-ups ([#2592](https://github.com/openai/codex-security/pull/2592))
- keep hosted patches uncommitted and report revision changes ([#2583](https://github.com/openai/codex-security/pull/2583))
- validate inputs and make plans and hooks reusable ([#2594](https://github.com/openai/codex-security/pull/2594))
- resolve saved scans in the current worktree ([#2590](https://github.com/openai/codex-security/pull/2590))
- resolve document links against selected sources ([#2430](https://github.com/openai/codex-security/pull/2430))
- resolve command paths and isolate standalone actions ([#2596](https://github.com/openai/codex-security/pull/2596))
- update install-action to v2.90.1 ([#2599](https://github.com/openai/codex-security/pull/2599))

</details>

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

<!-- Replace each candidate with the affected users and the action they need to take. -->

- preserve physical parent traversal ([#1709](https://github.com/openai/codex-security/pull/1709))
- make MCP targets and launchers explicit ([#2591](https://github.com/openai/codex-security/pull/2591))
- retire historical reader formats and Cloud checkpoints ([#2602](https://github.com/openai/codex-security/pull/2602))

<!-- release-section: upgrades:end -->
