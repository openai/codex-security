---
name: vulnerability-writeup
description: Write up vulnerabilities from disclosure documents, rough notes, supplied findings, PoCs, source code, or Codex Security scan output into polished, self-contained, source-backed reports. Use for one vulnerability or a disclosure campaign; a Codex Security scan is optional.
---

# Vulnerability Writeup

## Overview

Produce a distributable report set from rough vulnerability notes, PoCs, and source code. Treat this as a technical disclosure campaign: every distinct vulnerability gets its own directory, its own report, its own PoC artifacts,
and its own sub-agent draft. The desired output is not a cleaned-up note. It is a calm, expert narrative that proves the bug from source, explores how far the primitive can realistically be pushed, and ships with a PoC that another researcher can build and run.

Do not require a Codex Security scan, scan ID, manifest, findings JSON, coverage receipt, or seal. Ordinary disclosure documents and supplied vulnerability material are first-class inputs. When scan artifacts are present, use their validated fields as additional evidence; otherwise inventory the supplied documents directly and proceed with the same research and quality bar.

## Core Rules

- Use one sub-agent per vulnerability write-up. Do not assign multiple vulnerabilities to one worker.
- When this skill is used during Codex Security final reporting, the scan request is already authorization to launch the required one-finding write-up sub-agents. Do not ask for separate sub-agent authorization.
- The main agent owns inventory and deduplication. Workers receive only the single vulnerability they are writing.
- Review every sub-agent report yourself before accepting it.
- If a report falls short, run another sub-agent for that same vulnerability with the raw artifacts and a concise critique.
- Source access is mandatory for an excellent report. If the source tree or vulnerable revision is missing, stop and get it from the user unless the user explicitly accepts a lower-confidence report.
- Treat pre-captured source snippets as leads, not as the complete source of truth. Workers must inspect the target source tree or an exact revision snapshot before choosing final snippets.
- Never guess missing technical detail. Read source, inspect commits, run safe experiments, and clearly separate validated facts from hypotheses.
- Use lab or VM access only when it is explicitly authorized for this work.
  Never test against public or live production instances unless the user has explicitly instructed you to do so for that target.
- Make reports self-contained and distributable. Do not mention Drive,
  internal provenance, local absolute paths, or prior working folders.
- Write in the natural first-person voice of a professional vulnerability researcher. Use "we" throughout the technical walkthrough to guide the reader through source, state transitions, exploit ideas, and PoC behavior ("we first reach", "if we carry this value forward", "from here we control"). Include honest "I" statements for the work actually performed and its limits ("I reviewed revision", "I reproduced", "I could not run this without a VM"). Static review is work and may be stated as such. Never invent testing or personal observations. Do not sprinkle pronouns into otherwise impersonal prose merely to satisfy this rule; the report should feel genuinely narrated.
- Prefer readable, terminal-friendly line wrapping when it does not make the prose awkward. Do not let line length rules damage clarity, links, tables,
  code references, or the natural rhythm of the report.
- Prefer source-backed narrative over labels. Each report should tell the full story: trigger, vulnerable path, bad state, impact, PoC, and fix.
- Vulnerabilities sometimes have several different options for exploitation.
  Exploring and discussing alternative exploitation routes is often useful to include in a report even if it's not the best route or the one used for the PoC, so always include those discussions where they add interesting insights or explore ideas that otherwise wouldn't be covered. Where alternatives are covered, make the pros and cons clear, as one would expect in a technical discourse.
- Treat PoCs as first-class deliverables. The final report directory should contain clean PoC source, build/run instructions, representative output,
  and any reliability, cleanup, or target-environment notes the reader needs.
  If you feel it's not possible to develop a PoC, ask the user for guidance.

If the platform refuses to start more sub-agents, state that constraint to the user and queue the tasks. You should always delegate one report to one sub-agent. If a sub-agent starts but creates no files after one reasonable wait and one explicit finish instruction, close it and retry once with a tighter prompt for the same single vulnerability. If the retry also stalls,
mark the writeup phase blocked unless the user explicitly authorizes a main-agent fallback. Do not silently use a main-agent fallback for production scan completion.

## Inputs

Gather and preserve these inputs before drafting:

- raw vulnerability documents, exported text, or existing rough reports;
- supplied scanner findings or Codex Security finding bundles, when present;
- existing PoCs, scripts, crash logs, traces, and screenshots;
- the target source tree and exact vulnerable revision or release tag;
- a focused inventory of relevant source paths, functions, and revisions when available;
- fix commits, upstream diffs, or advisory text when available;
- lab access details such as SSH hosts, VMs, kernels, or test accounts;
- the user's authorization boundary for testing, especially whether any live target is in scope.

When the corpus comes from an external store (e.g. cloud storage or network paths), export the key text locally first. The final reports must not refer to external storage unless the user explicitly asks for provenance notes.

The produced write-ups must be distributable on their own and not assume access to other files or systems.

## Campaign Workflow

1. Create a destination directory, usually `reports` or the user-provided name. Use short, representative slug names.
2. Build an inventory of candidate documents and PoCs. Record title,
   subsystem, primitive, affected paths, and likely duplicates.
3. Deduplicate by root cause and vulnerable code path, not by document title.
   Merge notes and PoCs that describe the same bug.
4. Read `references/report-format.md` in full and use it as the report format.
   Instruct every worker to do the same before drafting.
5. Confirm that each distinct vulnerability has enough source context to let a worker trace the bug from entry point to bad state. Inspect the finding's recorded locations, reopen the source around each relevant boundary, and give the worker the focused paths, functions, revision, and short source excerpts it needs. If source access is missing, collect the missing files,
   revision, fix diff, or build instructions before drafting, or proceed at explicitly lower confidence when the user accepts that limitation.
6. If authorized lab access exists, record how to reach it and what safety limits apply. If it does not, instruct the worker to build or reason about PoCs locally and to state what could not be executed.
7. For each distinct vulnerability, create one directory containing an appropriately-named report file as markdown (e.g. `freebsd-shm-uaf.md`)
   and a `poc/` directory when PoCs exist. Don't just use a nondescript file name like `report.md`.
8. Launch exactly one sub-agent for that vulnerability. Give it the raw notes, focused source paths and excerpts, target source tree, vulnerable revision, PoCs, output directory, format rules, lab details, and authorization boundary. Do not give it other vulnerabilities.
9. Review the worker output immediately. Check technical correctness,
   completeness, line wrapping, self-contained wording, source snippets,
   exploitability depth, PoC usability, and narrative voice. Reject a report that is written as an impersonal sequence of facts, reserves "we" for one token sentence, or never states in first person what was and was not validated.
10. Reject snippets that cut off before the vulnerable condition, missing guard, dangerous sink, relevant lifetime transition, or proposed fixed invariant. Inspect source directly before asking the worker to rewrite. If the story is thin, incomplete,
   speculative, narratively compressed, impersonal, or missing a runnable PoC path, launch a new sub-agent for that same vulnerability with the raw inputs and the specific gaps to close.
11. Make only small main-agent edits after acceptance: heading fixes, line wrapping, command-path portability, and typo cleanup. Do not paper over a weak draft with surface edits.
12. Run final validation over the whole report set before returning.

## Sub-Agent Prompt

Use a prompt shaped like this for each vulnerability:

```text
Write one high-quality vulnerability disclosure report for <slug>.

You are responsible for exactly one vulnerability. Do not write about,
summarize, compare, or polish any other finding. Quality drops when one
worker handles multiple bugs, so keep all attention on this single report.

Inputs:
- Raw notes: <paths>
- Existing rough report, if any: <path>
- PoC artifacts: <paths>
- Focused source paths and excerpts: <paths and relevant functions>
- Target source tree: <path>
- Vulnerable revision/release: <revision>
- Fix commits/diffs, if any: <paths/revisions>
- Lab access: <ssh/vm details>
- Testing authorization boundary: <what is allowed and forbidden>
- Required format: `references/report-format.md`.
- Output directory: <reports-dir>/<slug>

Rules:
- Before drafting, open and read `references/report-format.md` in full. Its
  headings are the beginning of the assignment, not a completeness checklist.
- Analyze source and fixes directly; never guess. Trace the bug from the
  attacker-controlled entry point through the relevant state transitions to
  the bad state.
- Treat supplied snippets as starting points. If a snippet ends before the
  decisive branch, guard, sink, lifetime transition, or patch invariant,
  reopen the source tree and quote a complete short snippet instead.
- Use the source tree throughout the report. Include short, relevant snippets
  with file paths, functions, and enough surrounding explanation for a human
  reader to follow the path without opening the repository.
- Treat the rough notes as leads, not gospel. Validate each claim against the
  vulnerable source, the fix diff, or an experiment. Correct the notes when
  the source proves them incomplete or slightly wrong.
- Explore exploitability, not just reachability. Discuss viable primitives,
  constraints, allocator or protocol behavior, race windows, object lifetime,
  attacker-controlled bytes, reliability, and useful dead ends. Build small
  throwaway probes when they clarify an exploit path.
- Verify or improve the PoC when safe and authorized. Prefer disposable VMs
  or local test targets for crashes, corruption, LPE, data loss, or denial of
  service. Never run against public or live production instances unless the
  authorization boundary explicitly allows that target.
- Ship a polished final PoC in `poc/`. Include source, build files, a README
  when helpful, exact run commands using relative paths, required environment
  details, expected output, and notes on reliability or cleanup.
- Produce a self-contained report markdown file with no provenance references
  and no local absolute paths.
- Use a natural first-person researcher voice in the report itself. Guide the
  reader with "we" across the substantive walkthrough: introduce why each
  source excerpt matters, carry values and object state between functions,
  reason through exploit options, and explain PoC behavior. Do not leave the
  reader with a dense sequence of snippets and declarative conclusions.
- Include at least one truthful first-person-singular account of the validation
  basis and limits. For example: "I reviewed the vulnerable revision and fix
  directly, but I did not execute the panic trigger because no disposable VM
  was available." Mention builds, experiments, failures, or observations only
  when they actually happened.
- Give important transitions enough prose to teach why the evidence matters.
  Explore promising exploitation routes, relevant alternatives, constraints,
  and informative dead ends instead of collapsing exploitability into a verdict
  paragraph. Add depth where the bug warrants it; do not pad the report.
- Prefer readable prose wrapping, but do not contort technical language,
  links, tables, or code references to satisfy a fixed column width.
- Explain trigger, vulnerable path, bad state, impact, exploitability, PoC,
  and fix as one coherent narrative. The reader should feel calmly guided
  from background to source proof to practical demonstration.
- Use relative commands such as `cd poc` then `make`, not local absolute
  paths.
```

When re-running a weak report, add only the review deltas:

```text
The prior draft was too light on <specific gaps>. Rewrite from the raw
artifacts and source so the report reads as a complete technical story. Use
"we" to guide the actual source and exploitation walkthrough, and state with
"I" what you personally validated and what you could not test. Do not merely
add first-person phrases to the existing prose.
```

## Technical Analysis Standard

For each report, prove the vulnerability from the target source:

- identify the exact entry point and attacker-controlled inputs;
- follow data, lifetime, locking, bounds, and state transitions;
- quote short source snippets only when they clarify the path;
- inspect vulnerable release code with commands like `git show <rev>:<file>`;
- compare fix commits when available to confirm the intended invariant;
- describe the resulting kernel or application state precisely;
- calibrate impact to the validated primitive;
- name assumptions and unverified exploitability limits.

### Source Work

The worker should use the repository as a primary artifact:

- inspect the vulnerable revision, not just the current tree;
- use `git show <revision>:<path>` when the source tree is a Git checkout and the scanned revision is available;
- identify relevant compile-time options, configuration, permissions, and threat-model checks;
- search for sibling call sites and variants that help explain the invariant;
- include snippets from vulnerable code and, when useful, the fixing diff;
- keep snippets short and narrate the important lines before or after them.

### Exploitability Work

The Exploitability Analysis section should be thoughtful and specific. It may include unsuccessful branches when they teach the reader something important.
Useful lines of inquiry include:

- how to maximize attacker control over corrupted data or control flow;
- how allocator, scheduler, parser, cache, sandbox, or protocol behavior affects reliability;
- how to groom state before the trigger and stabilize state afterward;
- what information leaks, write gadgets, confused-deputy paths, or privilege boundaries might combine with the primitive;
- what constraints make a stronger exploit unlikely.

### PoC Work

Use the lab to build PoCs and run safe probes. For panic, wedge, corruption,
data-loss, or LPE cases, prefer disposable VMs and state the risk in the report. If a PoC cannot safely be run, at least verify that it builds or that its build recipe is coherent, and explain the missing execution condition.

A strong final PoC should be easy for the reader to run:

- place it under the report directory's `poc/` folder;
- include a `Makefile`, script, container recipe, or exact build command;
- include example commands from a clean checkout or unpacked report bundle;
- include representative output from a successful run;
- separate exploratory probes from the polished final PoC when both are kept;
- include cleanup or reset instructions when the PoC changes system state.

## Report Quality Bar

Every accepted report must follow the guidance in `references/report-format.md`.

The report should read like a complete story for a security engineer who has not seen the original notes. It should patiently walk the reader from the entry point to the vulnerable transition, the bad state, exploitation routes,
PoC behavior, and the fix. Avoid filler, generic variant-analysis endings,
and claims unsupported by source or experiment, but include thoughtful discussion and maintain a warm, professional attitude: the voice of one security researcher carefully explaining the work to another.

An excellent report usually has a few recognizable traits:

- The proof is layered. It establishes the actor, entry point, vulnerable check, bad transformation or state transition, sink, and fixed source shape in an order that feels easy to follow.
- Exploitability is treated as research. The report names attacker-controlled values, useful primitives, realistic routes, constraints, fallbacks,
  reliability dependencies, and dead ends that teach something.
- The PoC section separates diagnostic probes from the strongest exploit or demonstration path, gives a safe-first run order, and includes representative output.
- Remediation explains the invariant to restore, then gives minimal fixes,
  deeper structural hardening where useful, and regression tests that exercise the real vulnerable path.
- The language is precise, calm, and conversationally professional. It should not read like a terse scanner finding, a marketing advisory, or a pile of disconnected notes.
- The voice sounds like a researcher writing to peers. First-person plural carries the reader through the substantive source, exploitability, and PoC reasoning rather than appearing once as decoration. First-person singular gives an honest account of actual source review, validation work, failed attempts, and limits.
- The prose explains why each important transition matters. A complete set of headings, snippets, and conclusions is not enough when the connective reasoning remains implicit.

Before accepting a report, ask whether it reaches the excellent bar:

- Can a reader understand the affected component and threat model without the original notes?
- Does the report prove the vulnerable path from source and cite the exact functions, files, and revisions that matter?
- Are code snippets chosen because they illuminate the story, not because the report needed decoration?
- Does every snippet include the decisive line or branch it is meant to prove,
  rather than cutting off just before the vulnerability?
- Does the exploitability analysis explore multiple realistic paths,
  including constraints and dead ends that sharpen the conclusion?
- Is there a high-quality final PoC with build/run commands and example output, or a clear reason why execution was not authorized or safe?
- Does the remediation explain the invariant that must be restored and show a plausible minimal patch or defensive pattern?
- Does the report use a natural "we" voice through the walkthrough and include a truthful "I" account of what the author validated or could not test?
- Does the prose patiently connect the evidence, or does it still read like a technically correct but lightweight scanner expansion?

## Validation

Review the completed report set directly after drafting and after any rewrite.
Check every report against `references/report-format.md`, then run relevant project checks:

- `rg` for forbidden provenance terms and TODO markers;
- `rg -n '\b(we|We|I|our|Our|us)\b' <report>` as a quick signal for missing researcher voice, followed by a manual read for natural usage;
- `make -n` in every `poc/` directory (may need to run on the appropriate target system; doesn't necessarily need to build on whichever system the report is being written on);
- source commands used in the reports, when feasible;
- a parity check against the original report directory when rewriting.

Do not hand off until validation passes or the remaining failures are explicitly explained to the user.

A report with no natural first-person walkthrough, or no truthful singular account of the validation basis and limits, fails validation and must be rewritten. A mechanical pronoun match does not make an impersonal report pass.
