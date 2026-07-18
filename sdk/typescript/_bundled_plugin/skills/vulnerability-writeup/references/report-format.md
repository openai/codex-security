# Vulnerability Report Format

Use this guide to write a comprehensive vulnerability report that covers the details of a vulnerability, considers options for exploitation and walks the reader through the most effective steps to trigger the bug.

The report should be written in markdown. Use language hints in code snippets to indicate programming language -- e.g. use ```c rather than just ```. Choose an appropriate file name for the report that makes it clear what the vulnerability is at a glance. For example, `freebsd-shm-ftruncate-uaf-lpe.md`.
Don't just choose the name `report.md` or anything nondescript like that.

Audience: other vulnerability researchers and security engineers with a deep knowledge of software exploitation and software development. The report must be written in clear English and use precise language. Be warm and somewhat friendly in the manner of your writing, but not overly familiar: as you'd expect a technical write-up to read from one expert to another. Don't sound robotic.

Use a natural first-person researcher voice. The report should regularly guide the reader with language such as "we first reach this branch", "if we carry this value into the next call", "from here we control the length field", or
"we can now compare this with the fixed path". Use that voice in the real source, exploitability, and PoC walkthrough—not only in an introduction or summary.

Use first-person singular for actual work the report author performed and for its limits, such as "I reviewed the vulnerable revision and the fixing diff",
"I reproduced this on", "I did not get a stable shell", or "I could not exercise this path without a kernel fault-injection hook". Every report must include a truthful singular account of its validation basis. Static source review counts; do not imply that code was built or executed when it was not.
Never invent personal observations.

First person is a narrative tool, not a quota. Do not retrofit an impersonal draft by scattering "we can see" through it. The reader should feel accompanied through the reasoning: why a snippet matters, what state we carry forward, why one exploitation route looks promising, and what an experiment did or did not establish.

Talk through the details that matter and don't gloss over things or skip them when they add value.

The quality target is the "excellent" style of report: a source-backed story that patiently proves the vulnerable path, explores exploitation like a researcher actually working the bug, and leaves the reader with artifacts they can build and run. Do not settle for a short triage note with section headings.

Excellent reports usually do these things:

- establish the actor, reachable entry point, affected component, and exact source/revision basis early;
- walk the reader through the relevant call chain or state machine before naming the bug;
- use short source snippets with file paths and function names, then explain the important lines in prose;
- show the bad state with concrete values, type conversions, lifetime edges,
  bounds, lock transitions, parser states, or protocol fields;
- compare the fixed source shape when a fix exists, and explain the invariant the fix restores;
- treat exploitability as research, not a verdict. Discuss promising paths,
  constraints, architecture or configuration dependencies, and dead ends that clarify the primitive;
- include small probes or exploratory PoCs when they helped refine the final exploit story;
- ship a clean final PoC with build/run commands and representative output.

Use readable prose wrapping. Terminal-friendly line lengths are welcome when they fit naturally, but do not damage clarity, links, tables, code references, or the rhythm of the explanation to satisfy a fixed column width.

The report must be written using the high-level structure that follows. Use the headings as there are listed here for each section and include sub-sections (and even sub-sub sections if really necessary) judiciously to cleanly and logically organise the content.

## Quality Bar

The report should feel like a warm, professional technical walk-through from one security researcher to another. It should not read like a scanner result,
a terse triage note, or a stitched-together collection of bullets. The reader should be guided through the component, the reachable entry point, the vulnerable transition, the bad state, exploitation options, PoC behavior, and the fix in a coherent order.

Strong write-ups generally have these qualities:

- The proof is layered: actor, entry point, relevant state, vulnerable check,
  bad transformation or lifetime edge, sink, and fixed source shape.
- Source snippets are short and purposeful. Each snippet should be introduced or explained so the important lines are obvious without opening the repository.
- Exploitability is explored like research. Discuss attacker-controlled values, useful primitives, realistic routes, constraints, fallbacks,
  reliability dependencies, and dead ends that clarify the primitive.
- PoC material is first-class. Separate diagnostic probes from the strongest final demonstration when both are included, give a safe-first run order,
  and include representative output.
- Remediation explains the invariant to restore before showing code. It should also name regression tests that exercise the real vulnerable path and nearby variants.
- The tone is calm, precise, and conversationally professional: confident enough to be useful, careful enough not to overclaim. The voice should feel like a researcher writing to peers, with natural "we" walkthrough language and honest "I" statements for experiments actually performed.
- The prose contains the connective reasoning between source excerpts and conclusions. A report that has all required headings but reduces the bug to a sequence of snippets, terse facts, and verdicts is still incomplete.
- The validation basis is personal and precise: what I inspected, built, ran,
  observed, or could not test. The rest of the technical story uses "we" to make difficult control flow and exploitation reasoning comfortable to follow.

The structure must contain the following headings:

1. **Executive Summary**: Summarise what the vulnerability is, which versions of the software are affected, what the impact is and what it allows an attacker to do. Include the validation basis: source revision, fixed revision if known, lab target, and what was or was not executed. State this basis in a truthful first-person-singular sentence (for example, "I reviewed revision X directly, but I did not execute the trigger"). If exact advisory names, CVEs, or patch-level claims are uncertain, say that rather than overstating them. As well as the affected versions, it's often interesting to note how long ago the vulnerability was introduced to give the reader a sense of how ubiquitous it is.

2. **Background**: Provide a technical background to set the scene. Describe,
   briefly, the relevant part of the software functionality. Assume the audience is technically strong, but not necessarily intimately familiar with the relevant part of the attack surface or threat model (including actors). This section should introduce the objects, callbacks, permission model, configuration, and normal invariants needed to understand the bug.
   Use source snippets here when they establish the reachable surface or the security boundary.

3. **Vulnerability Details**: Continue naturally on from the Background section, but now work towards a full-detail walk-through of how the vulnerable code is reached and what the issue is. Tie this in with the mise-en-scène established so far so that the story of who can reach the code, by what means, and how the relevant input carries through is clear to the reader. Prove the bug from source: entry point, attacker-controlled fields, checks that should have protected the path, the exact missed invariant, and the resulting bad state. Concrete arithmetic, type truncation, lifetime diagrams, state tables, or before/after values are often more persuasive than broad claims.

4. **Exploitability Analysis**: By this point, the reader understands the full threat model context of the vulnerability and the story of how the bad state can be reached. This section should now focus on how it's possible to maximally capitalise on the vulnerability: for example, if relevant, how does the underlying heap allocator work and be groomed to arrange data in a favourable manner, or what kind of control do we have over any objects/data we can corrupt, etc. This is an excellent opportunity for both drawing on prior art and also being creative in how unique aspects of the vulnerability can be tackled. Including diagrams and small, self-contained PoCs to trigger these aspects is especially useful. An excellent PoC demonstrates leveraging the vulnerability to the maximum within reason.
   E.g. dropping to a stable interactive root shell, or confidently leaking a pointer to something useful, or achieving reliable command injection, etc.
   (this will vary according to what the vulnerability is). Include multiple realistic exploitation routes when they exist. It is useful to preserve failed or partial branches when they teach an important constraint, such as allocator behavior, address-space layout, sandbox permissions, protocol sequencing, or object lifetime.

   Write this as an investigation rather than a severity verdict. Walk through the strongest route with "we", then discuss meaningful alternatives,
   reliability constraints, and dead ends when they sharpen the conclusion.
   Spend prose on the hard or surprising parts; do not pad simple mechanics.

5. **Proof of Concept**: This should tie together all of the exploration and creative process performed in the Exploitability Analysis section into a maximally-effective and stable proof-of-concept that can be used with minimal configuration against the target. Don't just mention that a PoC is included: describe the approach it takes, any notes about reliability, and provide sample output from building and running it. Include exact relative commands from the report directory, expected output on vulnerable and fixed targets when possible, target requirements, cleanup instructions, and a clear warning when the PoC can crash, corrupt, delete data, or escalate on the test machine. Keep exploratory probes separate from the polished final PoC when both are included.

6. **Remediation**: Explain the most effective way to patch the vulnerability.
   Include a minimal code snippet on a proposed patch that would fix it. Also make suggestions about how the surrounding structure or other parts of the project could be improved or hardened to prevent the vulnerability. Explain the invariant in plain technical terms before showing the patch, and point to regression tests that would catch the original failure and nearby variants. This is a good location to include diagrams or flow charts, for instance.

7. **Summary**: Summarise what the impact of the vulnerability is, why the vulnerability is present and what we demonstrated through the story told in this report. Suggest areas of future research, such as where variant analysis may be effective or whether some part of the codebase "feels"
   complex or underprotected.

The report must also be distributed with proof-of-concept artifacts. These should reside in a directory alongside the report and include the fully-functional, clean, high-quality proof-of-concept code plus any build files needed (e.g. a Makefile).

The PoC directory should be usable from an unpacked report bundle. Prefer relative commands such as:

```sh
cd poc
make
./exploit_or_probe
```

The report should include representative output, for example:

```text
[+] primitive reached
[+] target state validated
[+] current process is uid=0 euid=0
```

Do not include local absolute paths, internal note provenance, or references to the drafting process in the final report.
