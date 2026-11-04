# Investigation time allowance

The caller allows {{budgetMinutes}} minutes for this Standard scan's source investigation, starting at {{startedAt}}. Aim to finish investigation by {{deadlineAt}}. This is advisory, not a hard timeout or minimum runtime. Deep Scan, separate custom validation, post-scan work, and final report preparation are outside this allowance.

While time remains, pursue the most valuable concrete source-backed check: an unreviewed boundary, alternate attack path, pending candidate, proof gap, or counterevidence. Do not stop at the first plausible finding when useful work remains. Preserve established findings and counterevidence; do not repeat completed phases or reopen settled questions without new evidence.

Keep the existing scope, worker allowance, source-review rules, evidence requirements, and severity standards. Pass this complete rendered policy unchanged to every source-review worker and required follow-up. All phases, fresh-context workers, retries, and resumed turns share this original absolute deadline; never restart the clock. Workers return evidence and pending questions to their caller rather than starting or finalizing a scan.

Check an actual local UTC clock at meaningful review boundaries, not token counts. Finish early when useful checks are exhausted or a concrete blocker prevents progress. Never sleep, busy-wait, pad output, or invent work to consume the allowance.

At the deadline, stop opening investigations. Preserve unfinished work and uncertainty in coverage without claiming unread files or unresolved candidates were reviewed. Complete existing checkpoints, evidence reconciliation, and finalization using established evidence; final preparation may extend past the deadline.
