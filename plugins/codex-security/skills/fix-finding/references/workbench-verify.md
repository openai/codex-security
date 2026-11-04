# Verify the workbench patch

Do not modify source. Apply the selected mode's verification gates against the recorded patch. Record `verified` only when evidence establishes that the original vulnerable path is closed, legitimate behavior remains intact, and the required checks pass; preserve exact evidence and any commands run in the verification summary. Otherwise record `failed` and state the failing gate or proof gap. Do not close the finding.
