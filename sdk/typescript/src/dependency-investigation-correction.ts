import { CodexSecurityError } from "./errors.js";

type Submission<Report, Feedback> =
  | { status: "approved"; report: Report }
  | { status: "correction"; feedback: Feedback };

// Fresh model calls carry explicit feedback. A session that can continue its
// thread manages its own longer submission budget.
export async function finishOneShotInvestigation<Draft, Report, Feedback>(
  draft: Draft,
  submit: (
    draft: Draft,
    canCorrect: boolean,
  ) => Promise<Submission<Report, Feedback>>,
  revise: (draft: Draft, feedback: Feedback) => Promise<Draft>,
): Promise<Report> {
  const maxSubmissions = 3;
  for (let attempt = 1; attempt <= maxSubmissions; attempt++) {
    const canCorrect = attempt < maxSubmissions;
    const result = await submit(draft, canCorrect);
    if (result.status === "approved") return result.report;
    if (!canCorrect) break;
    draft = await revise(draft, result.feedback);
  }
  throw new CodexSecurityError("Investigation corrections were exhausted.");
}
