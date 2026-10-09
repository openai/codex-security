/** Recognize policy blocks and explicit refusal responses, not ordinary review failures. */
export function isReviewRefusal(
  message: string,
  codexErrorInfo?: unknown,
): boolean {
  if (
    codexErrorInfo === "cyberPolicy" ||
    codexErrorInfo === "misalignmentPolicyViolation"
  )
    return true;
  return [
    /\bflagged for possible cybersecurity risk\b/iu,
    /\bflagged for potentially high-risk cyber activity\b/iu,
    /\bcyber[_\s-]?policy\b/iu,
    /\b(?:cybersecurity|cyber|content|safety)[ _-]*policy[ _-]*(?:violation|refusal|refused)\b/iu,
    /(?:^refusal|\b(?:request|review)\s+(?:refusal|(?:(?:is|was|has been)\s+)?(?:refused|blocked)))\s+(?:under|by|due to|because of|because (?:it|this request) violates|for violating|in accordance with)\s+(?:(?:the|a)\s+)?(?:cybersecurity|cyber|content|safety)[ _-]*policy\b/iu,
    /\b(?:cybersecurity|cyber|content|safety)[ _-]*policy\s+requires\s+(?:a\s+)?refusal\b/iu,
    /\b(?:cybersecurity|cyber|content|safety)[ _-]*policy\s*:\s*(?:this|the|your) request (?:is|was|has been) (?:refused|blocked)\b/iu,
    /\bunder\s+(?:(?:the|a)\s+)?(?:cybersecurity|cyber|content|safety)[ _-]*policy[, :]\s*(?:this|the|your) request (?:is|was|has been) (?:refused|blocked)\b/iu,
    /^(?:I(?:['’]m| am) sorry[,.:]?\s*(?:but\s+)?|Sorry[,.:]?\s*)?I(?:\s+(?:cannot|can['’]t|won['’]t|am (?:unable|not able) to)|['’]m (?:unable|not able) to)\s+(?:help|assist|comply)\b/iu,
  ].some((pattern) => pattern.test(message.trim()));
}
