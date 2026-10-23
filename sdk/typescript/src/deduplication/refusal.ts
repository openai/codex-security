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
  // Structured transport failures take precedence over fallback refusal wording.
  if (
    codexErrorInfo !== null &&
    typeof codexErrorInfo === "object" &&
    [
      "httpConnectionFailed",
      "responseStreamConnectionFailed",
      "responseStreamDisconnected",
      "responseTooManyFailedAttempts",
    ].some((variant) => Object.hasOwn(codexErrorInfo, variant))
  )
    return false;
  const text = message.trim();
  const policyRefusal =
    /\b(?:cybersecurity|cyber|content|safety)[ _-]*policy\s*:\s*(?:(?:this|the|your)\s+)?(?:request|review)\s+(?:(?:is|was|has been)\s+)?(?:refused|blocked)\b([\s\S]*)$/iu.exec(
      text,
    );
  if (policyRefusal) {
    // The explicit refusal predicate decides; its explanation has no controlled vocabulary.
    // A leading service-outage cause still describes an operational failure.
    return !/^\s*(?:(?:(?:because|as|due to)\s+|[.!:]\s*)(?:the\s+)?(?:upstream\s+)?service\s+(?:is\s+)?(?:unavailable|unavailability|timed? out|timeout)\b|by\s+upstream\s+with\s+[45]\d{2}\b)/iu.test(
      policyRefusal[1] ?? "",
    );
  }
  return [
    /\bflagged for possible cybersecurity risk\b/iu,
    /\bflagged for potentially high-risk cyber activity\b/iu,
    /\bcyber[_\s-]?policy\b/iu,
    /\b(?:cybersecurity|cyber)[ _-]*policy[ _-]*(?:violation|refusal|refused)\b/iu,
    /(?:^(?:refusal|refused)|\b(?:request|review)\s+(?:refusal|(?:(?:is|was|has been)\s+)?(?:refused|blocked)))\s+(?:under|by|due to|because of|because (?:it|this request) violates|for violating|in accordance with)\s+(?:(?:the|a)\s+)?(?:cybersecurity|cyber|content|safety)[ _-]*policy\b/iu,
    /^(?:(?:this|the|your)\s+)?(?:request|review)(?:\s+(?:is|was|has been))?\s+(?:refusal|refused|blocked)\s*:\s*(?:(?:the|a)\s+)?(?:cybersecurity|cyber|content|safety)[ _-]*policy(?:[.!](?:\s+(?:I can offer|Please ask)\b[^\n]*)?)?$/iu,
    /^(?:cybersecurity|cyber|content|safety)[ _-]*policy\s*:\s*(?:(?:(?:this|the|your)\s+)?request\s+)?(?:(?:is|was|has been)\s+)?(?:violation|refusal|refused|blocked)[.!]?$/iu,
    /\b(?:cybersecurity|cyber|content|safety)[ _-]*policy\s+requires\s+(?:a\s+)?refusal\s+of\s+(?:(?:this|the|your)\s+)?(?:request|review)\b/iu,
    /\bunder\s+(?:(?:the|a)\s+)?(?:cybersecurity|cyber|content|safety)[ _-]*policy[, :]\s*(?:this|the|your) request (?:is|was|has been) (?:refused|blocked)\b/iu,
    /^(?:I(?:['’]m| am) sorry[,.:]?\s*(?:but\s+)?|Sorry[,.:]?\s*)?I(?:\s+(?:cannot|can['’]t|won['’]t|am (?:unable|not able) to)|['’]m (?:unable|not able) to)\s+(?:help|assist|comply)\b/iu,
  ].some((pattern) => pattern.test(text));
}
