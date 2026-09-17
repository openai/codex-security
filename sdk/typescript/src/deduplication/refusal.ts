/** Recognize policy blocks and explicit refusal responses, not ordinary review failures. */
export function isReviewRefusal(message: string): boolean {
  return [
    /\bflagged for possible cybersecurity risk\b/iu,
    /\bflagged for potentially high-risk cyber activity\b/iu,
    /\bcyber[_\s-]?policy\b/iu,
    /\b(?:cybersecurity|cyber|content|safety)[ _-]*policy[ _-]*(?:violation|refusal|refused)\b/iu,
    /\b(?:refusal|refused)\b[^\n]*\b(?:cybersecurity|cyber|safety policy)\b/iu,
    /\b(?:cybersecurity|cyber|safety policy)\b[^\n]*\b(?:refusal|refused)\b/iu,
    /^(?:I(?:['’]m| am) sorry[,.:]?\s*(?:but\s+)?|Sorry[,.:]?\s*)?I(?:\s+(?:cannot|can['’]t|won['’]t|am unable to)|['’]m unable to)\s+(?:help|assist|comply)\b/iu,
  ].some((pattern) => pattern.test(message.trim()));
}
