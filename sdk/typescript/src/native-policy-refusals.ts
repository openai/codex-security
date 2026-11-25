/* Generated from plugin native-policy-refusals.ts. Run `pnpm generate:models`. */
// The SDK currently exposes only the message for turn errors. Match known
// terminal messages exactly so repository output embedded in another error
// cannot be mistaken for a permanent failure.
export const CYBERSECURITY_POLICY_REFUSAL_MESSAGES: ReadonlySet<string> =
  new Set([
    "Request blocked by cyberPolicy.",
    "Request blocked by a safety policy violation.",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. To get authorized for security work, join the Trusted Access for Cyber program: https://chatgpt.com/cyber",
    "This content was flagged for potentially high-risk cyber activity.",
    "This request has been flagged for possible cybersecurity risk.",
    "This request has been flagged for potentially high-risk cyber activity.",
    "This request was blocked due to a misalignment policy violation.",
  ]);
