export const CANONICAL_GHSA_ID = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/u;
// File imports and CLI arguments also accept the original mixed-case spelling.
export const GHSA_ID = new RegExp(CANONICAL_GHSA_ID, "iu");

export function githubRepositoryParts(
  value: string,
): [string, string] | undefined {
  const match = /^([a-z0-9_.-]+)\/([a-z0-9_.-]+)$/iu.exec(value);
  if (match && !match.slice(1).some((part) => /^\.{1,2}$/u.test(part)))
    return [match[1]!, match[2]!];
}
