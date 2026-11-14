export function gitlabPatchDescription(body: string): string {
  // GitLab ignores quick actions inside its native fenced blockquotes. Choose
  // a fence the report cannot close after quick-action CR removal; preserve its
  // original bytes and end the outer quote at EOF.
  let fenceLength = 3;
  for (const match of body.replaceAll("\r", "").matchAll(/^[ \t]*(>+)/gmu))
    fenceLength = Math.max(fenceLength, match[1]!.length + 1);
  return `${">".repeat(fenceLength)}\n${body}`;
}
