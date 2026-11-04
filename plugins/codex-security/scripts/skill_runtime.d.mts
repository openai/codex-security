export const skillRuntimeTopics: readonly [string, ...string[]];
export function readSkillRuntimeInstructions(
  pluginRoot: string,
  topic: string,
  context?: {
    platform?: NodeJS.Platform;
    clientSurface?: "desktop" | "headless";
  },
): Promise<string>;
