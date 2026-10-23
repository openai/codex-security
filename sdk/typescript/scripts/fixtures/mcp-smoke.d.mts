export const mcpSmokeInput: string;
export function mcpSmokeResponses(stdout: string): Array<{
  id?: number;
  result: { tools: unknown[] };
}>;
