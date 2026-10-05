export interface BuildBundledPluginOptions {
  contractPath?: string;
  destination?: string;
  source?: string;
}

export function buildBundledPlugin(
  options?: BuildBundledPluginOptions,
): Promise<string[]>;
