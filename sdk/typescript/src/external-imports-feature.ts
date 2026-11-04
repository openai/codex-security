import { CodexSecurityError } from "./errors.js";

const flag = "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS";
export const externalImportsDisabledMessage = `External findings imports are disabled. Set ${flag}=1 to enable them.`;

export function importEnvironmentSetting<Value>(
  environment: Record<string, Value>,
  requested: string,
) {
  const exact = environment[requested];
  if (process.platform !== "win32") return { key: requested, value: exact };
  // A scan can override a case-insensitive process.env with its own spelling.
  function callerDeclares(key: string): boolean {
    for (
      let owner: object | null = environment;
      owner && owner !== process.env;
      owner = Object.getPrototypeOf(owner)
    ) {
      if (Object.hasOwn(owner, key)) return true;
    }
    return false;
  }
  if (exact !== undefined && callerDeclares(requested))
    return { key: requested, value: exact };
  // Node includes enumerable prototype keys and sorts competing spellings.
  const keys: string[] = [];
  for (const name in environment) {
    if (name.toUpperCase() === requested) keys.push(name);
  }
  keys.sort();
  const key = keys.find(callerDeclares) ?? keys[0];
  if (key !== undefined)
    return { key, value: key === requested ? exact : environment[key] };
}

export function externalImportsEnabled(
  environment: NodeJS.ProcessEnv = process.env,
): boolean {
  return importEnvironmentSetting(environment, flag)?.value === "1";
}

/** Preserve the selected flag while copying a caller's environment for a child. */
export function forwardExternalImportSetting<Value>(
  source: Record<string, Value | undefined>,
  child: Record<string, Value>,
): void {
  const selected = importEnvironmentSetting(source, flag);
  if (selected === undefined) return;
  if (process.platform === "win32") {
    for (const name of Object.keys(child)) {
      if (name !== selected.key && name.toUpperCase() === flag)
        delete child[name];
    }
  }
  if (selected.value !== undefined) child[selected.key] = selected.value;
}

export function requireExternalImports(environment?: NodeJS.ProcessEnv): void {
  if (!externalImportsEnabled(environment)) {
    throw new CodexSecurityError(externalImportsDisabledMessage);
  }
}
