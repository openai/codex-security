/* Generated from plugin config-errors.ts. Run `pnpm generate:models`. */
/** Base error for Codex Security SDK failures. */
export class CodexSecurityError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class ConfigurationError extends CodexSecurityError {}
export class OutputDirectoryError extends CodexSecurityError {}
