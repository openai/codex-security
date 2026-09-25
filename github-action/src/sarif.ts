export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function safeSourcePath(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 &&
    !/[\\\x00-\x1f\x7f]/u.test(value) && !value.startsWith('/') &&
    !/^[a-z][a-z0-9+.-]*:/iu.test(value) &&
    value.split('/').every((part) => part !== '..' && part !== '' && part !== '.');
}

export function exportSarifArgs(scanDirectory: string, sourceRoot: string, outputPath: string): string[] {
  // Each item is an argv entry, not shell text. The caller supplies verified absolute paths.
  return ['export', scanDirectory, '--export-format', 'sarif', '--source-root', sourceRoot, '--output', outputPath];
}

/** Keep source references safe for publication without duplicating the CLI's SARIF contract. */
export function assertSafeSarif(value: unknown): void {
  const pending: unknown[] = [value];
  while (pending.length) {
    const item = pending.pop();
    if (Array.isArray(item)) { for (const child of item) pending.push(child); }
    else if (isRecord(item)) {
      for (const [key, child] of Object.entries(item)) {
        if (key === 'externalPropertyFileReferences' || key === 'originalUriBaseIds')
          throw new Error('External SARIF references are unsupported.');
        if (key === 'artifactLocation') {
          if (!isRecord(child) || typeof child.uri !== 'string' || child.uriBaseId !== undefined || child.index !== undefined ||
              !safeSourcePath(decodeURIComponent(child.uri))) throw new Error('Unsafe SARIF source location.');
        }
        if (typeof child === 'object' && child !== null) pending.push(child);
      }
    }
  }
}
