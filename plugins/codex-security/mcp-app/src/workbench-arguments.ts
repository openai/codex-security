export type WorkbenchFields = Record<
  string,
  string | number | boolean | readonly string[] | undefined
>;

export function workbenchArgs(
  command: string,
  fields: WorkbenchFields,
): string[] {
  const args = [command];
  for (const [name, value] of Object.entries(fields)) {
    if (value === undefined || value === false) continue;
    const flag = `--${name.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}`;
    (Array.isArray(value) ? value : [value]).forEach((item) => {
      if (item === true) args.push(flag);
      else {
        const scalar = String(item);
        if (scalar.startsWith("-")) args.push(`${flag}=${scalar}`);
        else args.push(flag, scalar);
      }
    });
  }
  return args;
}
