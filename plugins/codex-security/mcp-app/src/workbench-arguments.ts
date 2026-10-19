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
      args.push(flag);
      if (item !== true) args.push(String(item));
    });
  }
  return args;
}
