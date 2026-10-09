import { readFile, writeFile } from "node:fs/promises";

export async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

export async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function parseJsonLines<T = ReturnType<typeof JSON.parse>>(
  text: string,
): T[] {
  return text
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as T);
}

export function jsonLines(values: readonly unknown[]): string {
  return values.map((value) => JSON.stringify(value)).join("\n");
}

export const writeJsonLines = (path: string, values: readonly unknown[]) =>
  writeFile(path, jsonLines(values));

export const readJsonLines = async <T = ReturnType<typeof JSON.parse>>(
  path: string,
) => parseJsonLines<T>(await readFile(path, "utf8"));
