import * as fsPromises from "node:fs/promises";
import { mock } from "bun:test";

export const mockFs = (overrides: () => object) =>
  mock.module("node:fs/promises", () => ({ ...fsPromises, ...overrides() }));

export const restoreFs = (overrides: Partial<typeof fsPromises>) =>
  mockFs(() => overrides);
