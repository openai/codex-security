import type { StageFile } from "./cases.mts";
import type { EvidenceGroup } from "./grade.mts";

// Each group accepts any of its source excerpts. All groups are required.
export function excerpts(path: string, ...markers: string[]): EvidenceGroup {
  return markers.map((contains) => ({ path, contains }));
}

export const mail390 = "3e1e0291d7757501d334d19fe6553a78b45cc1eb";
export const nodemailer7010 = "4175e4baf92ffc4e20791a11fc0886025228a2ac";

export function nodemailerFile(
  source: string,
  revision = nodemailer7010,
): StageFile {
  return {
    kind: "git",
    repository: "nodemailer/nodemailer",
    revision,
    source,
    destination: `node_modules/nodemailer/${source}`,
  };
}

export const declaredNodemailerVersion = [
  ...excerpts("package.json", '"nodemailer": "7.0.10"'),
  ...excerpts(
    "package-lock.json",
    "nodemailer-7.0.10.tgz",
    '"nodemailer": "7.0.10"',
  ),
];
export const installedNodemailerVersion = excerpts(
  "node_modules/nodemailer/package.json",
  '"version": "7.0.10"',
);
