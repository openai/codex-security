// Each group accepts any of its source excerpts. All groups are required.
export function excerpts(path, ...markers) {
  return markers.map((contains) => ({ path, contains }));
}

// Keep the historical skill's exact-quote rubric reproducible. The CLI
// grades the application identity and the facts deciding the scoped verdict.
export function skillOnly(...groups) {
  return { skillOnly: groups };
}

export function originalRubric(scenario) {
  const { identityEvidence, evidenceGroups } = scenario;
  return {
    ...scenario,
    skillEvidenceGroups: evidenceGroups.flatMap(
      (group) => group.skillOnly ?? [group],
    ),
    evidenceGroups: evidenceGroups.filter(
      (group) => !group.skillOnly && !identityEvidence.includes(group),
    ),
  };
}

export const mail390 = "3e1e0291d7757501d334d19fe6553a78b45cc1eb";
export const nodemailer7010 = "4175e4baf92ffc4e20791a11fc0886025228a2ac";
export const nodemailer7011 = "3d17dbec49ab3e3f0e13e62871e5534be5b99994";

export function nodemailerFile(source, revision = nodemailer7010) {
  return {
    kind: "git",
    repository: "nodemailer/nodemailer",
    revision,
    source,
    destination: `node_modules/nodemailer/${source}`,
  };
}

export const installedNodemailerVersion = excerpts(
  "node_modules/nodemailer/package.json",
  '"version": "7.0.10"',
);
