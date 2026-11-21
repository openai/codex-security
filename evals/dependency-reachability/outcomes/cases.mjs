const applications = [
  {
    id: "backstage",
    repository: "backstage/backstage",
    revision: "99d7a6f42d71e86578c89c0669a3d962088ed8ae",
    service: "backstage-scaffolder",
    subject: "npm:vm2",
    sourceQuestion:
      "Which version of vm2 does the lockfile select for the scaffolder backend, and where does its template renderer construct the VM?",
    version: "3.9.19",
    evidence: [
      { path: "yarn.lock", line: 40050, endLine: 40051 },
      {
        path: "plugins/scaffolder-backend/src/lib/templating/SecureTemplater.ts",
        line: 147,
      },
    ],
  },
  {
    id: "superset",
    repository: "apache/superset",
    revision: "c35842e9f1c987d5e684969540fea3d8a5d03ad9",
    service: "superset-web",
    subject: "PyPI:sqlparse",
    sourceQuestion:
      "Which version of sqlparse do the base requirements pin, and where does ParsedQuery invoke the parser when constructed?",
    version: "0.4.4",
    evidence: [
      { path: "requirements/base.txt", line: 347 },
      { path: "superset/sql_parse.py", line: 280 },
    ],
  },
];

export const cases = applications.map(({ sourceQuestion, ...app }) => {
  const release = app.service + " at revision " + app.revision;
  return {
    ...app,
    description: "Review the provenance of the " + app.subject + " dependency in this application.",
    callerScope: [
      sourceQuestion,
      "Which immutable artifact does the release inventory record for " + release + "?",
      "Start with release_record. Include the full artifact digest and the evidence for it.",
      "Limit this investigation to inspecting source and the supplied synthetic inventory.",
      "Distinguish what the inventory establishes from evidence of actual execution.",
    ].join(" "),
    outcomes: [
      "Answer the source question with the selected version and citations to the version selection and application call.",
      "State the full artifact digest for " + release + " supported by a matching record from the supplied inventory.",
      "Scope the conclusion to the evidence. A recorded artifact establishes release identity. A claim about runtime execution requires a separate observation.",
    ],
  };
});
