import { z } from "zod";
import {
  createDependencySourceWorkTools,
  sourceWorkMutationSchema,
  sourceWorkQuerySchema,
} from "./dependency-source-worklist.js";
import {
  dependencySourceNoteQuerySchema,
  dependencySourceNoteSchema,
} from "./dependency-stack-evidence.js";
import { isRecord } from "./record.js";

export { createDependencySourceWorkTools };

type Tool = {
  name: string;
  description: string;
  inputSchema: object;
  run(input: unknown): unknown;
};

const graphActions = {
  query: {
    name: "query_codex_security_graph",
    description:
      "Pass note or sourceWork as the only argument when querying shared research. Use note:{search} to find notes, note:{} to list them, or note:{id} to read pinned excerpts. Use sourceWork:{} for coverage counts, or sourceWork:{rosterId} or {partitionId} with page:{view,limit,cursor} for paths and gaps.",
    fields: {
      note: dependencySourceNoteQuerySchema,
      sourceWork: sourceWorkQuerySchema,
    },
  },
  update: {
    name: "update_codex_security_graph",
    description:
      "Pass exactly one of note or sourceWork. A note shares a question, scope and assertion with exact line ranges from the pinned checkout. Use sourceWork to record search results, resolve gaps, assign files or mark paths examined. For append_roster_page, omit expectedRevision on the first page and supply the current roster revision on later pages. Set declaredComplete to true when no gaps remain across all pages, and false when any gap remains open.",
    fields: {
      note: dependencySourceNoteSchema,
      sourceWork: sourceWorkMutationSchema,
    },
  },
};

export function withInvestigationGraphTools(
  tools: Tool[],
  sourceWork: ReturnType<typeof createDependencySourceWorkTools>,
  readOnly: boolean,
  notes: {
    query(input: unknown): unknown;
    update(input: unknown): unknown;
  },
): Tool[] {
  function graphTool(action: keyof typeof graphActions, base?: Tool): Tool {
    const { name, description, fields } = graphActions[action];
    const { properties } = z.toJSONSchema(z.strictObject(fields).partial());
    const baseSchema = base?.inputSchema as { properties?: object } | undefined;
    return {
      name,
      description: base ? base.description + " " + description : description,
      inputSchema: {
        type: "object",
        properties: { ...baseSchema?.properties, ...properties },
        additionalProperties: false,
        ...(!base && { minProperties: 1, maxProperties: 1 }),
      },
      run(input) {
        if (isRecord(input)) {
          const note = Object.hasOwn(input, "note");
          const work = Object.hasOwn(input, "sourceWork");
          if (!note && !work && base) return base.run(input);
          if (Object.keys(input).length === 1) {
            if (note) return notes[action](input["note"]);
            if (work)
              return { source_work: sourceWork[action](input["sourceWork"]) };
          }
        }
        throw new Error("Supply exactly one of note or sourceWork.");
      },
    };
  }

  const base = tools.find((tool) => tool.name === graphActions.query.name);
  const result = tools.filter((tool) => tool !== base);
  result.push(graphTool("query", base));
  if (!readOnly) result.push(graphTool("update"));
  return result;
}
