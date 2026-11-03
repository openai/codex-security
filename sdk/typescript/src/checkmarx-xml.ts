import { SaxesParser } from "saxes";
import { checkmarxEvidence } from "./checkmarx-evidence.js";
import type { ExternalFindings } from "./external-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  array,
  normalizeRecords,
  record,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";

type Attributes = Record<string, string>;
interface Element {
  name: string;
  attributes: Attributes;
  children: Element[];
  text: string;
}

function fields(element: Element): Attributes {
  return Object.fromEntries(
    element.children
      .filter((child) => !child.children.length)
      .map((child) => [child.name, child.text]),
  );
}

function pathNode(element: Element): Record<string, unknown> {
  const node: Record<string, unknown> = fields(element);
  const snippet = element.children.find((child) => child.name === "Snippet");
  if (snippet)
    node["Snippet"] = snippet.children
      .filter((child) => child.name === "Line")
      .map(fields);
  return node;
}

interface Row extends Record<string, unknown> {
  projectId: string;
  query: Attributes;
  result: Attributes;
  path: Attributes | null;
  nodes: Record<string, unknown>[];
}

function readReport(contents: string) {
  const rows: Row[] = [];
  const stack: Element[] = [];
  const parser = new SaxesParser({ xmlns: false });
  let projectId = "";
  let scanId = "";
  parser.on("opentag", ({ name, attributes }) => {
    const element: Element = { name, attributes, children: [], text: "" };
    if (!stack.length) {
      if (name !== "CxXMLResults")
        throw new Error("Expected a Checkmarx CxSAST CxXMLResults report.");
      projectId = requiredText(attributes["ProjectId"], "CxSAST ProjectId");
      scanId = requiredText(attributes["ScanId"], "CxSAST ScanId");
    } else if (
      (stack.length === 1 && name !== "Query") ||
      (stack.length === 2 && name !== "Result")
    ) {
      throw new Error("Expected CxSAST results directly under their Query.");
    }
    // Only build subtrees within the current result, then release them.
    if (stack.length >= 3) stack.at(-1)!.children.push(element);
    stack.push(element);
  });
  function appendText(value: string) {
    const element = stack.at(-1);
    if (element) element.text += value;
  }
  parser.on("text", appendText);
  parser.on("cdata", appendText);
  parser.on("closetag", () => {
    const element = stack.pop()!;
    const parent = stack.at(-1);
    if (parent?.name !== "Query" || stack.length !== 2) return;
    const paths = element.children.filter((child) => child.name === "Path");
    const path = paths.length === 1 ? paths[0] : undefined;
    rows.push({
      projectId,
      query: parent.attributes,
      result: element.attributes,
      path: path?.attributes ?? null,
      nodes:
        path?.children
          .filter((child) => child.name === "PathNode")
          .map(pathNode) ?? [],
    });
  });
  parser.write(contents).close();
  return { rows, projectId, scanId };
}

/** SimilarityId groups paths, including paths with different intermediate nodes. */
export function checkmarxXmlId(source: Record<string, unknown>): string {
  const query = record(source["query"], "CxSAST Query");
  const result = record(source["result"], "CxSAST Result");
  const path = record(source["path"], "CxSAST Path");
  const nodes = array(source["nodes"], "CxSAST Path nodes");
  const route = (nodes.length ? nodes : [result]).map((value) => {
    const node = record(value, "CxSAST path node");
    return [
      text(node["FileName"]),
      text(node["Line"]),
      text(node["Column"]),
      text(node["Name"]),
      text(node["Type"]),
    ];
  });
  return stableId("checkmarx-cxsast", [
    requiredText(source["projectId"], "CxSAST ProjectId"),
    requiredText(query["id"], "CxSAST Query id"),
    requiredText(path["SimilarityId"], "CxSAST SimilarityId"),
    route,
  ]);
}

export function normalizeCheckmarxXml(
  contents: string,
  repository: string,
  target: ExternalImportTarget,
): ExternalFindings {
  const { rows, scanId, projectId } = readReport(contents);
  return normalizeRecords(
    rows,
    (row) => {
      const { query, result } = row;
      return checkmarxEvidence(
        {
          format: "cxsast-xml",
          repository,
          scanId,
          title: requiredText(query["name"], "CxSAST Query name"),
          ruleId: query["id"]!,
          severity: text(result["Severity"]) ?? query["Severity"],
          description: text(result["Remark"]),
          status: text(result["Status"]),
          verdict:
            result["FalsePositive"]?.toLowerCase() === "true"
              ? "False positive"
              : text(result["state"]),
          cwe: query["cweId"],
          sourceData: row,
        },
        target,
      );
    },
    checkmarxXmlId,
    target,
    {
      report: {
        format: "cxsast-xml",
        scanId,
        projectId,
        sourceRepositoryUrl: repository,
      },
    },
  );
}
