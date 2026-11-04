import { SaxesParser } from "saxes";
import { asRecord } from "./record.js";
import { checkmarxEvidence } from "./checkmarx-evidence.js";
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

const viewerPath = "/cxwebclient/viewermain.aspx";

function viewerLink(value: unknown) {
  const url = typeof value === "string" ? URL.parse(value) : null;
  if (
    url &&
    /^https?:$/u.test(url.protocol) &&
    url.pathname.toLowerCase().endsWith(viewerPath)
  )
    return url;
}

function viewerInstance(link: URL | undefined) {
  return link && link.origin + link.pathname.slice(0, -viewerPath.length);
}

function instanceKey(value: string) {
  const url = URL.parse(value);
  return url && /^https?:$/u.test(url.protocol) ? url.href : value;
}

export function checkmarxXmlInstance(
  current: string | undefined,
  next: string | undefined,
) {
  if (
    current !== undefined &&
    next !== undefined &&
    current !== next &&
    instanceKey(current) !== instanceKey(next)
  )
    throw new Error("CxSAST viewer links must identify the same instance.");
  return current ?? next;
}

function viewerId(link: URL | undefined, field: string, expected?: string) {
  let selected = expected;
  for (const [key, id] of link?.searchParams ?? []) {
    if (!id || key.toLowerCase() !== field) continue;
    if (selected !== undefined && selected !== id)
      throw new Error(`CxSAST DeepLink ${field} does not match the report.`);
    selected = id;
  }
  return selected;
}

export function checkmarxResultViewer(
  source: Record<string, unknown> | null | undefined,
) {
  return viewerLink(asRecord(source?.["result"])?.["DeepLink"]);
}

export function checkmarxXmlScope(
  source: Record<string, unknown>,
  scanId?: string,
  projectId?: string,
) {
  const link = checkmarxResultViewer(source);
  viewerId(
    link,
    "pathid",
    text(asRecord(source["path"])?.["PathId"]) ?? undefined,
  );
  const instance = source["instance"];
  return {
    instance: checkmarxXmlInstance(
      instance === undefined
        ? undefined
        : requiredText(instance, "CxSAST instance"),
      viewerInstance(link),
    ),
    scanId: viewerId(link, "scanid", scanId),
    projectId: viewerId(link, "projectid", projectId),
  };
}

function readReport(contents: string) {
  const rows: Row[] = [];
  const stack: Element[] = [];
  const parser = new SaxesParser({ xmlns: false });
  let scanId = "";
  let rootInstance: string | undefined;
  const project: Attributes & { projectId: string } = { projectId: "" };
  parser.on("opentag", ({ name, attributes }) => {
    const element: Element = { name, attributes, children: [], text: "" };
    if (!stack.length) {
      if (name !== "CxXMLResults")
        throw new Error("Expected a Checkmarx CxSAST CxXMLResults report.");
      project.projectId = requiredText(
        attributes["ProjectId"],
        "CxSAST ProjectId",
      );
      scanId = requiredText(attributes["ScanId"], "CxSAST ScanId");
      const projectName = text(attributes["ProjectName"]);
      const team = text(attributes["TeamFullPathOnReportDate"]);
      if (projectName) project["projectName"] = projectName;
      if (team) project["teamFullPathOnReportDate"] = team;
      const link = viewerLink(attributes["DeepLink"]);
      viewerId(link, "scanid", scanId);
      viewerId(link, "projectid", project.projectId);
      rootInstance = viewerInstance(link);
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
      ...project,
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
  return { rows, project, scanId, rootInstance };
}

/** SimilarityId groups paths, including paths with different intermediate nodes. */
export function checkmarxXmlId(source: Record<string, unknown>): string {
  const projectId = requiredText(source["projectId"], "CxSAST ProjectId");
  const query = record(source["query"], "CxSAST Query");
  const result = record(source["result"], "CxSAST Result");
  const path = record(source["path"], "CxSAST Path");
  const nodes = array(source["nodes"], "CxSAST Path nodes");
  const route = (nodes.length ? nodes : [result]).map((value) => {
    const node = record(value, "CxSAST path node");
    return ["FileName", "Line", "Column", "Name", "Type"].map((field) =>
      text(node[field]),
    );
  });
  return stableId("checkmarx-cxsast", [
    projectId,
    requiredText(query["id"], "CxSAST Query id"),
    requiredText(path["SimilarityId"], "CxSAST SimilarityId"),
    route,
  ]);
}

export function normalizeCheckmarxXml(
  contents: string,
  repository: string,
  target: ExternalImportTarget,
) {
  const { rows, project, scanId, rootInstance } = readReport(contents);
  function normalize(instance: string | undefined) {
    const report = {
      format: "cxsast-xml",
      scanId,
      ...project,
      ...(instance && { instance }),
      sourceRepositoryUrl: repository,
    } as const;
    return normalizeRecords(
      rows,
      (row) => {
        const { query, result } = row;
        return checkmarxEvidence(
          report,
          {
            title: requiredText(query["name"], "CxSAST Query name"),
            ruleId: query["id"],
            severity: text(result["Severity"]) ?? query["Severity"],
            description: result["Remark"],
            status: result["Status"],
            verdict:
              result["FalsePositive"]?.toLowerCase() === "true"
                ? "False positive"
                : result["state"],
            cwe: query["cweId"],
            sourceData:
              !row["instance"] && instance ? { ...row, instance } : row,
          },
          target,
        );
      },
      (row) => {
        const scope = checkmarxXmlScope(row, scanId, project.projectId);
        if (scope.instance) row["instance"] = scope.instance;
        return checkmarxXmlId(row);
      },
      target,
      { report },
    );
  }

  const result = normalize(rootInstance);
  let instance = rootInstance;
  let hasUnboundRows = false;
  for (const { evidence } of result.findings) {
    const rowInstance = text(evidence.source_data?.["instance"]);
    if (rowInstance) instance = checkmarxXmlInstance(instance, rowInstance);
    else hasUnboundRows = true;
  }
  if (instance && !rootInstance) {
    // Count inherited instance bytes before accepting linkless findings for Cloud.
    if (hasUnboundRows) return normalize(instance);
    result.report!["instance"] = instance;
  }
  return result;
}
