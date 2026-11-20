import { isMap, isScalar, LineCounter, parseAllDocuments } from "yaml";
import type { TraceEvidence } from "./types.ts";

export const catalogNames = ["catalog-info.yaml", "catalog-info.yml"];
export const maxCatalogBytes = 32 * 1024;

const entityName = /^[A-Za-z0-9](?:[-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?$/u;
const namespace = /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/u;

export function catalogEvidence(text: string, path: string): TraceEvidence[] {
  const lineCounter = new LineCounter();
  const documents = parseAllDocuments(text, {
    lineCounter,
    prettyErrors: false,
  });
  if (documents.some((doc) => doc.errors.length || doc.warnings.length))
    return [];
  const components = documents.filter(
    (doc) =>
      doc.get("apiVersion") === "backstage.io/v1alpha1" &&
      doc.get("kind") === "Component",
  );
  // A shared catalog can describe unrelated workloads in the same checkout.
  if (components.length !== 1) return [];
  const doc = components[0]!;
  const spec = doc.get("spec", true);
  if (!isMap(spec)) return [];
  const name = doc.getIn(["metadata", "name"]);
  const ns = doc.getIn(["metadata", "namespace"], true);
  const componentNamespace =
    ns === undefined ? "default" : isScalar(ns) ? ns.value : undefined;
  if (
    typeof name !== "string" ||
    !entityName.test(name) ||
    typeof componentNamespace !== "string" ||
    !namespace.test(componentNamespace)
  )
    return [];
  const type = spec.get("type", true);
  const isService = isScalar(type) && type.value === "service";
  const component = {
    kind: "component",
    name: componentNamespace + "/" + name.toLowerCase(),
  };
  const evidence: TraceEvidence[] = [];
  if (isService && type.range) {
    evidence.push({
      source: path,
      line: lineCounter.linePos(type.range[0]).line,
      step: {
        from: { kind: "file", name: path },
        relation: "declares",
        to: component,
      },
    });
  }
  const system = spec.get("system", true);
  if (!isScalar(system) || !system.range || typeof system.value !== "string")
    return evidence;
  // Backstage resolves a relative system ref in the component's namespace.
  const ref = /^(?:system:)?(?:([^/:]+)\/)?([^/:]+)$/iu.exec(system.value);
  if (!ref) return evidence;
  const systemNamespace = ref[1] ?? componentNamespace;
  const systemName = ref[2]!;
  if (!namespace.test(systemNamespace) || !entityName.test(systemName))
    return evidence;
  evidence.push({
    source: path,
    line: lineCounter.linePos(system.range[0]).line,
    step: {
      from: component,
      relation: "part_of",
      to: {
        kind: "system",
        name: systemNamespace + "/" + systemName.toLowerCase(),
      },
    },
  });
  return evidence;
}
