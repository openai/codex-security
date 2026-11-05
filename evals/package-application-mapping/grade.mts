import { isRecord } from "../../sdk/typescript/src/record.ts";
import { catalogServer, catalogTool, type MappingCase } from "./cases.mts";

const catalogCitation = `${catalogServer}/${catalogTool}`;

export function gradeMapping(c: MappingCase, snapshots: readonly unknown[]) {
  const errors: string[] = [];
  const applications: { name: string; scope?: string }[] = [];
  const replies = snapshots.filter(isRecord);
  const states = replies
    .map((reply) => reply.service_resolution)
    .filter(isRecord);
  const revision = Math.max(
    ...states.map(({ revision }) =>
      typeof revision === "number" ? revision : -1,
    ),
  );
  const query = replies.findLast(
    (reply) =>
      isRecord(reply.service_resolution) &&
      reply.service_resolution.revision === revision &&
      isRecord(reply.node) &&
      reply.node.kind === "file" &&
      reply.node.name === c.path,
  );
  const state = query?.service_resolution;
  const configured = c.catalog !== undefined;
  if (
    !query ||
    !isRecord(state) ||
    state.catalog_configured !== configured ||
    state.pending !== 0 ||
    state.truncated ||
    query.truncated ||
    query.service_lookup !== (configured ? "checked" : undefined) ||
    !Array.isArray(query.evidence)
  ) {
    const latest = states.findLast((state) => state.revision === revision);
    if (typeof latest?.pending === "number" && latest.pending > 0) {
      const paths = Array.isArray(latest.paths)
        ? latest.paths.filter((path) => typeof path === "string")
        : [];
      errors.push(
        `Pending service lookups (${latest.pending})${paths.length ? ` for ${paths.join(", ")}` : ""}`,
      );
    } else {
      errors.push(
        `Missing complete graph query for ${c.path} at the final revision`,
      );
    }
    return { pass: false, errors, applications };
  }
  const expected = c.expected.applications;
  const isExpected = (name: unknown, scope: unknown) =>
    expected.some(
      (app) => app.name === name && `${catalogServer}:${app.id}` === scope,
    );
  const evidence = query.evidence.filter(isRecord);
  const uses = [];
  for (const { from, relation, to, source } of evidence) {
    if (
      relation !== "uses" ||
      !isRecord(from) ||
      from.kind !== "service" ||
      typeof from.name !== "string" ||
      !isRecord(to)
    )
      continue;
    const coversFile = to.kind === "file" && to.name === c.path;
    const coversDirectory =
      to.kind === "directory" &&
      typeof to.name === "string" &&
      (to.name === "." || c.path.startsWith(to.name + "/"));
    if (!coversFile && !coversDirectory) continue;
    const scope = typeof from.scope === "string" ? from.scope : undefined;
    const name = from.name;
    uses.push({ name, scope, source });
    if (applications.some((app) => app.name === name && app.scope === scope))
      continue;
    applications.push({ name, ...(scope && { scope }) });
    if (!isExpected(name, scope))
      errors.push(`Unexpected application ${name} (${scope ?? "unscoped"})`);
  }
  if (
    configured &&
    replies.some(
      ({ services }) =>
        Array.isArray(services) &&
        services
          .filter(isRecord)
          .some(({ name, scope }) => !isExpected(name, scope)),
    )
  ) {
    errors.push("Graph contains a service outside the expected applications");
  }
  for (const { name, id } of expected) {
    if (
      !uses.some(
        (use) =>
          use.name === name &&
          use.scope === `${catalogServer}:${id}` &&
          use.source === `${catalogCitation}#${id}`,
      )
    ) {
      errors.push(`Missing catalog evidence for ${name} (${id})`);
    }
  }
  const noService = evidence.some(
    ({ from, relation, source }) =>
      relation === "no_service_found" &&
      isRecord(from) &&
      from.kind === "file" &&
      from.name === c.path &&
      source === catalogCitation,
  );
  if (configured && !expected.length && !noService) {
    errors.push(`Missing cited no_service_found result for ${c.path}`);
  }
  if (
    !configured &&
    (replies.some(
      (reply) =>
        typeof reply.services_found === "number" && reply.services_found > 0,
    ) ||
      evidence.some(
        ({ from, to, relation }) =>
          relation === "no_service_found" ||
          (isRecord(from) && from.kind === "service") ||
          (isRecord(to) && to.kind === "service"),
      ))
  ) {
    errors.push("Unconfigured graph decided a service identity or absence");
  }
  return { pass: errors.length === 0, errors, applications };
}
