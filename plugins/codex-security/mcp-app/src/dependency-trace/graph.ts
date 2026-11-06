import { posix } from "node:path";
import type { TraceEntity, TraceResult, TraceStep } from "./types.ts";

export interface CatalogReceiptSelection {
  receiptId: string;
  textBlock: number | null;
  record: (string | number)[];
}

interface ResolvedServiceResolution {
  path: string;
  project?: string;
  status?: undefined;
  directory?: string;
  services: readonly {
    name: string;
    scope?: string;
    source?: string;
    receiptSelections?: CatalogReceiptSelection[];
  }[];
  receiptSelections?: CatalogReceiptSelection[];
  source?: string;
  reason?: string;
  line?: number;
}

interface UnresolvedServiceResolution {
  path: string;
  project?: string;
  status: "unresolved";
  reason: string;
  source?: string;
}

export type ServiceResolution =
  ResolvedServiceResolution | UnresolvedServiceResolution;

interface ServiceQuestion {
  status: "pending" | "checked" | "unresolved";
  projects: Set<string>;
  project?: string;
  reason?: string;
  source?: string;
}

interface GraphNode extends TraceEntity {
  id: string;
  receiptSelections?: CatalogReceiptSelection[];
}

interface Fact extends Omit<TraceStep, "from" | "to"> {
  from: GraphNode;
  to?: GraphNode;
  source: string;
  reason?: string;
  line?: number;
  receiptSelections?: CatalogReceiptSelection[];
}

function entityKey({ kind, name, scope }: TraceEntity) {
  return JSON.stringify([kind, name, scope]);
}

function staticEntity(entity: TraceEntity) {
  return entity.kind === "service" ? { ...entity, kind: "component" } : entity;
}

// Keep a single model-visible reply within the same observation count as a trace.
const MAX_ITEMS = 128;

function* parents(path: string) {
  for (let dir = posix.dirname(path); ; dir = posix.dirname(dir)) {
    yield dir;
    if (posix.dirname(dir) === dir) return;
  }
}

function hasDirectory(path: string, directories: Set<string>) {
  if (directories.size) {
    for (const parent of parents(path))
      if (directories.has(parent)) return true;
  }
  return false;
}

export class EvidenceGraph {
  private nodes = new Map<string, GraphNode>();
  private facts = new Map<string, Fact>();
  private paths = new Set<Fact>();
  // An investigated but unresolved question is distinct from a confirmed
  // association.
  private questions = new Map<string, ServiceQuestion>();
  private coveredDirectories = new Set<string>();
  private directoryMappings = new Set<Fact>();
  private revision = 0;
  private bytesLeft: number;
  private full = false;

  constructor(maxBytes = 4 * 1024 * 1024) {
    this.bytesLeft = maxBytes;
  }

  private reserve(bytes: number) {
    if (bytes > this.bytesLeft) {
      if (!this.full) this.revision++;
      this.full = true;
      return false;
    }
    this.bytesLeft -= bytes;
    return true;
  }

  private node(key: string, entity: TraceEntity) {
    let node = this.nodes.get(key);
    if (!node) {
      const prefix = entity.kind === "service" ? "svc" : "node";
      node = { ...entity, id: prefix + "_" + (this.nodes.size + 1) };
      this.nodes.set(key, node);
    }
    return node;
  }

  private record(
    { from, to, ...observation }: TraceStep,
    source: string,
    line: number | undefined,
    reason?: string,
    receiptSelections?: CatalogReceiptSelection[],
  ) {
    const a = entityKey(from);
    const b = to && entityKey(to);
    const key = JSON.stringify([
      a,
      observation.relation,
      b,
      observation.calleeText,
      observation.sourceText,
      source,
      line,
      ...(reason === undefined ? [] : [reason]),
      ...(receiptSelections === undefined ? [] : [receiptSelections]),
    ]);
    const previous = this.facts.get(key);
    if (previous) return previous;
    // Estimate keys, retained strings, and record/Map overhead. Keep evidence
    // already cited during this check if a later trace exceeds the budget.
    const bytes = 640 + 8 * key.length;
    if (!this.reserve(bytes)) return;
    const fact: Fact = {
      from: this.node(a, from),
      ...observation,
      ...(b && to && { to: this.node(b, to) }),
      source,
      ...(reason === undefined ? {} : { reason }),
      ...(line !== undefined && { line }),
      ...(receiptSelections === undefined ? {} : { receiptSelections }),
    };
    if (from.kind === "service" && receiptSelections?.length) {
      fact.from.receiptSelections = [
        ...new Map(
          [...(fact.from.receiptSelections ?? []), ...receiptSelections].map(
            (selection) => [JSON.stringify(selection), selection],
          ),
        ).values(),
      ];
    }
    this.facts.set(key, fact);
    return fact;
  }

  addTrace(result: TraceResult, queueServices = true) {
    for (const { evidence } of result.scopes) {
      for (const { step, source, line } of evidence) {
        const fact = this.record(
          {
            ...step,
            from: staticEntity(step.from),
            to: step.to && staticEntity(step.to),
          },
          source,
          line,
        );
        if (!fact) continue;
        const candidate =
          step.relation === "candidate_call" ||
          step.relation === "candidate_flow";
        if (candidate) this.paths.add(fact);
        if (candidate || step.relation === "depends_on") {
          // A caller or build may be the subject instead of the cited file.
          const file = { kind: "file", name: source };
          this.node(entityKey(file), file);
          if (queueServices) this.requestServices([source]);
        }
      }
    }
  }

  requestServices(paths: string[], project?: string, retryUnresolved = false) {
    for (const path of paths) {
      const existing = this.questions.get(path);
      if (existing) {
        if (project !== undefined && project !== existing.project) {
          if (!existing.projects.has(project)) {
            if (!this.reserve(128 + 8 * project.length)) continue;
            existing.projects.add(project);
          }
          existing.project = project;
          if (existing.status !== "pending") {
            existing.status = "pending";
            delete existing.reason;
            delete existing.source;
          }
          this.revision++;
        } else if (retryUnresolved && existing.status === "unresolved") {
          existing.status = "pending";
          delete existing.reason;
          delete existing.source;
          this.revision++;
        }
        continue;
      }
      if (
        !this.reserve(
          384 +
            8 * path.length +
            (project === undefined ? 0 : 128 + 8 * project.length),
        )
      )
        continue;
      this.questions.set(path, {
        status: "pending",
        projects: new Set(project === undefined ? [] : [project]),
        ...(project === undefined ? {} : { project }),
      });
      const file = { kind: "file", name: path };
      this.node(entityKey(file), file);
      this.revision++;
    }
  }

  resolveServices(answers: readonly ServiceResolution[]) {
    // Check the whole batch before settling any question. Path keys are
    // normalized checkout-relative names from the provider or the MCP boundary.
    for (const answer of answers) {
      const { path } = answer;
      if (!this.questions.has(path))
        throw new Error(`No service question for ${path}.`);
      if (answer.status === "unresolved") {
        if (!answer.reason.trim())
          throw new Error("An unresolved service question needs a reason.");
        continue;
      }
      const { directory, services } = answer;
      if (
        directory !== undefined &&
        (!services.length ||
          !(directory === "." || path.startsWith(directory + "/")))
      ) {
        throw new Error(
          "A directory mapping must cover the requested file and identify a service.",
        );
      }
    }
    for (const answer of answers) {
      const { path, reason, source = "configured service catalog" } = answer;
      const question = this.questions.get(path)!;
      // A newer hint may arrive during a lookup. Retain older positive evidence,
      // but only the current context can settle the question or its uncertainty.
      const currentContext = answer.project === question.project;
      if (
        !currentContext &&
        (answer.status === "unresolved" || answer.services.length === 0)
      )
        continue;
      const changedExplanation =
        currentContext &&
        (question.reason !== reason || question.source !== source);
      if (
        changedExplanation &&
        !this.reserve(128 + 8 * ((reason?.length ?? 0) + source.length))
      )
        continue;
      if (answer.status === "unresolved") {
        if (question.status !== "unresolved" || changedExplanation)
          this.revision++;
        question.status = "unresolved";
        question.reason = answer.reason;
        question.source = source;
        continue;
      }
      const { directory, services, line } = answer;
      const target =
        directory === undefined
          ? { kind: "file", name: path }
          : { kind: "directory", name: directory };
      const before = this.facts.size;
      const beforeMappings = this.directoryMappings.size;
      if (services.length === 0) {
        if (
          !this.record(
            { from: target, relation: "no_service_found" },
            source,
            line,
            reason,
            answer.receiptSelections,
          )
        )
          continue;
      } else {
        const retained = services.map(
          ({ source: citation, receiptSelections, ...service }) =>
            this.record(
              {
                from: { kind: "service", ...service },
                relation: "uses",
                to: target,
              },
              citation ?? source,
              line,
              reason,
              receiptSelections,
            ),
        );
        if (!retained.every((fact): fact is Fact => fact !== undefined))
          continue;
        if (directory !== undefined) {
          this.coveredDirectories.add(directory);
          for (const fact of retained) this.directoryMappings.add(fact);
        }
      }
      if (!currentContext) {
        if (
          this.facts.size !== before ||
          this.directoryMappings.size !== beforeMappings
        )
          this.revision++;
        continue;
      }
      if (
        question.status !== "checked" ||
        changedExplanation ||
        this.facts.size !== before ||
        this.directoryMappings.size !== beforeMappings
      )
        this.revision++;
      question.status = "checked";
      if (reason === undefined) delete question.reason;
      else question.reason = reason;
      question.source = source;
    }
  }

  private lookupState(path: string) {
    const question = this.questions.get(path);
    if (question === undefined) return undefined;
    return hasDirectory(path, this.coveredDirectories)
      ? "checked"
      : question.status;
  }

  isServicePending(path: string) {
    return this.lookupState(path) === "pending";
  }

  serviceProject(path: string) {
    return this.questions.get(path)?.project;
  }

  serviceResolution() {
    let pending = 0;
    let checked = 0;
    let unresolved = 0;
    const paths: string[] = [];
    const unresolvedPaths: {
      path: string;
      reason: string;
      source?: string;
    }[] = [];
    for (const [path, question] of this.questions) {
      switch (this.lookupState(path)) {
        case "checked":
          checked++;
          break;
        case "unresolved":
          unresolved++;
          if (unresolvedPaths.length < MAX_ITEMS)
            unresolvedPaths.push({
              path,
              reason: question.reason!,
              ...(question.source === undefined
                ? {}
                : { source: question.source }),
            });
          break;
        default:
          pending++;
          if (paths.length < MAX_ITEMS) paths.push(path);
      }
    }
    return {
      revision: this.revision,
      pending,
      checked,
      unresolved,
      paths,
      unresolved_paths: unresolvedPaths,
      ...(this.full && { truncated: true as const }),
    };
  }

  query(node?: string) {
    const nodes = [...this.nodes.values()];
    const limit = (size: number) =>
      this.full || size > MAX_ITEMS ? { truncated: true } : {};
    if (node === undefined) {
      const services = nodes.filter(({ kind }) => kind === "service");
      return {
        code_paths_found: this.paths.size,
        services_found: services.length,
        services: services
          .slice(0, MAX_ITEMS)
          .map(({ id, name, scope, receiptSelections }) => ({
            id,
            name,
            ...(scope !== undefined && { scope }),
            ...(receiptSelections === undefined ? {} : { receiptSelections }),
          })),
        ...limit(services.length),
      };
    }

    const byId = nodes.find(({ id }) => id === node);
    const matches = byId ? [byId] : nodes.filter(({ name }) => name === node);
    if (matches.length !== 1)
      return { matches: matches.slice(0, MAX_ITEMS), ...limit(matches.length) };
    const subject = matches[0]!;
    const evidence = new Set<Fact>();
    const paths: Fact[] = [];
    const files = new Set<string>();
    const directories = new Set<string>();
    const localFile = subject.kind === "file" && subject.scope === undefined;
    const fileParents = localFile ? new Set(parents(subject.name)) : undefined;
    const lookup = localFile ? this.lookupState(subject.name) : undefined;
    const question = localFile ? this.questions.get(subject.name) : undefined;
    if (localFile) files.add(subject.name);
    for (const fact of this.facts.values()) {
      if (
        fact.from !== subject &&
        fact.to !== subject &&
        !(
          this.directoryMappings.has(fact) &&
          fact.to &&
          fileParents?.has(fact.to.name)
        )
      )
        continue;
      if (!this.paths.has(fact)) evidence.add(fact);
      if (subject.kind !== "service") continue;
      const other = fact.from === subject ? fact.to : fact.from;
      if (other?.kind === "file") files.add(other.name);
      if (other && this.directoryMappings.has(fact))
        directories.add(other.name);
    }
    for (const fact of this.facts.values()) {
      const candidate = this.paths.has(fact);
      if (!candidate && fact.relation !== "depends_on") continue;
      const fromFile =
        files.has(fact.source) || hasDirectory(fact.source, directories);
      if (candidate) {
        if (fromFile || fact.from === subject || fact.to === subject)
          paths.push(fact);
      } else if (fromFile) {
        evidence.add(fact);
      }
    }
    return {
      node: subject,
      ...(lookup && { service_lookup: lookup }),
      ...(question?.reason && question.status === lookup
        ? {
            service_lookup_detail: {
              reason: question.reason,
              ...(question.source === undefined
                ? {}
                : { source: question.source }),
            },
          }
        : {}),
      paths: paths.slice(0, MAX_ITEMS),
      evidence: [...evidence].slice(0, MAX_ITEMS),
      ...limit(Math.max(evidence.size, paths.length)),
    };
  }
}
