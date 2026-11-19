import { createHash } from "node:crypto";
import { posix } from "node:path";
import { executionSummary } from "./rule-config.ts";
import type {
  TraceEntity,
  TraceObservation,
  TraceResult,
  TraceStep,
  RuleExecution,
  NativeMatch,
} from "./types.ts";

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
  match?: NativeMatch;
  receiptSelections?: CatalogReceiptSelection[];
}

interface Witness {
  id: string;
  native_id: string;
  kind: TraceObservation["kind"];
  scope: Record<string, unknown>;
  frames: string[];
  receiptSelections: CatalogReceiptSelection[];
}

interface ObservedCall {
  from: GraphNode;
  to: GraphNode;
  relation: "observed_call";
  // Positions identify adjacent frame pairs in a particular ordered witness.
  witnesses: Map<string, number[]>;
}

type WitnessSummary = Omit<Witness, "frames"> & {
  frame_count: number;
  frame_order: "root_first";
};
interface ObservedCallSummary extends Omit<ObservedCall, "witnesses"> {
  witness: string;
  positions: number[];
  occurrences_found: number;
  receiptSelections: CatalogReceiptSelection[];
  truncated?: boolean;
}

interface NodeGraphQuery {
  node: GraphNode;
  paths: Fact[];
  evidence: Fact[];
  service_lookup?: ServiceQuestion["status"];
  service_lookup_detail?: { reason: string; source?: string };
  witness?: WitnessSummary;
  witnesses_found?: number;
  witnesses?: WitnessSummary[];
  observed_calls_found?: number;
  observed_calls?: ObservedCallSummary[];
}

type GraphQueryResult = (
  | NodeGraphQuery
  | {
      matches: GraphNode[];
      matches_found?: number;
      witness_found?: boolean;
      witnesses_found?: number;
      witnesses?: WitnessSummary[];
    }
  | {
      witness: WitnessSummary;
      frames: string[];
      frame_order: "root_first";
      nodes: GraphNode[];
      frame_receipts: {
        position: number;
        receiptSelections: CatalogReceiptSelection[];
      }[];
    }
  | {
      code_paths_found: number;
      services_found: number;
      services: Pick<
        GraphNode,
        "id" | "name" | "scope" | "receiptSelections"
      >[];
      witnesses_found?: number;
      observed_calls_found?: number;
      observations_omitted?: number;
      witnesses?: WitnessSummary[];
    }
) & {
  truncated?: boolean;
  response_omitted_items?: number;
  response_omitted_fields?: number;
};

export interface ObservationSummary {
  received: number;
  retained: number;
  already_recorded: number;
  omitted: number;
  witnesses_found: number;
  observed_calls_found: number;
  truncated?: true;
}

function entityKey({ kind, name, scope }: TraceEntity) {
  return JSON.stringify([kind, name, scope]);
}

function staticEntity(entity: TraceEntity) {
  return entity.kind === "service" ? { ...entity, kind: "component" } : entity;
}

// Keep a single model-visible reply within the same observation count as a trace.
const MAX_ITEMS = 128;

// Native MCP output has truncated large profile replies at about 58 KiB.
// Leave room for the tool envelope as well as bounding the item count.
export const MAX_GRAPH_RESPONSE_BYTES = 32 * 1024;

/** Omit whole details, never shorten a citation or silently clip a name. */
export function boundGraphResponse<T extends object>(
  result: T,
): T & {
  truncated?: true;
  response_omitted_items?: number;
  response_omitted_fields?: number;
} {
  const bytes = (value: unknown) =>
    Buffer.byteLength(JSON.stringify(value) ?? "null");
  if (bytes(result) <= MAX_GRAPH_RESPONSE_BYTES) return result;
  const bounded = structuredClone(result) as T & {
    truncated?: true;
    response_omitted_items?: number;
    response_omitted_fields?: number;
  };
  bounded.truncated = true;
  const detailFields = new Set([
    "scope",
    "name",
    "native_id",
    "source",
    "reason",
    "calleeText",
    "sourceText",
  ]);
  while (bytes(bounded) > MAX_GRAPH_RESPONSE_BYTES) {
    let largest = 0;
    let omit: (() => void) | undefined;
    let citationFallback: (() => void) | undefined;
    function visit(value: unknown) {
      if (!value || typeof value !== "object") return;
      if (Array.isArray(value)) {
        for (const item of value) visit(item);
        return;
      }
      const object = value as Record<string, unknown>;
      for (const [key, child] of Object.entries(object)) {
        if (key === "omitted_fields") continue;
        if (key === "receiptSelections") {
          const selections = child as CatalogReceiptSelection[];
          // Only a citation larger than the entire response budget needs this.
          // Drop the whole selection rather than return an invalid selector.
          if (selections.length)
            citationFallback = () => {
              selections.pop();
              bounded.response_omitted_items =
                (bounded.response_omitted_items ?? 0) + 1;
            };
          continue;
        }
        const size = bytes(child);
        if (detailFields.has(key) && size > largest) {
          largest = size;
          omit = () => {
            delete object[key];
            ((object.omitted_fields ??= []) as string[]).push(key);
            bounded.response_omitted_fields =
              (bounded.response_omitted_fields ?? 0) + 1;
          };
        }
        if (Array.isArray(child) && child.length > 1) {
          const size = bytes(child.at(-1));
          if (size > largest) {
            largest = size;
            omit = () => {
              child.pop();
              bounded.response_omitted_items =
                (bounded.response_omitted_items ?? 0) + 1;
              object[`${key}_omitted`] =
                Number(object[`${key}_omitted`] ?? 0) + 1;
            };
          }
        }
        visit(child);
      }
    }
    visit(bounded);
    // Graph-controlled IDs and counters are small; unbounded details and exact
    // receipt selections above are the only remaining sources of large output.
    const remove = omit ?? citationFallback;
    if (!remove) throw new Error("Graph response cannot fit its byte budget.");
    remove();
  }
  return bounded;
}

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

// Estimate retained JSON values, including object/array/string overhead. Shared
// graph references are accounted separately, rather than charging their full
// serialized names again for every occurrence in a sampled stack.
function retainedValueBytes(value: unknown): number {
  if (typeof value === "string") return 24 + 2 * value.length;
  if (value === null || typeof value !== "object") return 8;
  if (Array.isArray(value))
    return (
      32 +
      value.reduce((bytes, item) => bytes + 8 + retainedValueBytes(item), 0)
    );
  return Object.entries(value).reduce(
    (bytes, [key, item]) =>
      bytes + 32 + retainedValueBytes(key) + retainedValueBytes(item),
    64,
  );
}

export class EvidenceGraph {
  private nodes = new Map<string, GraphNode>();
  private facts = new Map<string, Fact>();
  private paths = new Set<Fact>();
  private ruleExecutions = new Map<string, RuleExecution>();
  private witnesses = new Map<string, Witness>();
  private observedCalls = new Map<string, ObservedCall>();
  private runtimeNodes = new Set<GraphNode>();
  private omittedObservations = 0;
  // An investigated but unresolved question is distinct from a confirmed
  // association.
  private questions = new Map<string, ServiceQuestion>();
  private coveredDirectories = new Set<string>();
  private directoryMappings = new Set<Fact>();
  private revision = 0;
  private bytesLeft: number;
  private full = false;

  // Host retention must accommodate successive collections independently of
  // the much smaller model-visible response budget.
  constructor(maxBytes = 64 * 1024 * 1024) {
    this.bytesLeft = maxBytes;
  }

  recordObservations(
    observations: readonly TraceObservation[],
    receiptId: string,
    recordPrefix: readonly (string | number)[] = ["observations"],
    textBlock: number | null = 0,
  ): ObservationSummary {
    let retained = 0;
    let alreadyRecorded = 0;
    let omitted = 0;
    for (const [index, observation] of observations.entries()) {
      const selection: CatalogReceiptSelection = {
        receiptId,
        textBlock,
        record: [...recordPrefix, index],
      };
      const id =
        "witness_" +
        createHash("sha256").update(JSON.stringify(selection)).digest("hex");
      if (this.witnesses.has(id)) {
        alreadyRecorded++;
        continue;
      }
      const newNodes = new Map<string, GraphNode>();
      const frames = observation.frames.map((frame) => {
        // Source and sampled entities have distinct namespaces even if their
        // names and scopes happen to match. Unscoped runtime names are local to
        // one witness; producers supply build/image scopes for shared identity.
        const key = JSON.stringify([
          "observed",
          frame.scope === undefined ? id : null,
          entityKey(frame),
        ]);
        let node = this.nodes.get(key) ?? newNodes.get(key);
        if (!node) {
          const prefix = frame.kind === "service" ? "svc" : "node";
          node = {
            kind: frame.kind,
            name: frame.name,
            ...(frame.scope === undefined ? {} : { scope: frame.scope }),
            id: prefix + "_" + (this.nodes.size + newNodes.size + 1),
          };
          newNodes.set(key, node);
        }
        return node;
      });
      const witness: Witness = {
        id,
        native_id: observation.id,
        kind: observation.kind,
        scope: structuredClone(observation.scope),
        frames: frames.map(({ id }) => id),
        receiptSelections: [selection],
      };
      const calls = new Map<
        string,
        { call: ObservedCall; positions: number[]; isNew: boolean }
      >();
      for (let position = 0; position + 1 < frames.length; position++) {
        const from = frames[position]!;
        const to = frames[position + 1]!;
        const key = JSON.stringify([from.id, to.id]);
        let pending = calls.get(key);
        if (!pending) {
          const existing = this.observedCalls.get(key);
          pending = {
            call: existing ?? {
              from,
              to,
              relation: "observed_call",
              witnesses: new Map(),
            },
            positions: [],
            isNew: existing === undefined,
          };
          calls.set(key, pending);
        }
        pending.positions.push(position);
      }
      const { frames: frameIds, ...metadata } = witness;
      // Charge the witness and its ordered ID references, each new node/edge
      // once, and this witness's membership/position arrays on shared edges.
      // All estimates are complete before mutating any retained graph state.
      let bytes = 96 + retainedValueBytes(metadata) + 8 * frameIds.length;
      for (const [key, node] of newNodes)
        bytes += 96 + retainedValueBytes(key) + retainedValueBytes(node);
      for (const [key, { positions, isNew }] of calls) {
        if (isNew) bytes += 160 + retainedValueBytes(key);
        bytes += 96 + 8 * positions.length;
      }
      if (!this.reserve(bytes)) {
        omitted++;
        continue;
      }
      for (const [key, node] of newNodes) {
        this.nodes.set(key, node);
        this.runtimeNodes.add(node);
      }
      this.witnesses.set(id, witness);
      for (const [key, { call, positions, isNew }] of calls) {
        if (isNew) this.observedCalls.set(key, call);
        call.witnesses.set(id, positions);
      }
      retained++;
    }
    this.omittedObservations += omitted;
    return {
      received: observations.length,
      retained,
      already_recorded: alreadyRecorded,
      omitted,
      witnesses_found: this.witnesses.size,
      observed_calls_found: this.observedCalls.size,
      ...(this.full && { truncated: true as const }),
    };
  }

  private witnessSelections(witness: Witness, fields: (string | number)[][]) {
    return witness.receiptSelections.flatMap((selection) =>
      fields.map((field) => ({
        ...selection,
        record: [...selection.record, ...field],
      })),
    );
  }

  private witnessSummary({ frames, ...witness }: Witness) {
    return {
      ...witness,
      frame_count: frames.length,
      frame_order: "root_first" as const,
      // A whole observation can contain thousands of frames. Reviewers should
      // read only metadata and the adjacent frames cited by a graph query.
      receiptSelections: [
        ...this.witnessSelections({ ...witness, frames }, [
          ["id"],
          ["kind"],
          ["scope"],
        ]),
        ...witness.receiptSelections.map((selection) => ({
          ...selection,
          record: [...selection.record.slice(0, -2), "frame_order"],
        })),
      ],
    };
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
    match?: NativeMatch,
  ) {
    const a = entityKey(from);
    const b = to && entityKey(to);
    const key = JSON.stringify([
      a,
      observation.relation,
      b,
      observation.calleeText,
      observation.sourceText,
      ...(observation.ruleExecutionId === undefined
        ? []
        : [observation.ruleExecutionId, observation.nativeRuleId]),
      source,
      line,
      ...(reason === undefined ? [] : [reason]),
      ...(receiptSelections === undefined ? [] : [receiptSelections]),
      ...(match === undefined ? [] : [match]),
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
      ...(match === undefined ? {} : { match }),
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
    for (const { evidence, textMatches, ruleExecution } of result.scopes) {
      if (
        ruleExecution &&
        !this.ruleExecutions.has(ruleExecution.id) &&
        this.reserve(retainedValueBytes(ruleExecution))
      )
        this.ruleExecutions.set(ruleExecution.id, ruleExecution);
      for (const {
        source,
        text,
        line,
        ruleExecutionId,
        nativeRuleId,
      } of textMatches ?? []) {
        if (ruleExecutionId !== undefined)
          this.record(
            {
              from: { kind: "file", name: source },
              relation: "unresolved_lead",
              sourceText: text,
              ruleExecutionId,
              nativeRuleId,
            },
            source,
            line,
          );
      }
      for (const { step, source, line, match } of evidence) {
        const fact = this.record(
          {
            ...step,
            from: staticEntity(step.from),
            to: step.to && staticEntity(step.to),
          },
          source,
          line,
          undefined,
          undefined,
          match,
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

  query(
    node?: string,
    options: { witness?: string; search?: string } = {},
  ): GraphQueryResult {
    const witness =
      options.witness === undefined
        ? undefined
        : this.witnesses.get(options.witness);
    const frameIds = witness && new Set(witness.frames);
    const nodes = [...this.nodes.values()].filter(
      ({ id, name }) =>
        (!frameIds || frameIds.has(id)) &&
        (options.search === undefined || name.includes(options.search)),
    );
    const limit = (size: number) =>
      this.full || size > MAX_ITEMS ? { truncated: true } : {};
    if (options.witness !== undefined && !witness)
      return { matches: [], witness_found: false, ...limit(0) };
    const matchingWitnesses = (ids: Set<string>) =>
      [...this.witnesses.values()].filter(({ frames }) =>
        frames.some((id) => ids.has(id)),
      );
    if (options.search !== undefined && node === undefined) {
      const witnesses = witness
        ? [witness]
        : matchingWitnesses(new Set(nodes.map(({ id }) => id)));
      return boundGraphResponse({
        matches_found: nodes.length,
        matches: nodes.slice(0, MAX_ITEMS),
        witnesses_found: witnesses.length,
        witnesses: witnesses
          .slice(0, MAX_ITEMS)
          .map((item) => this.witnessSummary(item)),
        ...limit(Math.max(nodes.length, witnesses.length)),
      });
    }
    if (node === undefined && witness) {
      return boundGraphResponse({
        witness: this.witnessSummary(witness),
        frames: witness.frames.slice(0, MAX_ITEMS),
        frame_order: "root_first" as const,
        nodes: nodes.slice(0, MAX_ITEMS),
        frame_receipts: witness.frames
          .slice(0, MAX_ITEMS)
          .map((_, position) => ({
            position,
            receiptSelections: this.witnessSelections(witness, [
              ["frames", position],
            ]),
          })),
        ...limit(Math.max(witness.frames.length, nodes.length)),
      });
    }
    if (node === undefined) {
      const services = nodes.filter(
        (item) => item.kind === "service" && !this.runtimeNodes.has(item),
      );
      return boundGraphResponse({
        code_paths_found: this.paths.size,
        ...(this.ruleExecutions.size > 0 && {
          ruleExecutions: [...this.ruleExecutions.values()]
            .slice(0, MAX_ITEMS)
            .map(executionSummary),
        }),
        services_found: services.length,
        services: services
          .slice(0, MAX_ITEMS)
          .map(({ id, name, scope, receiptSelections }) => ({
            id,
            name,
            ...(scope !== undefined && { scope }),
            ...(receiptSelections === undefined ? {} : { receiptSelections }),
          })),
        ...(this.witnesses.size || this.omittedObservations
          ? {
              witnesses_found: this.witnesses.size,
              observed_calls_found: this.observedCalls.size,
              observations_omitted: this.omittedObservations,
              witnesses: [...this.witnesses.values()]
                .slice(0, MAX_ITEMS)
                .map((item) => this.witnessSummary(item)),
            }
          : {}),
        ...limit(Math.max(services.length, this.witnesses.size)),
      });
    }

    const byId = nodes.find(({ id }) => id === node);
    const matches = byId ? [byId] : nodes.filter(({ name }) => name === node);
    if (matches.length !== 1)
      return boundGraphResponse({
        matches: matches.slice(0, MAX_ITEMS),
        ...limit(matches.length),
      });
    const subject = matches[0]!;
    const detail: NodeGraphQuery = { node: subject, paths: [], evidence: [] };
    if (witness) {
      const calls = [...this.observedCalls.values()]
        .filter(
          ({ from, to, witnesses }) =>
            witnesses.has(witness.id) && (from === subject || to === subject),
        )
        .map(({ from, to, relation, witnesses }) => {
          const allPositions = witnesses.get(witness.id)!;
          const positions = allPositions.slice(0, MAX_ITEMS);
          const framePositions = [
            ...new Set(
              positions.flatMap((position) => [position, position + 1]),
            ),
          ];
          return {
            from,
            to,
            relation,
            witness: witness.id,
            positions,
            occurrences_found: allPositions.length,
            receiptSelections: [
              ...this.witnessSummary(witness).receiptSelections,
              ...this.witnessSelections(
                witness,
                framePositions.map((position) => ["frames", position]),
              ),
            ],
            ...limit(allPositions.length),
          };
        });
      return boundGraphResponse({
        ...detail,
        witness: this.witnessSummary(witness),
        observed_calls_found: calls.length,
        observed_calls: calls.slice(0, MAX_ITEMS),
        ...limit(calls.length),
      });
    }
    if (this.runtimeNodes.has(subject)) {
      const witnesses = matchingWitnesses(new Set([subject.id]));
      return boundGraphResponse({
        ...detail,
        witnesses_found: witnesses.length,
        witnesses: witnesses
          .slice(0, MAX_ITEMS)
          .map((item) => this.witnessSummary(item)),
        ...limit(witnesses.length),
      });
    }
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
    return boundGraphResponse({
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
    });
  }
}
