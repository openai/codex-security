import { parseJson } from "./value.js";
import { createHash } from "node:crypto";
import { open, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { isRecord } from "./record.js";
import {
  estimateScanCost,
  tokenUsage,
  type ScanCost,
  type ScanTokenUsage,
} from "./cost-model.js";
import {
  scanActivityFromSessionEvent,
  sessionContentText,
  type ScanActivity,
} from "./scan-activity.js";
import {
  isScanArtifactDirectory,
  sessionOwnsTurn,
  sessionParentThreadId,
  sessionStartedAt,
} from "./scan-sessions.js";
import {
  scanProgressUpdatesFromText,
  type ScanProgress,
} from "./worker-progress.js";

export { estimateScanCost, formatUsd, type ScanCost } from "./cost-model.js";

/** A persisted worker session discovered during this run. Contains no model text. */
export interface ScanWorkerEvent {
  kind: "observed";
  /** Scan-local number shared with activity and session observers. */
  worker: number;
}

export interface ScanSessionEvent {
  threadId: string;
  parentThreadId: string | null;
  worker?: number;
  event: Record<string, unknown>;
}

type SessionReasoning = ReturnType<typeof createSessionReasoning>;

function createSessionReasoning(id: string, text = "") {
  return { id, text, raw: false, activity: null as ScanActivity | null };
}

interface SessionProgress {
  update: ScanProgress;
  order?: number;
  position: number;
  completion: boolean;
  markerIndex: number;
  receipt: boolean;
  duplicate: boolean;
  // This saved occurrence already supplied scope before a delayed live copy.
  inventoryAdmitted?: true;
  scopeFilesTotal?: number;
  projection?: StreamedProgressItem;
}

interface ProgressItem {
  kind: "message" | "command";
  outputDigest: string;
  persistedOutputDigest: string;
  commandDigest?: string;
}

type ProgressOccurrenceQueues = Map<
  string,
  { indexes: number[]; next: number }
>;

interface NativeProgressItem extends ProgressItem {
  updates: ScanProgress[];
}

interface SessionCompletion {
  position: number;
  item: ProgressItem | null;
  kind?: ProgressItem["kind"];
  lastCommandProgress?: SessionProgress;
  // An exact completion, or a complete projection bounded by an exact anchor.
  // The latter does not identify the live command's occurrence.
  projection?: StreamedProgressItem;
}

interface UnresolvedParentCommand {
  live: StreamedProgressItem;
  after: number;
}

export type ParentProgressSource =
  | {
      event: Readonly<Record<string, unknown>>;
      reconciled?: false;
      inventory?: never;
    }
  | { reconciled: true; inventory?: true; worker?: true };

interface ParentProgressMarker {
  progress: ScanProgress;
  index: number;
  order: number;
  accepted: boolean;
  scopeFilesTotal?: number;
  // Source coordinates of a complete saved projection, not a live occurrence.
  projection?: { position: number; markerIndex: number };
}

interface ProgressOrder {
  order: number;
  position?: number;
  markerIndex?: number;
  live?: StreamedProgressItem;
  source?: SessionProgress;
}

interface OrderedProgress extends ProgressOrder {
  progress: ScanProgress;
}

interface LiveInventory extends OrderedProgress {
  marker: ParentProgressMarker;
  live: StreamedProgressItem;
}

interface InventoryEvidence extends OrderedProgress {
  position: number;
  markerIndex: number;
  afterLive?: StreamedProgressItem;
}

// A live parent keeps authority over an unresolved saved prefix. Once an exact
// anchor bounds that prefix, source order also governs admission and display.
// Independent workers and legacy projections still use observation order.
function compareProgressOrder(
  left: ProgressOrder,
  right: ProgressOrder,
): number {
  const source = compareSourceOrder(left, right);
  if (source !== undefined) return source;
  // A display preference is not source proof. Keep current live authority over
  // an unresolved prefix, while retaining that prefix for later reconciliation.
  if (left.live?.after !== undefined && right.position !== undefined) return 1;
  if (right.live?.after !== undefined && left.position !== undefined) return -1;
  const observedOrder = (candidate: ProgressOrder) => {
    const marker =
      candidate.source?.projection?.markers[candidate.markerIndex ?? 0];
    // A complete source projection retains its originating live order even
    // when polling observes that copy after a newer unpositioned phase.
    return marker !== undefined &&
      progressKey(marker.progress) === progressKey(candidate.source!.update)
      ? marker.order
      : candidate.order;
  };
  return observedOrder(left) - observedOrder(right);
}

function compareSourceOrder(
  left: ProgressOrder,
  right: ProgressOrder,
): number | undefined {
  const leftPosition = left.position ?? left.live?.position ?? undefined;
  const rightPosition = right.position ?? right.live?.position ?? undefined;
  if (leftPosition !== undefined && rightPosition !== undefined)
    return (
      leftPosition - rightPosition ||
      (left.markerIndex ?? 0) - (right.markerIndex ?? 0)
    );
  if (leftPosition !== undefined && right.live?.after !== undefined)
    return leftPosition >= right.live.after ? 1 : undefined;
  if (rightPosition !== undefined && left.live?.after !== undefined)
    return rightPosition >= left.live.after ? -1 : undefined;
  return undefined;
}

interface StreamedProgressItem {
  markers: ParentProgressMarker[];
  // Live review admission rejects later zero inventories in this same item,
  // even if recovered scope subsequently invalidates that review's cutoff.
  reviewMarker?: number;
  item: ProgressItem | null;
  position: number | null;
  // First saved position proved to follow an otherwise unpositioned live item.
  after?: number;
}

type SessionUsage = ReturnType<typeof createSessionUsage> & {
  events?: Record<string, unknown>[];
};

interface ScanCostTrackerOptions {
  codexHome: string;
  model: string;
  repository?: string;
  scanDirectory?: string;
  maxCostUsd?: number;
  expectedFilesTotal?: number;
  /** Incomplete costs are measured subtotals, usable for spending limits only. */
  onCost?: (cost: Readonly<ScanCost>, complete: boolean) => void;
  onUsage?: (usage: Readonly<ScanTokenUsage>) => void;
  onActivity?: (activity: ScanActivity) => void;
  onProgress?: (progress: ScanProgress, source?: ParentProgressSource) => void;
  onSessionEvent?: (event: ScanSessionEvent) => void;
  onWorkerEvent?: (event: ScanWorkerEvent) => void;
  onError?: (error: unknown) => void;
}

interface ScanCostSnapshot {
  usage: unknown;
  cost: ScanCost | null;
}

const COST_POLL_INTERVAL_MS = 100;
const SESSION_READ_SIZE = 64 * 1_024;

function createSessionUsage() {
  return {
    offset: 0,
    decoder: new StringDecoder("utf8"),
    pendingLine: [] as string[],
    unreadable: false,
    threadId: null as string | null,
    parentThreadId: null as string | null,
    workingDirectory: null as string | null,
    startedAt: null as number | null,
    inheritedUsage: null as ScanTokenUsage | null,
    replaying: false,
    usage: null as ScanTokenUsage | null,
    responseUsage: null as ScanTokenUsage | null,
    responseIds: new Set<string>(),
    calls: new Map<string, ScanActivity>(),
    activities: [] as ScanActivity[],
    progress: [] as SessionProgress[],
    position: 0,
    completions: [] as SessionCompletion[],
    latestWorkerProgress: null as OrderedProgress | null,
    pendingWorkerProgress: new Map<
      number,
      { progress: ScanProgress; order: number }
    >(),
    messageProjections: new Map<
      string,
      { native: number; event: number; response: number }
    >(),
    messageProgressOrder: 0,
    messageProgressFrontiers: { native: 0, event: 0, response: 0 },
    messageProgressProjections: new Map<
      string,
      {
        occurrences: number[];
        next: { native: number; event: number; response: number };
      }
    >(),
    filesCompleted: 0,
    filesTotal: null as number | null,
    prose: new Set<string>(),
    reasoning: null as SessionReasoning | null,
    reasoningCount: 0,
  };
}

export class ScanCostTracker {
  readonly #options: ScanCostTrackerOptions;
  readonly #sessions = new Map<string, SessionUsage>();
  readonly #receipts = new Map<string, ScanTokenUsage | null>();
  readonly #workers = new Map<string, number>();
  readonly #workerProgress = new Map<string, number>();
  readonly #liveParentProgress = new Set<string>();
  readonly #liveParentItems: StreamedProgressItem[] = [];
  #liveParentEvents = new WeakMap<
    Readonly<Record<string, unknown>>,
    StreamedProgressItem
  >();
  #acceptedParent: StreamedProgressItem | null = null;
  // Global coverage admitted from either the live or saved parent projection.
  #parentProgress: OrderedProgress | null = null;
  readonly #parentFacts = new Map<number, OrderedProgress>();
  #parentInventory: ParentProgressMarker | null = null;
  #parentInventoryBoundary: {
    position: number;
    markerIndex: number;
    reviewed: boolean;
    projection?: ProgressOrder & { live: StreamedProgressItem };
  } | null = null;
  // A bound excludes inventories at or after it without locating the review.
  #parentReviewBefore: (ProgressOrder & { live: StreamedProgressItem }) | null =
    null;
  readonly #readyParentMarkers = new Map<
    ParentProgressMarker,
    StreamedProgressItem
  >();
  #inventoryFrontier: Omit<InventoryEvidence, "progress"> & {
    progress?: ScanProgress;
  } = {
    position: 0,
    markerIndex: -1,
    order: 0,
    progress: undefined as ScanProgress | undefined,
  };
  #progressOrder = 0;
  #displayedProgress:
    | (ProgressOrder & {
        update: ScanProgress;
        owner: "live" | "parent" | "worker";
      })
    | null = null;
  #matchedParentItems = 0;
  #parentCompletionCursor = 0;
  #indexedParentCompletions = 0;
  #indexedParentItems = 0;
  readonly #parentCompletionKeys: ProgressOccurrenceQueues = new Map();
  readonly #parentItemKeys: ProgressOccurrenceQueues = new Map();
  readonly #parentMatches: number[] = [];
  readonly #pendingParentMatches = new Set<number>();
  #parentSession: SessionUsage | null = null;
  #parentTurnStartKnown = true;
  #parentFrontier = { position: 0, markerIndex: -1 };
  #threadId: string | null = null;
  #observingWorkers = true;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> = Promise.resolve();
  #snapshot: ScanCostSnapshot = { usage: null, cost: null };
  #lastCost: string | null = null;
  #lastUsage: string | null = null;
  #highestFilesCompleted = 0;
  #expectedFilesTotal: number | undefined;
  #parentTurnFilesTotal: number | undefined;
  #inventoryNeedsReconciliation = false;

  public constructor(options: ScanCostTrackerOptions) {
    this.#options = options;
    if (options.expectedFilesTotal !== undefined)
      this.setExpectedFilesTotal(options.expectedFilesTotal);
  }

  public setExpectedFilesTotal(filesTotal: number): void {
    this.#parentTurnFilesTotal ??= filesTotal;
    if (
      this.#expectedFilesTotal !== undefined &&
      this.#expectedFilesTotal !== filesTotal
    )
      this.#inventoryNeedsReconciliation = true;
    this.#expectedFilesTotal = filesTotal;
  }

  /** Called before launching a turn, after loading any resumed history. */
  public beginParentTurn(resumed = false): void {
    this.#parentTurnFilesTotal = this.#expectedFilesTotal;
    this.#parentTurnStartKnown = this.#parentSession !== null || !resumed;
    for (const live of this.#liveParentItems) {
      delete live.after;
    }
    this.#liveParentItems.length = 0;
    this.#liveParentEvents = new WeakMap();
    this.#acceptedParent = null;
    this.#parentInventory = null;
    this.#parentReviewBefore = null;
    // Historical logs may omit projection kinds emitted by the new turn.
    this.#parentSession?.messageProjections.clear();
    if (this.#parentSession !== null) {
      this.#parentSession.messageProgressProjections.clear();
      this.#parentSession.messageProgressOrder = 0;
      this.#parentSession.messageProgressFrontiers = {
        native: 0,
        event: 0,
        response: 0,
      };
    }
    // A new turn retires unresolved hypotheses from the previous turn; admitted
    // coverage and source summaries remain available for resumed scans.
    if (this.#parentSession !== null) this.#parentSession.progress.length = 0;
    for (const completion of this.#parentSession?.completions ?? []) {
      completion.item = null;
      delete completion.kind;
      delete completion.lastCommandProgress;
      delete completion.projection;
    }
    this.#readyParentMarkers.clear();
    this.#matchedParentItems = 0;
    this.#parentCompletionCursor = this.#parentSession?.completions.length ?? 0;
    this.#indexedParentCompletions = this.#parentCompletionCursor;
    this.#indexedParentItems = 0;
    this.#parentCompletionKeys.clear();
    this.#parentItemKeys.clear();
    this.#parentMatches.length = 0;
    this.#pendingParentMatches.clear();
    this.#liveParentProgress.clear();
  }

  /** Observe every supported completion so repeated output keeps its occurrence. */
  public recordParentItem(event: Readonly<Record<string, unknown>>): void {
    const item = event["item"];
    if (
      event["type"] !== "item.completed" ||
      !isRecord(item) ||
      (item["type"] !== "command_execution" &&
        item["type"] !== "agent_message") ||
      this.#liveParentEvents.has(event)
    )
      return;
    const live: StreamedProgressItem = {
      markers: [],
      item: streamedProgressItem(event),
      position: null,
    };
    this.#liveParentItems.push(live);
    this.#liveParentEvents.set(event, live);
    this.#matchParentCompletions();
  }

  /** Observe source identity before applying display/count guards. */
  public recordParentProgress(
    progress: ScanProgress,
    event: Readonly<Record<string, unknown>>,
  ): boolean {
    this.recordParentItem(event);
    const live = this.#liveParentEvents.get(event);
    if (live === undefined) return true;
    // Parsed rows were observed before this live marker even when their
    // file.close is still pending. Do not give that old snapshot a later order.
    for (const session of this.#sessions.values())
      if (session.threadId === this.#threadId)
        for (const saved of session.progress)
          saved.order ??= ++this.#progressOrder;
    const marker = {
      progress,
      index: live.markers.length,
      order: ++this.#progressOrder,
      accepted: false,
    };
    live.markers.push(marker);
    if (progress.phase === "discovery" && progress.filesCompleted === 0)
      this.#parentInventory = marker;
    if (live.position !== null) this.#readyParentMarkers.set(marker, live);
    const current =
      progress.phase === "discovery" && progress.filesCompleted === 0
        ? this.#retainedInventory()
        : this.#parentFacts.get(progress.filesTotal);
    return (
      live.position === null ||
      this.#afterParentFrontier(live.position, marker.index) ||
      // Polling can admit this completion before live delivery. Its live copy
      // restores progress after worker output or an unmatched live completion;
      // older proved positions and earlier markers remain stale.
      ((this.#displayedProgress?.owner === "worker" ||
        (this.#displayedProgress?.owner === "live" &&
          this.#displayedProgress.position === undefined)) &&
        ((live.position === this.#parentFrontier.position &&
          marker.index === this.#parentFrontier.markerIndex) ||
          (current?.position === this.#parentFrontier.position &&
            current.markerIndex === this.#parentFrontier.markerIndex &&
            progressKey(current.progress) === progressKey(progress))))
    );
  }

  /** Source acceptance is independent of duplicate observer notifications. */
  public deferParentInventory(event: Readonly<Record<string, unknown>>): void {
    const marker = this.#liveParentEvents.get(event)?.markers.at(-1);
    // Parent inventory can invalidate provisional worker coverage. Reconcile
    // it before displaying anything, so still-eligible coverage never drops.
    if (
      marker !== undefined &&
      marker === this.#parentInventory &&
      (!this.#parentIsEligible(this.#parentProgress) ||
        this.#parentProgress.progress.filesCompleted === 0)
    )
      marker.accepted = true;
  }

  public acceptParentProgress(
    progress: ScanProgress,
    event: Readonly<Record<string, unknown>>,
  ): void {
    const live = this.#liveParentEvents.get(event);
    if (live === undefined) return;
    const marker = live.markers.at(-1);
    if (marker === undefined) return;
    marker.accepted = true;
    if (progress.filesCompleted > 0) live.reviewMarker ??= marker.index;
    this.#acceptedParent = live;
    const provenance = {
      order: marker.order,
      live,
      markerIndex: marker.index,
      ...(live.position === null ? {} : { position: live.position }),
    };
    this.#parentProgress = { progress, ...provenance };
    this.#rememberParentFact(this.#parentProgress);
    const update = {
      ...progress,
      filesTotal: this.#expectedFilesTotal ?? progress.filesTotal,
    };
    this.#displayedProgress = { update, owner: "live", ...provenance };
    this.#highestFilesCompleted = Math.max(
      this.#highestFilesCompleted,
      progress.filesCompleted,
    );
    this.#liveParentProgress.add(progressKey(progress));
    this.#recordParentBoundary(
      progress,
      live.position ?? undefined,
      marker.index,
      true,
      undefined,
      live,
    );
    if (live.position !== null) {
      if (this.#afterParentFrontier(live.position, marker.index))
        this.#parentFrontier = {
          position: live.position,
          markerIndex: marker.index,
        };
    }
  }

  #rememberParentFact(candidate: OrderedProgress): void {
    // Unbound live markers stay in the existing completion queue until their
    // saved occurrence resolves. Inventory markers have their own frontier.
    if (
      candidate.position === undefined ||
      !this.#parentSourceIsEligible(candidate) ||
      (candidate.progress.phase === "discovery" &&
        candidate.progress.filesCompleted === 0)
    )
      return;
    const total = candidate.progress.filesTotal;
    const previous = this.#parentFacts.get(total);
    if (
      previous === undefined ||
      !this.#parentSourceIsEligible(previous) ||
      candidate.progress.filesCompleted > previous.progress.filesCompleted ||
      (candidate.progress.filesCompleted === previous.progress.filesCompleted &&
        compareProgressOrder(candidate, previous) > 0)
    )
      this.#parentFacts.set(total, candidate);
  }

  #parentSourceIsEligible(candidate: OrderedProgress): boolean {
    const marker = candidate.live?.markers[candidate.markerIndex ?? 0];
    return (
      // Inventory establishes scope; only coverage is bounded by its prefix.
      (candidate.progress.phase === "discovery" &&
        candidate.progress.filesCompleted === 0) ||
      candidate.progress.filesTotal <=
        (candidate.source?.scopeFilesTotal ??
          marker?.scopeFilesTotal ??
          Number.MAX_SAFE_INTEGER)
    );
  }

  #parentIsEligible(
    candidate: OrderedProgress | null,
  ): candidate is OrderedProgress {
    return (
      candidate !== null &&
      this.#parentSourceIsEligible(candidate) &&
      candidate.progress.filesTotal <=
        (this.#expectedFilesTotal ?? Number.MAX_SAFE_INTEGER)
    );
  }

  #parentInventoryWitness(): ProgressOrder | undefined {
    const accepted = this.#acceptedParent;
    if (accepted === null) return undefined;
    let witness: ProgressOrder | undefined;
    // Compute one proof for the accepted live prefix. Later unpositioned items
    // keep their predecessors' ordering evidence without gaining a position.
    for (const live of this.#liveParentItems) {
      for (const marker of live.markers) {
        if (
          marker.progress.phase === "discovery" &&
          marker.progress.filesCompleted === 0
        )
          continue;
        const position = live.position ?? marker.projection?.position;
        if (position === undefined) continue;
        const candidate = {
          position,
          markerIndex:
            live.position === null
              ? marker.projection!.markerIndex
              : marker.index,
          order: marker.order,
          live,
        };
        if (
          witness === undefined ||
          (compareSourceOrder(candidate, witness) ?? 0) > 0
        )
          witness = candidate;
      }
      if (live === accepted) break;
    }
    return witness;
  }

  #retainedInventory(): InventoryEvidence | undefined {
    const { progress, ...source } = this.#inventoryFrontier;
    return progress === undefined ? undefined : { progress, ...source };
  }

  #acceptedInventory(): LiveInventory | undefined {
    let accepted: LiveInventory | undefined;
    let precedingAnchor: StreamedProgressItem | undefined;
    for (const live of this.#liveParentItems) {
      for (const marker of live.markers) {
        if (
          !marker.accepted ||
          marker.progress.phase !== "discovery" ||
          marker.progress.filesCompleted !== 0 ||
          (live.position !== null &&
            !this.#inventoryPrecedesReview(
              live.position,
              marker.index,
              live,
            )) ||
          // An unresolved command follows the whole preceding exact completion.
          // That lower bound can exclude it without assigning it a position.
          (live.position === null &&
            precedingAnchor !== undefined &&
            !this.#inventoryPrecedesReview(
              precedingAnchor.position!,
              precedingAnchor.markers.length,
            ))
        )
          continue;
        const candidate = {
          progress: marker.progress,
          marker,
          live,
          position: live.position ?? undefined,
          markerIndex: marker.index,
          order: marker.order,
        };
        if ((this.#inventoryReviewOrder(candidate) ?? -1) >= 0) continue;
        if (
          accepted === undefined ||
          compareProgressOrder(candidate, accepted) > 0
        )
          accepted = candidate;
      }
      if (live.position !== null) precedingAnchor = live;
    }
    return accepted;
  }

  #savedInventorySupersedes(
    saved: InventoryEvidence,
    live: LiveInventory,
    native = this.#parentSession?.completions.some(
      (completion) => completion.kind === "command",
    ),
  ): boolean {
    const source = this.#inventorySourceOrder(saved, live);
    if (source !== undefined) {
      return source >= 0;
    } else if (live.live.after === undefined && !native) {
      // Older logs omit command completions. Their later phase receipts still
      // provide the existing best-effort evidence for a saved inventory.
      const phase = this.#parentFacts.get(saved.progress.filesTotal);
      const row = this.#parentSession?.progress.find(
        (row) =>
          row.position === saved.position &&
          row.markerIndex === saved.markerIndex,
      );
      const evidence =
        phase !== undefined && (compareSourceOrder(phase, saved) ?? 0) > 0
          ? phase
          : row === undefined || !this.#unboundParentCopy(row)
            ? saved
            : undefined;
      if (evidence !== undefined && compareProgressOrder(evidence, live) >= 0) {
        // Keep admitted relative authority when a later anchor only narrows
        // an unknown occurrence. Exact source order can still supersede it.
        saved.afterLive = live.live;
        return true;
      }
    }
    return false;
  }

  #inventorySourceOrder(
    saved: InventoryEvidence,
    live: LiveInventory,
  ): number | undefined {
    const source = compareSourceOrder(saved, live);
    if (source !== undefined) return source;
    const projection = saved.source?.projection;
    const marker = projection?.markers[saved.markerIndex];
    // A complete bounded projection preserves live inventory order without
    // identifying the saved occurrence. Count rejection cannot erase that proof.
    if (
      projection !== undefined &&
      marker !== undefined &&
      progressKey(marker.progress) === progressKey(saved.progress)
    )
      return (
        compareSourceOrder(
          { order: marker.order, markerIndex: marker.index, live: projection },
          live,
        ) ?? marker.order - live.order
      );
    return saved.afterLive === live.live ? 1 : undefined;
  }

  #projectParentInventory(): void {
    const saved = this.#retainedInventory();
    const live = this.#acceptedInventory();
    const selected =
      saved !== undefined &&
      (live === undefined || this.#savedInventorySupersedes(saved, live))
        ? saved
        : live;
    if (selected === saved && saved !== undefined) {
      if (saved.source !== undefined) saved.source.inventoryAdmitted = true;
      if (saved.afterLive !== undefined)
        this.#inventoryFrontier.afterLive = saved.afterLive;
    }
    const invalidated =
      selected === undefined &&
      this.#liveParentItems.some((item) =>
        item.markers.some(
          (marker) =>
            marker.accepted &&
            marker.progress.phase === "discovery" &&
            marker.progress.filesCompleted === 0,
        ),
      );
    // Empty source history does not override a caller's explicit scope update.
    // Roll back only when observed inventory authority has lost eligibility.
    const filesTotal =
      selected?.progress.filesTotal ??
      (invalidated ? this.#parentTurnFilesTotal : undefined);
    if (filesTotal !== undefined) {
      // Scope recovered here has not necessarily reached the API, including
      // its first assignment when registration supplied no file count.
      if (filesTotal !== this.#expectedFilesTotal)
        this.#inventoryNeedsReconciliation = true;
      this.setExpectedFilesTotal(filesTotal);
    }
  }

  #recordParentBoundary(
    progress: ScanProgress,
    position: number | undefined,
    markerIndex: number,
    admitted = false,
    filesTotal?: number,
    projection?: StreamedProgressItem,
  ): void {
    let reviewed = progress.filesCompleted > 0;
    filesTotal ??= projection?.markers[markerIndex]?.scopeFilesTotal;
    if (position === undefined) {
      if (
        reviewed &&
        admitted &&
        projection?.after !== undefined &&
        progress.filesTotal <= (filesTotal ?? Number.MAX_SAFE_INTEGER)
      ) {
        const marker = projection.markers[markerIndex]!;
        const previous = this.#parentReviewBefore;
        if (
          previous === null ||
          projection.after < previous.live.after! ||
          (projection.after === previous.live.after &&
            marker.order < previous.order)
        )
          this.#parentReviewBefore = {
            order: marker.order,
            markerIndex,
            live: projection,
          };
      }
      return;
    }
    // Eligible source progress can start review without winning the display.
    // Merely locating a rejected oversized marker cannot fix that cutoff.
    if (
      reviewed &&
      progress.filesTotal > (filesTotal ?? Number.MAX_SAFE_INTEGER)
    ) {
      const boundary = this.#parentInventoryBoundary;
      if (
        boundary?.reviewed === true &&
        boundary.position === position &&
        boundary.markerIndex === markerIndex
      )
        // Retire the contradicted cutoff while preserving its source position
        // as an ordering witness for preceding inventory.
        boundary.reviewed = false;
      if (projection === undefined) return;
      // A bounded current completion still orders its preceding inventory.
      // Scope-ineligible progress supplies that witness, not a reviewed cutoff.
      reviewed = false;
    }
    if (progress.filesCompleted === 0 && progress.phase === "discovery") return;
    const boundary = this.#parentInventoryBoundary;
    const order =
      boundary === null
        ? 0
        : position - boundary.position || markerIndex - boundary.markerIndex;
    // Before review starts, each later phase can establish its preceding
    // inventory. Once coverage starts, preserve the first reviewed boundary.
    if (
      boundary === null ||
      (reviewed
        ? !boundary.reviewed || order < 0
        : !boundary.reviewed && order > 0)
    )
      this.#parentInventoryBoundary = {
        position,
        markerIndex,
        reviewed,
        projection:
          projection === undefined
            ? reviewed
              ? undefined
              : boundary?.projection
            : {
                position,
                markerIndex,
                order: projection.markers[markerIndex]!.order,
                live: projection,
              },
      };
    else if (order === 0 && projection !== undefined)
      boundary.projection = {
        position,
        markerIndex,
        order: projection.markers[markerIndex]!.order,
        live: projection,
      };
  }

  #recordParentSourceBoundaries(
    command?: UnresolvedParentCommand,
  ): InventoryEvidence | undefined {
    const session = this.#parentSession;
    if (session === null) return;
    const native = session.completions.some(
      (completion) => completion.kind === "command",
    );
    const projectedItems = new Set<StreamedProgressItem>();
    for (const completion of session.completions)
      if (completion.projection !== undefined)
        projectedItems.add(completion.projection);
    this.#parentReviewBefore = null;
    for (const live of this.#liveParentItems) {
      for (const marker of live.markers) delete marker.projection;
      if (
        live.position === null &&
        live.after !== undefined &&
        !projectedItems.has(live)
      )
        // Complete projections get their eligibility from the ordered rows
        // below. Only omitted admitted reviews contribute this upper bound.
        for (const marker of live.markers)
          if (marker.accepted && marker.progress.filesCompleted > 0)
            this.#recordParentBoundary(
              marker.progress,
              undefined,
              marker.index,
              true,
              undefined,
              live,
            );
    }
    const authority = this.#acceptedInventory();
    // Legacy logs without command positions keep the established live scope.
    // An old copied preview cannot replace it merely by being read later.
    let filesTotal =
      !native &&
      authority?.live.position === null &&
      authority.live.after === undefined
        ? authority.progress.filesTotal
        : this.#parentTurnFilesTotal;
    let inventory: InventoryEvidence | LiveInventory | undefined;
    let savedInventory: InventoryEvidence | undefined;
    const scopeAt = (
      candidate: InventoryEvidence,
      completion?: SessionCompletion,
    ) => {
      if (
        !native ||
        inventory !== undefined ||
        authority?.live.position !== null ||
        Number.isFinite(authority.live.after)
      )
        return filesTotal;
      if (
        candidate.markerIndex < authority.marker.index &&
        completion?.item?.kind === "command" &&
        completion.item.outputDigest === authority.live.item?.outputDigest
      )
        // Complete output agreement proves marker layout, not occurrence.
        // A command's later inventory cannot justify its own earlier coverage.
        return filesTotal;
      // An initial estimate is not source proof against an admitted inventory
      // missing from persistence. Keep it for rows known or observed before
      // that live authority; unresolved later rows retain the admitted scope.
      const order =
        this.#inventorySourceOrder(candidate, authority) ??
        (candidate.order === 0 ? 1 : candidate.order - authority.order);
      return order < 0 ? filesTotal : authority.progress.filesTotal;
    };
    let liveIndex = 0;
    const applyBounds = (position: number) => {
      while (liveIndex < this.#liveParentItems.length) {
        const live = this.#liveParentItems[liveIndex]!;
        if (live.position !== null || live.after === undefined) {
          liveIndex++;
          continue;
        }
        if (live.after > position) break;
        liveIndex++;
        // Every marker remains available. A rejected trailing zero must not
        // replace inventory whose order still proves it precedes review.
        for (const marker of live.markers) {
          if (
            marker.progress.phase !== "discovery" ||
            marker.progress.filesCompleted !== 0 ||
            // A bound orders a lossy inventory but does not admit its scope.
            // Unaccepted inventory needs a complete projection or corroboration.
            (!marker.accepted && !projectedItems.has(live))
          )
            continue;
          const bounded = {
            progress: marker.progress,
            marker,
            live,
            markerIndex: marker.index,
            order: marker.order,
          };
          if (
            // An upper bound does not place this inventory at the anchor.
            // Unknown relative order cannot revoke already admitted scope.
            (this.#inventoryReviewOrder(bounded) ?? -1) < 0 &&
            (inventory === undefined ||
              ("marker" in inventory
                ? compareProgressOrder(inventory, bounded) < 0
                : !this.#savedInventorySupersedes(inventory, bounded, native)))
          ) {
            inventory = bounded;
            filesTotal = bounded.progress.filesTotal;
          }
        }
      }
    };
    const recordInventory = (candidate: InventoryEvidence) => {
      const retained = this.#retainedInventory();
      inventory =
        retained?.position === candidate.position &&
        retained.markerIndex === candidate.markerIndex
          ? retained
          : candidate;
      savedInventory = inventory;
      filesTotal = candidate.progress.filesTotal;
    };
    let completionIndex = 0;
    const remainingMarkers = (completion: SessionCompletion) => {
      applyBounds(completion.position);
      const live = completion.projection;
      if (
        completion.kind !== "command" ||
        live?.position !== completion.position
      )
        return;
      // Exact command identity also locates markers omitted by persistence.
      // Finish that command before examining the next saved source position.
      for (
        let index = (completion.lastCommandProgress?.markerIndex ?? -1) + 1;
        index < live.markers.length;
        index++
      ) {
        const marker = live.markers[index]!;
        marker.scopeFilesTotal = scopeAt(
          {
            progress: marker.progress,
            position: completion.position,
            markerIndex: marker.index,
            order: marker.order,
            live,
          },
          completion,
        );
        if (
          marker.progress.phase === "discovery" &&
          marker.progress.filesCompleted === 0
        ) {
          if (
            this.#inventoryPrecedesReview(
              completion.position,
              marker.index,
              live,
            )
          )
            recordInventory({
              progress: marker.progress,
              position: completion.position,
              markerIndex: marker.index,
              order: marker.order,
              live,
            });
        } else
          this.#recordParentBoundary(
            marker.progress,
            completion.position,
            marker.index,
            marker.accepted,
            marker.scopeFilesTotal,
          );
      }
    };
    for (const saved of session.progress) {
      while (
        completionIndex < session.completions.length &&
        session.completions[completionIndex]!.position < saved.position
      )
        remainingMarkers(session.completions[completionIndex++]!);
      const completion = session.completions[completionIndex];
      applyBounds(saved.position);
      saved.projection =
        completion?.position === saved.position
          ? completion.projection
          : undefined;
      const projected = saved.projection?.markers[saved.markerIndex];
      if (saved.duplicate) continue;
      const progress = saved.update;
      saved.scopeFilesTotal = scopeAt(
        {
          progress,
          position: saved.position,
          markerIndex: saved.markerIndex,
          order: saved.order ?? 0,
          source: saved,
        },
        completion?.position === saved.position ? completion : undefined,
      );
      const exact = completion?.projection?.position === saved.position;
      const nativeOccurrence = this.#parentTurnStartKnown && saved.completion;
      if (projected !== undefined) {
        projected.scopeFilesTotal = saved.scopeFilesTotal;
        if (progressKey(projected.progress) === progressKey(progress))
          projected.projection = {
            position: saved.position,
            markerIndex: saved.markerIndex,
          };
      }
      if (progress.phase === "discovery" && progress.filesCompleted === 0) {
        // Source eligibility follows the inventory at this position, not the
        // display scope at the start or end of a poll. The retained rows make
        // this ordered pass identical for every partition of the same input.
        if (
          this.#inventoryPrecedesReview(
            saved.position,
            saved.markerIndex,
            saved.projection,
            saved,
          )
        ) {
          if (exact || nativeOccurrence || !this.#unboundParentCopy(saved))
            recordInventory({
              progress,
              position: saved.position,
              markerIndex: saved.markerIndex,
              order: saved.order ?? 0,
              source: saved,
            });
          else if (
            authority !== undefined &&
            progressKey(progress) === progressKey(authority.progress) &&
            (compareSourceOrder(
              {
                position: saved.position,
                markerIndex: saved.markerIndex,
                order: saved.order ?? 0,
              },
              authority,
            ) ?? 0) >= 0
          ) {
            // A duplicate can restate the admitted legacy scope without proving
            // an occurrence or becoming eligible for another notification.
            inventory = authority;
            filesTotal = authority.progress.filesTotal;
          }
        }
        continue;
      }
      if (
        projected !== undefined ||
        // Native current-turn review rows have their own source evidence. Their
        // eligibility does not depend on the provisional display frontier.
        (nativeOccurrence && progress.filesCompleted > 0) ||
        (this.#savedParentProgressIsCurrent(saved) &&
          (command === undefined ||
            command.live !== this.#acceptedParent ||
            command.live.position !== null ||
            saved.position >= command.after)) ||
        (!saved.receipt &&
          progress.filesCompleted > 0 &&
          this.#liveParentProgress.has(progressKey(progress)))
      )
        this.#recordParentBoundary(
          progress,
          saved.position,
          saved.markerIndex,
          exact && (projected?.accepted ?? false),
          saved.scopeFilesTotal,
          projected === undefined ? undefined : completion!.projection,
        );
    }
    while (completionIndex < session.completions.length)
      remainingMarkers(session.completions[completionIndex++]!);
    return savedInventory;
  }

  #precedesParentBoundary(position: number, markerIndex: number): boolean {
    const first = this.#parentInventoryBoundary;
    return (
      first !== null &&
      (position < first.position ||
        (position === first.position && markerIndex < first.markerIndex))
    );
  }

  #inventoryAllowedInCompletion(
    live: StreamedProgressItem | undefined,
    markerIndex: number,
  ): boolean {
    return (
      live?.reviewMarker === undefined ||
      markerIndex < live.reviewMarker ||
      live.markers[markerIndex]?.accepted !== false
    );
  }

  #inventoryPrecedesReview(
    position: number,
    markerIndex: number,
    live?: StreamedProgressItem,
    source?: SessionProgress,
  ): boolean {
    return (
      (source?.inventoryAdmitted === true ||
        this.#inventoryAllowedInCompletion(live, markerIndex)) &&
      position < (this.#parentReviewBefore?.live.after ?? Infinity) &&
      (this.#parentInventoryBoundary?.reviewed !== true ||
        this.#precedesParentBoundary(position, markerIndex))
    );
  }

  #inventoryReviewOrder(inventory: ProgressOrder): number | undefined {
    const projection =
      inventory.live?.markers[inventory.markerIndex ?? 0]?.projection;
    if (
      // A complete projection can exclude this inventory even though its live
      // occurrence remains unknown. A mere upper bound cannot do so.
      (projection !== undefined &&
        !this.#inventoryPrecedesReview(
          projection.position,
          projection.markerIndex,
        )) ||
      !this.#inventoryAllowedInCompletion(
        inventory.live,
        inventory.markerIndex ?? 0,
      )
    )
      return 1;
    const boundary = this.#parentInventoryBoundary;
    const reviews: ProgressOrder[] = [];
    if (boundary?.reviewed === true)
      reviews.push({
        position: boundary.position,
        markerIndex: boundary.markerIndex,
        live: boundary.projection?.live,
        order: boundary.projection?.order ?? 0,
      });
    if (this.#parentReviewBefore !== null)
      reviews.push(this.#parentReviewBefore);
    let order: number | undefined = -1;
    for (const review of reviews) {
      const relation =
        compareSourceOrder(inventory, review) ??
        // A resolved projection or bounded omitted review preserves the live
        // sequence, including marker order within one command. It does not
        // assign either completion an otherwise unknown saved occurrence.
        (inventory.live !== undefined && review.live !== undefined
          ? inventory.order - review.order
          : undefined);
      if (relation !== undefined && relation >= 0) return relation;
      if (relation === undefined) order = undefined;
    }
    return order;
  }

  #afterParentFrontier(position: number, index: number): boolean {
    return (
      position > this.#parentFrontier.position ||
      (position === this.#parentFrontier.position &&
        index > this.#parentFrontier.markerIndex)
    );
  }

  #unresolvedParentCommand(): UnresolvedParentCommand | undefined {
    const live = this.#acceptedParent;
    if (
      live?.position !== null ||
      live.after === undefined ||
      !live.markers.some((marker) => marker.accepted)
    )
      return undefined;
    return { live, after: live.after };
  }

  #boundParentCommands(
    session: SessionUsage,
    start = 0,
    end = this.#liveParentItems.length,
    completionIndex = 0,
  ): void {
    // Exact-only intervals require neither source scans nor alias indexes.
    while (start < end && this.#liveParentItems[start]!.position !== null)
      start++;
    if (
      start === end ||
      !this.#parentTurnStartKnown ||
      !session.completions.some((completion) => completion.kind === "command")
    )
      return;
    while (start < end) {
      if (this.#liveParentItems[start]!.position !== null) {
        start++;
        continue;
      }
      let stop = start;
      while (stop < end && this.#liveParentItems[stop]!.position === null)
        stop++;
      const before = this.#liveParentItems[start - 1]?.position ?? 0;
      const after = this.#liveParentItems[stop]?.position ?? Infinity;
      const saved = new Map<string, SessionCompletion[]>();
      while (
        completionIndex < session.completions.length &&
        session.completions[completionIndex]!.position < after
      ) {
        const completion = session.completions[completionIndex++]!;
        if (
          completion.position <= before ||
          completion.item?.kind !== "command"
        )
          continue;
        // Bounded projections are derived from this interval, not occurrences.
        // Rebuild them when a later completion provides a tighter bound.
        if (completion.projection?.position === null)
          delete completion.projection;
        const key = completion.item.outputDigest;
        const occurrences = saved.get(key);
        if (occurrences === undefined) saved.set(key, [completion]);
        else occurrences.push(completion);
      }
      const observed = new Map<string, number[]>();
      const groups = new Map<string, { keys: string[]; members: number[] }>();
      for (let index = start; index < stop; index++) {
        const live = this.#liveParentItems[index]!;
        if (live.item?.kind !== "command") continue;
        const keys = [
          ...new Set([live.item.outputDigest, live.item.persistedOutputDigest]),
        ]
          .filter((key) => saved.has(key))
          .sort();
        for (const key of keys) {
          const occurrences = observed.get(key);
          if (occurrences === undefined) observed.set(key, [index]);
          else occurrences.push(index);
        }
        if (live.markers.length === 0) continue;
        const key = keys.join(":");
        const group = groups.get(key);
        if (group === undefined) groups.set(key, { keys, members: [index] });
        else group.members.push(index);
      }
      const evidence = new Map<
        number,
        {
          candidates: { saved: SessionCompletion[]; first: number }[];
          reserved: boolean;
        }
      >();
      for (const { keys, members } of groups.values()) {
        const queues = keys.map((key) => ({
          key,
          saved: saved.get(key)!,
          observed: observed.get(key)!,
          reserved: 0,
          next: 0,
        }));
        let reservations = 0;
        for (const index of members) {
          // Reserve preceding compatible live items once for this signature
          // group. Advancing ordered cursors is equivalent to consuming the
          // earliest compatible item for each saved occurrence, without splice.
          while (true) {
            const previous = Math.min(
              ...queues.map((queue) => queue.observed[queue.next] ?? Infinity),
            );
            if (previous >= index) break;
            const item = this.#liveParentItems[previous]!.item!;
            let selected: (typeof queues)[number] | undefined;
            for (const queue of queues) {
              if (queue.observed[queue.next] === previous) queue.next++;
              if (
                (queue.key === item.outputDigest ||
                  queue.key === item.persistedOutputDigest) &&
                queue.reserved < queue.saved.length &&
                (selected === undefined ||
                  queue.saved[queue.reserved]!.position <
                    selected.saved[selected.reserved]!.position)
              )
                selected = queue;
            }
            if (selected !== undefined) {
              selected.reserved++;
              reservations++;
            }
          }
          evidence.set(index, {
            candidates: queues.map((queue) => ({
              saved: queue.saved,
              first: queue.reserved,
            })),
            reserved: reservations > 0,
          });
        }
      }
      // Later complete projections constrain earlier compatible copies. A
      // bound narrows the interval without assigning a live occurrence.
      let bound = after;
      for (let index = stop - 1; index >= start; index--) {
        const live = this.#liveParentItems[index]!;
        bound = Math.min(bound, live.after ?? Infinity);
        const progress = live.markers.at(-1)?.progress;
        if (live.item?.kind !== "command" || progress === undefined) {
          if (bound !== Infinity) live.after = bound;
          continue;
        }
        const { candidates, reserved } = evidence.get(index)!;
        let latest: SessionCompletion | undefined;
        for (const { saved, first } of candidates) {
          let lower = first;
          let upper = saved.length;
          while (lower < upper) {
            const middle = Math.floor((lower + upper) / 2);
            if (saved[middle]!.position < bound) lower = middle + 1;
            else upper = middle;
          }
          const candidate = lower > first ? saved[lower - 1] : undefined;
          if (
            candidate !== undefined &&
            (latest === undefined || candidate.position > latest.position)
          )
            latest = candidate;
        }
        if (
          latest === undefined &&
          !reserved &&
          bound === Infinity &&
          !(progress.phase === "discovery" && progress.filesCompleted === 0)
        )
          continue;
        const visible = latest?.lastCommandProgress;
        const fullProjection =
          bound !== Infinity &&
          visible !== undefined &&
          visible.markerIndex === live.markers.length - 1 &&
          progressKey(visible.update) === progressKey(progress);
        if (fullProjection) latest!.projection = live;
        live.after = Math.min(
          live.after ?? Infinity,
          fullProjection ? visible.position + 1 : bound,
        );
        // A preceding completion ends before this projection's inclusive edge.
        bound = Math.min(bound, fullProjection ? visible.position : live.after);
      }
      start = stop + 1;
    }
  }

  #matchParentCompletions(): void {
    if (this.#parentSession === null || !this.#parentTurnStartKnown) return;
    const completions = this.#parentSession.completions;
    // Ordinary live completions can be dropped by native queue backpressure.
    // Match ordered signatures, not list indexes. Identical output signatures
    // remain ambiguous; use the earliest compatible occurrence after our anchor.
    const add = (
      index: number,
      key: string,
      queues: ProgressOccurrenceQueues,
    ) => {
      let queue = queues.get(key);
      if (queue === undefined) {
        queue = { indexes: [], next: 0 };
        queues.set(key, queue);
      }
      queue.indexes.push(index);
      this.#queueParentMatch(key);
    };
    while (this.#indexedParentCompletions < completions.length) {
      const index = this.#indexedParentCompletions++;
      const item = completions[index]!.item;
      if (item !== null)
        add(index, progressItemKey(item), this.#parentCompletionKeys);
    }
    while (this.#indexedParentItems < this.#liveParentItems.length) {
      const index = this.#indexedParentItems++;
      const item = this.#liveParentItems[index]!.item;
      if (item !== null)
        for (const key of progressItemKeys(item))
          add(index, key, this.#parentItemKeys);
    }
    while (this.#parentMatches.length > 0) {
      const index = takeFirstIndex(this.#parentMatches);
      this.#pendingParentMatches.delete(index);
      if (index < this.#matchedParentItems) continue;
      const live = this.#liveParentItems[index]!;
      if (live.item === null) continue;
      let matched: number | undefined;
      for (const key of progressItemKeys(live.item)) {
        const queue = this.#parentCompletionKeys.get(key);
        const savedIndex = queue?.indexes[queue.next];
        if (
          savedIndex !== undefined &&
          (matched === undefined || savedIndex < matched)
        )
          matched = savedIndex;
      }
      if (matched === undefined) continue;
      live.position = completions[matched]!.position;
      completions[matched]!.projection = live;
      for (const marker of live.markers)
        this.#readyParentMarkers.set(marker, live);
      this.#boundParentCommands(
        this.#parentSession,
        this.#matchedParentItems,
        index + 1,
        this.#parentCompletionCursor,
      );
      const changed = new Set<string>();
      const remove = (key: string, queues: ProgressOccurrenceQueues) => {
        const queue = queues.get(key)!;
        if (++queue.next === queue.indexes.length) queues.delete(key);
        changed.add(key);
      };
      // A compatible later anchor lets both prefixes advance. Without an
      // anchor, retain compact unmatched signatures: reads can precede writes
      // or native persistence can fail and later retry. Neither blocks other
      // compatible signatures, and each occurrence is indexed/consumed once.
      while (this.#matchedParentItems <= index) {
        const previous = this.#liveParentItems[this.#matchedParentItems++]!;
        if (previous.position === null) {
          if (previous.item?.kind !== "command") {
            previous.after = Math.min(
              previous.after ?? Infinity,
              live.position,
            );
          }
        }
        if (previous.item !== null) {
          for (const key of progressItemKeys(previous.item))
            remove(key, this.#parentItemKeys);
          if (previous.position !== null) previous.item = null;
        }
      }
      while (this.#parentCompletionCursor <= matched) {
        const saved = completions[this.#parentCompletionCursor++]!;
        if (saved.item !== null) {
          remove(progressItemKey(saved.item), this.#parentCompletionKeys);
          if (saved.position === live.position) {
            saved.item = null;
          }
        }
      }
      for (const key of changed) this.#queueParentMatch(key);
    }
  }

  #queueParentMatch(key: string): void {
    if (!this.#parentCompletionKeys.has(key)) return;
    const queue = this.#parentItemKeys.get(key);
    const index = queue?.indexes[queue.next];
    if (index === undefined || this.#pendingParentMatches.has(index)) return;
    this.#pendingParentMatches.add(index);
    insertIndex(this.#parentMatches, index);
  }

  #corroboratedInventory(
    live: StreamedProgressItem,
    marker: ParentProgressMarker,
    inventoryWitness?: ProgressOrder,
  ): InventoryEvidence | undefined {
    if (
      !this.#parentTurnStartKnown ||
      marker.progress.filesCompleted === 0 ||
      live.position === null
    )
      return undefined;
    let inventory: ParentProgressMarker | undefined;
    let pending: StreamedProgressItem | undefined;
    for (
      let index = this.#liveParentItems.indexOf(live) - 1;
      index >= 0;
      index--
    ) {
      const candidate = this.#liveParentItems[index]!;
      inventory = candidate.markers.findLast(
        (observed) =>
          (observed.accepted || observed === this.#parentInventory) &&
          observed.progress.phase === "discovery" &&
          observed.progress.filesCompleted === 0 &&
          observed.progress.filesTotal === marker.progress.filesTotal,
      );
      if (inventory !== undefined) {
        pending = candidate;
        break;
      }
    }
    if (
      inventory === undefined ||
      pending === undefined ||
      !this.#inventoryAllowedInCompletion(pending, inventory.index)
    )
      return undefined;
    let position = pending.position;
    if (position === null) {
      const item = pending.item;
      if (item?.kind !== "command") return undefined;
      for (const completion of this.#parentSession?.completions ?? []) {
        if (
          completion.item?.kind !== "command" ||
          completion.item.outputDigest !== item.persistedOutputDigest
        )
          continue;
        if (position !== null) return undefined;
        position = completion.position;
      }
    }
    // A retained source row may have supplied scope before its lossy live copy
    // arrived. Reusing that receipt does not locate the live command.
    const source = this.#inventoryFrontier.source;
    const admittedSource =
      source?.inventoryAdmitted === true &&
      source.position === position &&
      source.markerIndex === inventory.index &&
      progressKey(source.update) === progressKey(inventory.progress);
    // A matched review can corroborate an accepted inventory or admit a lost
    // inventory without assigning its command a guessed occurrence. A later
    // inventory still wins, and duplicate lossy output remains ambiguous.
    const bounded =
      position !== null &&
      (position > this.#inventoryFrontier.position ||
        (position === this.#inventoryFrontier.position &&
          ((pending.position !== null &&
            inventory.index >= this.#inventoryFrontier.markerIndex) ||
            admittedSource))) &&
      (position < live.position ||
        (pending.position !== null &&
          position === live.position &&
          inventory.index < marker.index));
    if (
      !bounded ||
      !this.#inventoryPrecedesReview(
        position!,
        pending.position === null ? 0 : inventory.index,
      )
    )
      return undefined;
    const later = this.#parentSession?.progress.findLast(
      (saved) =>
        !saved.duplicate &&
        saved.update.phase === "discovery" &&
        saved.update.filesCompleted === 0 &&
        (saved.position > position! ||
          (pending.position !== null &&
            saved.position === position &&
            saved.markerIndex > inventory.index)) &&
        (saved.position < live.position! ||
          (saved.position === live.position &&
            saved.markerIndex < marker.index)) &&
        this.#parentInventoryAdmission(
          saved,
          undefined,
          {
            live: pending,
            after: {
              position: position!,
              markerIndex: inventory.index,
              order: inventory.order,
            },
          },
          inventoryWitness,
        ) !== "retained",
    );
    // Corroboration admits scope without relocating the inventory to the review.
    // Its original live order continues to participate alongside newer scopes.
    if (later === undefined && pending.position === null) {
      inventory.accepted = true;
      return undefined;
    }
    return later === undefined
      ? {
          progress: inventory.progress,
          position: pending.position!,
          markerIndex: inventory.index,
          order: inventory.order,
        }
      : {
          progress: later.update,
          position: later.position,
          markerIndex: later.markerIndex,
          order: (later.order ??= ++this.#progressOrder),
          afterLive: pending,
          source: later,
        };
  }

  #reconcileParentProgress(): ProgressOrder | undefined {
    const ready = [...this.#readyParentMarkers];
    this.#readyParentMarkers.clear();
    for (const [marker, live] of ready) {
      if (live.position !== null) {
        this.#rememberParentFact({
          progress: marker.progress,
          order: marker.order,
          position: live.position,
          markerIndex: marker.index,
          live,
        });
        if (marker.accepted)
          this.#recordParentBoundary(
            marker.progress,
            live.position,
            marker.index,
            true,
            marker.scopeFilesTotal,
            live,
          );
      }
      if (marker.accepted && live.position !== null) {
        const source = { position: live.position, markerIndex: marker.index };
        if (this.#parentProgress?.order === marker.order)
          Object.assign(this.#parentProgress, source);
        if (
          this.#displayedProgress?.owner !== "worker" &&
          this.#displayedProgress?.order === marker.order
        )
          Object.assign(this.#displayedProgress, source);
      }
    }
    if (this.#parentSession !== null)
      this.#boundParentCommands(this.#parentSession);
    const unresolvedCommand = this.#unresolvedParentCommand();
    // Source proof and its eligible review cutoff precede inventory admission.
    // A count-rejected review can invalidate a later provisional inventory.
    const sourceInventory =
      this.#recordParentSourceBoundaries(unresolvedCommand);
    let witnessParent = this.#acceptedParent;
    let inventoryWitness = this.#parentInventoryWitness();
    if (
      !this.#inventoryPrecedesReview(
        this.#inventoryFrontier.position,
        this.#inventoryFrontier.markerIndex,
        this.#inventoryFrontier.live ??
          this.#inventoryFrontier.source?.projection,
        this.#inventoryFrontier.source,
      )
    )
      this.#inventoryFrontier = { position: 0, markerIndex: -1, order: 0 };
    const acceptedInventory = this.#acceptedInventory();
    let corrected:
      (OrderedProgress & { owner: "worker" | "live" | "parent" }) | null = null;
    for (const [marker, live] of ready) {
      const position = live.position;
      if (position === null) continue;
      const corroborated = this.#corroboratedInventory(
        live,
        marker,
        inventoryWitness,
      );
      const progress = corroborated?.progress ?? marker.progress;
      if (
        marker === this.#parentInventory &&
        !marker.accepted &&
        this.#parentProgress !== null &&
        this.#parentProgress.progress.filesCompleted > 0 &&
        this.#parentIsEligible(this.#parentProgress) &&
        this.#parentInventoryBoundary?.reviewed !== true
      ) {
        // A read can reach EOF before the next completion is appended, then
        // receive both live items while file.close is pending. Keep the compact
        // inventory proof until the admitted review's source position resolves.
        this.#readyParentMarkers.set(marker, live);
        continue;
      }
      if (
        (corroborated !== undefined ||
          marker === acceptedInventory?.marker ||
          (marker === this.#parentInventory &&
            this.#inventoryPrecedesReview(position, marker.index, live))) &&
        (corroborated !== undefined ||
          this.#inventoryPrecedesReview(position, marker.index, live)) &&
        progress.phase === "discovery" &&
        progress.filesCompleted === 0 &&
        (position > this.#inventoryFrontier.position ||
          (position === this.#inventoryFrontier.position &&
            marker.index >= this.#inventoryFrontier.markerIndex))
      ) {
        // A saved occurrence remains authoritative when its live copy arrives
        // after polling consumed it, even if provisional coverage rejects it.
        // Inventory may precede already-admitted review even when its full live
        // marker arrives later. For lossy output, the real matched review marks
        // the scope-proof boundary; the missing inventory position stays unknown.
        this.#inventoryFrontier = corroborated ?? {
          position,
          markerIndex: marker.index,
          order: marker.order,
          progress,
          live,
        };
      }
    }
    if (
      acceptedInventory !== undefined &&
      acceptedInventory.marker === this.#parentInventory &&
      acceptedInventory.live.position === null &&
      (!this.#parentIsEligible(this.#parentProgress) ||
        this.#parentProgress.progress.filesCompleted === 0) &&
      acceptedInventory.order > (this.#parentProgress?.order ?? 0)
    ) {
      // This live inventory was accepted for deferred scope reconciliation;
      // its saved occurrence remains unknown until source matching resolves it.
      const progress = acceptedInventory.marker.progress;
      this.#acceptedParent = acceptedInventory.live;
      this.#parentProgress = {
        progress,
        order: acceptedInventory.order,
        live: acceptedInventory.live,
        markerIndex: acceptedInventory.marker.index,
      };
      this.#liveParentProgress.add(progressKey(progress));
      corrected = { ...this.#parentProgress, owner: "live" };
      witnessParent = this.#acceptedParent;
      inventoryWitness = this.#parentInventoryWitness();
    }
    // Recover eligible retained source authority before a baseline rollback
    // could temporarily revive an out-of-scope parent or worker phase.
    if (
      this.#retainedInventory() === undefined &&
      this.#acceptedInventory() === undefined &&
      sourceInventory?.source !== undefined
    ) {
      const admission = this.#parentInventoryAdmission(
        sourceInventory.source,
        unresolvedCommand,
        undefined,
        inventoryWitness,
      );
      if (admission === "current" || admission === "proven")
        this.#inventoryFrontier = sourceInventory;
    }
    const inventory = this.#retainedInventory();
    this.#projectParentInventory();
    const inventoryChanged = this.#inventoryNeedsReconciliation;
    this.#inventoryNeedsReconciliation = false;
    const parentIneligible =
      this.#parentProgress !== null &&
      !this.#parentIsEligible(this.#parentProgress);
    const inventoryReconciled = inventoryChanged || parentIneligible;
    if (inventoryReconciled) {
      let retainedWorker: OrderedProgress | null = null;
      // Reconsider compact worker receipts under the proven inventory. Keep an
      // oversized receipt available without counting it as reviewed coverage.
      for (const session of this.#sessions.values()) {
        if (session.threadId === null || session.threadId === this.#threadId)
          continue;
        for (const [total, pending] of session.pendingWorkerProgress) {
          const progress = pending.progress;
          if (
            total > this.#expectedFilesTotal! ||
            (session.filesTotal !== null && total !== session.filesTotal) ||
            progress.filesCompleted < session.filesCompleted
          )
            continue;
          session.filesTotal = total;
          session.filesCompleted = progress.filesCompleted;
          const latest = session.latestWorkerProgress;
          if (
            latest === null ||
            progress.filesCompleted > latest.progress.filesCompleted ||
            pending.order > latest.order
          )
            session.latestWorkerProgress = pending;
          session.pendingWorkerProgress.delete(total);
          if (corrected === null || pending.order > corrected.order)
            corrected = { ...pending, owner: "worker" };
        }
        if (
          session.filesTotal !== null &&
          session.filesTotal <= this.#expectedFilesTotal!
        ) {
          this.#workerProgress.set(session.threadId, session.filesCompleted);
          const latest = session.latestWorkerProgress;
          if (
            latest !== null &&
            (retainedWorker === null || latest.order > retainedWorker.order)
          )
            retainedWorker = latest;
          if (
            parentIneligible &&
            latest !== null &&
            (corrected === null || latest.order > corrected.order)
          )
            corrected = { ...latest, owner: "worker" };
        } else this.#workerProgress.delete(session.threadId);
      }
      const parentCount = this.#parentIsEligible(this.#parentProgress)
        ? this.#parentProgress.progress.filesCompleted
        : 0;
      // Project the phase from the greatest eligible coverage. A zero-count
      // inventory establishes scope but cannot mask restored worker progress.
      const workerCoverage = Math.min(
        this.#expectedFilesTotal!,
        this.#workerProgress.values().reduce((sum, count) => sum + count, 0),
      );
      if (
        retainedWorker !== null &&
        workerCoverage > parentCount &&
        (corrected === null ||
          (corrected.owner !== "worker" &&
            workerCoverage > corrected.progress.filesCompleted))
      )
        corrected = { ...retainedWorker, owner: "worker" };
      this.#highestFilesCompleted = Math.max(parentCount, workerCoverage);
      if (this.#parentSession !== null) {
        this.#parentSession.filesCompleted = parentCount;
        this.#parentSession.filesTotal = this.#expectedFilesTotal!;
      }
    }
    const workerCoverage = Math.min(
      this.#expectedFilesTotal ?? Number.MAX_SAFE_INTEGER,
      this.#workerProgress.values().reduce((sum, count) => sum + count, 0),
    );
    for (const currentCompletion of this.#liveParentItems) {
      if (
        currentCompletion.position !== null ||
        // Unfamiliar projections supply no source identity. Keep the existing
        // recovery of an admitted completion's remaining parsed markers.
        (currentCompletion.item === null &&
          !currentCompletion.markers.some((marker) => marker.accepted))
      )
        continue;
      // A bound orders other completions; it does not retire later markers
      // inside any retained completion. Scope can make those markers eligible
      // after provisional worker coverage prevented their live admission.
      for (const marker of currentCompletion.markers) {
        const progress = marker.progress;
        const candidate: OrderedProgress & { owner: "live" } = {
          progress,
          order: marker.order,
          live: currentCompletion,
          markerIndex: marker.index,
          owner: "live",
        };
        if (
          marker.accepted ||
          !this.#parentSourceIsEligible(candidate) ||
          // Inventory has its own admission path. A rejected inventory cannot
          // become a phase merely because coverage later falls to zero.
          (progress.phase === "discovery" && progress.filesCompleted === 0) ||
          progress.filesTotal >
            (this.#expectedFilesTotal ?? Number.MAX_SAFE_INTEGER) ||
          progress.filesCompleted < this.#highestFilesCompleted ||
          (this.#parentProgress !== null &&
            compareProgressOrder(candidate, this.#parentProgress) < 0)
        )
          continue;
        marker.accepted = true;
        this.#acceptedParent = currentCompletion;
        this.#recordParentBoundary(
          progress,
          undefined,
          marker.index,
          true,
          undefined,
          currentCompletion,
        );
        this.#parentProgress = candidate;
        this.#liveParentProgress.add(progressKey(progress));
        this.#highestFilesCompleted = progress.filesCompleted;
        const correctedCoverage =
          corrected?.owner === "worker"
            ? workerCoverage
            : (corrected?.progress.filesCompleted ?? -1);
        if (
          progress.filesCompleted > correctedCoverage ||
          (progress.filesCompleted === correctedCoverage &&
            corrected !== null &&
            compareProgressOrder(candidate, corrected) > 0)
        )
          corrected = candidate;
      }
    }
    for (const [marker, live] of ready) {
      const position = live.position;
      const progress = marker.progress;
      const deferredCoverage =
        !marker.accepted &&
        progress.filesCompleted > this.#highestFilesCompleted;
      if (
        position === null ||
        (!deferredCoverage &&
          !this.#afterParentFrontier(position, marker.index) &&
          !(
            inventoryChanged &&
            marker === this.#parentInventory &&
            position === this.#parentFrontier.position &&
            marker.index === this.#parentFrontier.markerIndex
          ))
      )
        continue;
      const candidate: OrderedProgress & { owner: "live" } = {
        progress,
        order: marker.order,
        position,
        markerIndex: marker.index,
        live,
        owner: "live",
      };
      const selectedCoverage =
        corrected?.owner === "worker"
          ? workerCoverage
          : (corrected?.progress.filesCompleted ?? -1);
      // Do not let a newer, lower-coverage worker candidate mask a valid parent
      // correction before the final display guards can consider it.
      const preferCandidate =
        corrected === null ||
        progress.filesCompleted > selectedCoverage ||
        (progress.filesCompleted === selectedCoverage &&
          compareProgressOrder(candidate, corrected) > 0);
      if (!marker.accepted) {
        if (
          (this.#expectedFilesTotal !== undefined &&
            progress.filesTotal > this.#expectedFilesTotal) ||
          progress.filesTotal >
            (marker.scopeFilesTotal ?? Number.MAX_SAFE_INTEGER) ||
          progress.filesCompleted < this.#highestFilesCompleted ||
          (progress.phase === "discovery" &&
            progress.filesCompleted === 0 &&
            !this.#inventoryPrecedesReview(position, marker.index, live))
        ) {
          // Saved inventory can admit the live receipt or invalidate provisional
          // worker coverage. Keep only the parsed fact until it is eligible.
          this.#readyParentMarkers.set(marker, live);
          continue;
        }
        marker.accepted = true;
        this.#acceptedParent = live;
        const selectedParent = this.#parentProgress;
        if (
          !this.#parentIsEligible(selectedParent) ||
          progress.filesCompleted !== selectedParent.progress.filesCompleted ||
          compareProgressOrder(candidate, selectedParent) >= 0
        )
          this.#parentProgress = {
            progress,
            order: marker.order,
            position,
            markerIndex: marker.index,
            live,
          };
        this.#recordParentBoundary(
          progress,
          position,
          marker.index,
          false,
          marker.scopeFilesTotal,
        );
        this.#liveParentProgress.add(progressKey(progress));
        this.#highestFilesCompleted = progress.filesCompleted;
        if (preferCandidate) corrected = candidate;
      } else if (
        this.#parentIsEligible(candidate) &&
        this.#displayedProgress?.owner === "parent" &&
        compareProgressOrder(candidate, this.#displayedProgress) > 0 &&
        preferCandidate
      ) {
        corrected = candidate;
      }
      if (this.#afterParentFrontier(position, marker.index))
        this.#parentFrontier = { position, markerIndex: marker.index };
    }
    if (witnessParent !== this.#acceptedParent)
      inventoryWitness = this.#parentInventoryWitness();
    // Parent facts outlive display admission and queue draining. Preserve the
    // greatest eligible coverage for each original inventory, then source order.
    let eligible = this.#parentIsEligible(this.#parentProgress)
      ? this.#parentProgress
      : null;
    for (const candidate of [
      ...this.#parentFacts.values(),
      ...(inventory === undefined ? [] : [inventory]),
    ]) {
      // Apply eligible preceding inventories before promoting a retained phase.
      // Retained copies and unresolved alternatives are not unapplied work.
      if (
        this.#parentSession?.progress.some((saved) => {
          const admission = this.#parentInventoryAdmission(
            saved,
            unresolvedCommand,
            undefined,
            inventoryWitness,
          );
          return (
            (admission === "current" || admission === "proven") &&
            (saved.position < candidate.position! ||
              (saved.position === candidate.position &&
                saved.markerIndex < candidate.markerIndex!))
          );
        })
      )
        continue;
      if (
        !this.#parentIsEligible(candidate) ||
        candidate.progress.filesCompleted < workerCoverage
      )
        continue;
      if (
        eligible === null ||
        candidate.progress.filesCompleted > eligible.progress.filesCompleted ||
        (candidate.progress.filesCompleted ===
          eligible.progress.filesCompleted &&
          compareProgressOrder(candidate, eligible) > 0)
      )
        eligible = candidate;
    }
    if (eligible !== null) {
      this.#parentProgress = eligible;
      if (this.#afterParentFrontier(eligible.position!, eligible.markerIndex!))
        this.#parentFrontier = {
          position: eligible.position!,
          markerIndex: eligible.markerIndex!,
        };
      this.#recordParentBoundary(
        eligible.progress,
        eligible.position!,
        eligible.markerIndex!,
        false,
        eligible.source?.scopeFilesTotal ??
          eligible.live?.markers[eligible.markerIndex ?? 0]?.scopeFilesTotal,
        eligible.live,
      );
      this.#highestFilesCompleted = Math.max(
        workerCoverage,
        eligible.progress.filesCompleted,
      );
      if (this.#parentSession !== null) {
        this.#parentSession.filesCompleted = eligible.progress.filesCompleted;
        this.#parentSession.filesTotal =
          this.#expectedFilesTotal ?? eligible.progress.filesTotal;
      }
      const correctedCoverage =
        corrected?.owner === "worker"
          ? workerCoverage
          : (corrected?.progress.filesCompleted ?? -1);
      if (
        corrected === null ||
        eligible.progress.filesCompleted > correctedCoverage ||
        (eligible.progress.filesCompleted === correctedCoverage &&
          compareProgressOrder(eligible, corrected) > 0)
      )
        corrected = { ...eligible, owner: "parent" };
    }
    const displayed = this.#displayedProgress;
    const displayedParentIneligible =
      displayed !== null &&
      displayed.owner !== "worker" &&
      !this.#parentIsEligible({
        ...displayed,
        // Scope recovery can replace the parent before changing the display.
        // Requalify the receipt that actually supplied the displayed phase.
        progress:
          displayed.live?.markers[displayed.markerIndex ?? 0]?.progress ??
          displayed.source?.update ??
          displayed.update,
      });
    if (!inventoryReconciled && corrected === null) return inventoryWitness;
    const correctedCoverage =
      corrected?.owner === "worker"
        ? workerCoverage
        : (corrected?.progress.filesCompleted ?? 0);
    const replacePhase =
      corrected !== null &&
      correctedCoverage >= this.#highestFilesCompleted &&
      (displayed === null ||
        displayedParentIneligible ||
        correctedCoverage > displayed.update.filesCompleted ||
        compareProgressOrder(corrected, displayed) >= 0);
    const selected = replacePhase ? corrected : displayed;
    const parent = this.#parentProgress;
    const parentAtEqualCoverage =
      selected?.owner === "worker" &&
      this.#parentIsEligible(parent) &&
      parent.progress.filesCompleted === this.#highestFilesCompleted;
    const phase = parentAtEqualCoverage
      ? parent.progress.phase
      : replacePhase
        ? corrected!.progress.phase
        : (displayed?.update.phase ?? "discovery");
    const progress = {
      phase,
      filesCompleted: this.#highestFilesCompleted,
      filesTotal:
        this.#expectedFilesTotal ??
        corrected?.progress.filesTotal ??
        displayed!.update.filesTotal,
    };
    const key = progressKey(progress);
    // An initial zero-count discovery already reported this inventory. Other
    // equal raw keys can still require synchronization of the API's file total.
    const inventoryReported =
      progress.phase === "discovery" && progress.filesCompleted === 0;
    const duplicate =
      displayed !== null &&
      progressKey(displayed.update) === key &&
      (!inventoryReconciled || inventoryReported);
    const displaySource = parentAtEqualCoverage
      ? { ...parent, owner: "parent" as const }
      : selected;
    this.#displayedProgress = {
      update: progress,
      owner: displaySource?.owner ?? "live",
      order: displaySource?.order ?? 0,
      live: displaySource?.live,
      source: displaySource?.source,
      markerIndex: displaySource?.markerIndex,
      ...(displaySource?.position === undefined
        ? {}
        : {
            position: displaySource.position,
          }),
    };
    if (duplicate) return inventoryWitness;
    this.#options.onProgress?.(progress, {
      reconciled: true,
      ...(displaySource?.owner === "worker" ? { worker: true } : {}),
      // Recovered prefix scope can invalidate coverage even when a later
      // inventory restores the same total. Synchronize the API's count too.
      ...(inventoryReconciled ? { inventory: true } : {}),
    });
    return inventoryWitness;
  }

  #savedParentProgressIsCurrent(saved: SessionProgress): boolean {
    if (!this.#afterParentFrontier(saved.position, saved.markerIndex))
      return false;
    // An outer tool result has its own completion order. Native output does not
    // identify whether its text was copied from a nested command or emitted
    // directly, so text equality and call-start time cannot establish a copy.
    // Treat it as a receipt; a copied truncated preview can consequently hide
    // omitted same-count phases from its earlier command. This is best effort.
    if (saved.receipt) return true;
    const live = this.#acceptedParent;
    if (live === null) return true;
    // A later saved occurrence may legitimately repeat an earlier live tuple,
    // including progress recovered only from the original multipart response.
    if (live.position !== null) return saved.position > live.position;
    if (live.after !== undefined) return saved.position >= live.after;
    return !this.#unboundParentCopy(saved);
  }

  #unboundParentCopy(saved: SessionProgress): boolean {
    const live = this.#acceptedParent;
    return (
      !saved.receipt &&
      live?.position === null &&
      live.after === undefined &&
      this.#liveParentProgress.has(progressKey(saved.update))
    );
  }

  public recordUsage(usage: unknown, threadId = this.#threadId): void {
    const normalized = tokenUsage(usage);
    if (threadId !== null) {
      this.#receipts.set(threadId, normalized);
    }
  }

  public start(threadId: string): void {
    if (this.#threadId !== null) return;
    this.#threadId = threadId;
    if (
      this.#options.maxCostUsd === undefined &&
      this.#options.onCost === undefined &&
      this.#options.onUsage === undefined &&
      this.#options.onActivity === undefined &&
      this.#options.onProgress === undefined &&
      this.#options.onSessionEvent === undefined &&
      this.#options.onWorkerEvent === undefined
    ) {
      return;
    }
    let polling = false;
    let rerun = false;
    const poll = () => {
      if (polling) {
        rerun = true;
        return;
      }
      polling = true;
      void this.refresh()
        .catch((error: unknown) => {
          this.#options.onError?.(error);
        })
        .finally(() => {
          polling = false;
          if (rerun && this.#timer !== null) {
            rerun = false;
            poll();
          }
        });
    };
    this.#timer = setInterval(poll, COST_POLL_INTERVAL_MS);
    this.#timer.unref();
    poll();
  }

  public async refresh(): Promise<ScanCostSnapshot> {
    const update = this.#pending.then(async () => {
      await this.#readSessions();
    });
    this.#pending = update.catch(() => {});
    await update;
    return this.#snapshot;
  }

  public async stop(fallbackUsage?: unknown): Promise<ScanCostSnapshot> {
    clearInterval(this.#timer ?? undefined);
    this.#timer = null;
    if (fallbackUsage !== undefined) this.recordUsage(fallbackUsage);
    try {
      await this.refresh();
    } finally {
      this.#observingWorkers = false;
    }
    if (this.#receipts.size > 0 || this.#snapshot.usage !== null)
      return this.#snapshot;
    const cost = estimateScanCost(this.#options.model, fallbackUsage);
    this.#snapshot = { usage: fallbackUsage ?? null, cost };
    this.#reportUsage(tokenUsage(fallbackUsage));
    this.#reportCost(cost);
    return this.#snapshot;
  }

  async #readSessions(): Promise<void> {
    if (this.#threadId === null) return;
    const repository =
      this.#options.onActivity === undefined
        ? undefined
        : this.#options.repository;
    const progressThread =
      this.#options.onProgress === undefined ? undefined : this.#threadId;
    const unreadable: Array<{ session: SessionUsage; error: unknown }> = [];
    for await (const path of sessionFiles(
      join(this.#options.codexHome, "sessions"),
    )) {
      let session = this.#sessions.get(path);
      if (session === undefined) {
        session = createSessionUsage();
        this.#sessions.set(path, session);
      }
      try {
        await readSessionUsage(path, session, repository, progressThread);
      } catch (error) {
        if (session.threadId === null) throw error;
        unreadable.push({ session, error });
      }
    }

    const included = new Set([this.#threadId, ...this.#receipts.keys()]);
    if (this.#options.scanDirectory !== undefined) {
      const scanStartedAt =
        [...this.#sessions.values()].find(
          (session) => session.threadId === this.#threadId,
        )?.startedAt ?? null;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId === null ||
          session.parentThreadId !== null ||
          session.workingDirectory === null ||
          scanStartedAt === null ||
          session.startedAt === null ||
          session.startedAt < scanStartedAt
        ) {
          continue;
        }
        if (
          isScanArtifactDirectory(
            this.#options.scanDirectory,
            session.workingDirectory,
          )
        ) {
          included.add(session.threadId);
        }
      }
    }
    let previousSize: number;
    do {
      previousSize = included.size;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId !== null &&
          session.parentThreadId !== null &&
          included.has(session.parentThreadId)
        ) {
          included.add(session.threadId);
        }
      }
    } while (included.size !== previousSize);
    for (const { session, error } of unreadable) {
      if (included.has(session.threadId!)) throw error;
    }

    const usages = new Map(this.#receipts);
    for (const [path, session] of this.#sessions) {
      const threadId = session.threadId;
      if (threadId === null || !included.has(threadId)) continue;
      if (
        this.#options.onSessionEvent !== undefined &&
        session.events === undefined
      ) {
        // Replay event history through the already-read snapshot without
        // replacing its authoritative progress, usage, or partial-line decoder.
        const replay: SessionUsage = createSessionUsage();
        replay.events = [];
        await readSessionUsage(
          path,
          replay,
          undefined,
          undefined,
          session.offset,
        );
        if (replay.offset === session.offset) session.events = replay.events;
      }
      let worker: number | undefined;
      if (threadId !== this.#threadId) {
        worker = this.#workers.get(threadId);
        if (worker === undefined) {
          worker = this.#workers.size + 1;
          this.#workers.set(threadId, worker);
          if (this.#observingWorkers)
            this.#options.onWorkerEvent?.({ kind: "observed", worker });
        }
      }
      for (const event of session.events?.splice(0) ?? []) {
        this.#options.onSessionEvent?.({
          threadId,
          parentThreadId: session.parentThreadId,
          worker,
          event,
        });
      }
      if (worker !== undefined) {
        for (const activity of session.activities.splice(0)) {
          this.#options.onActivity?.({
            ...activity,
            id: `${threadId}:${activity.id}`,
            worker,
          });
        }
      }
      let unresolvedCommand: UnresolvedParentCommand | undefined;
      let inventoryWitness: ProgressOrder | undefined;
      if (threadId === this.#threadId) {
        this.#parentSession = session;
        for (const saved of session.progress)
          if (saved.order !== undefined && !saved.duplicate)
            this.#rememberParentFact({
              progress: saved.update,
              order: saved.order,
              position: saved.position,
              markerIndex: saved.markerIndex,
              source: saved,
            });
        this.#matchParentCompletions();
        inventoryWitness = this.#reconcileParentProgress();
        unresolvedCommand = this.#unresolvedParentCommand();
      }
      const reviewWasUnpositioned =
        this.#parentInventoryBoundary?.reviewed !== true;
      this.#reportSessionProgress(
        session,
        threadId === this.#threadId,
        unresolvedCommand,
        inventoryWitness,
      );
      // Fresh saved facts are observed at their source-loop position, so initial
      // inventory notifications keep their order. Recover after the batch too:
      // a later accepted parent may have hidden an eligible earlier receipt.
      if (threadId === this.#threadId) {
        // A newly admitted review locates inventories parked earlier in this
        // batch. Reconsider them before the final refresh returns.
        if (
          reviewWasUnpositioned &&
          this.#parentInventoryBoundary?.reviewed === true
        )
          this.#reportSessionProgress(
            session,
            true,
            unresolvedCommand,
            inventoryWitness,
          );
        this.#reconcileParentProgress();
      }
      const receipt = usages.get(threadId);
      // A discovered thread without a receipt has unknown usage, not zero.
      // Retain it so a parent-only subtotal cannot appear to be complete.
      if (receipt === undefined) usages.set(threadId, null);
      if (
        session.usage !== null &&
        (session.usage.total_tokens > (receipt?.total_tokens ?? -1) ||
          // The SDK inserts zero when the final receipt omits cache writes.
          (session.usage.total_tokens === receipt?.total_tokens &&
            receipt.cache_write_input_tokens === 0))
      ) {
        usages.set(threadId, session.usage);
      }
    }
    let usage: ScanTokenUsage | null = null;
    let complete = true;
    for (const value of usages.values()) {
      if (value === null) {
        complete = false;
        continue;
      }
      usage = addTokenUsage(usage, value);
    }
    if (!complete) this.#snapshot = { usage: null, cost: null };
    if (usage === null) return;
    const cost = estimateScanCost(this.#options.model, usage);
    if (complete) {
      this.#snapshot = { usage, cost };
      this.#reportUsage(usage);
    }
    this.#reportCost(cost, complete);
  }

  #parentInventoryAdmission(
    saved: SessionProgress,
    command?: UnresolvedParentCommand,
    corroboration?: { live: StreamedProgressItem; after: ProgressOrder },
    inventoryWitness?: ProgressOrder,
  ): "current" | "proven" | "retained" | undefined {
    if (saved.update.phase !== "discovery" || saved.update.filesCompleted !== 0)
      return undefined;
    const newer =
      saved.position > this.#inventoryFrontier.position ||
      (saved.position === this.#inventoryFrontier.position &&
        saved.markerIndex > this.#inventoryFrontier.markerIndex);
    if (saved.duplicate || !newer) return "retained";
    if (
      !this.#inventoryPrecedesReview(
        saved.position,
        saved.markerIndex,
        saved.projection,
        saved,
      )
    )
      return "retained";
    const authority = this.#acceptedInventory();
    const source = {
      progress: saved.update,
      position: saved.position,
      markerIndex: saved.markerIndex,
      order: saved.order ?? 0,
      source: saved,
    };
    // A matched review can order an inventory after a compatible truncated
    // prefix without identifying the live command's occurrence. That proof
    // applies to its own inventory, not a newer independent live authority.
    const relation =
      authority === undefined
        ? 0
        : (this.#inventorySourceOrder(source, authority) ??
          (corroboration?.live === authority.live
            ? compareSourceOrder(source, corroboration.after)
            : undefined) ??
          (authority.live.after === undefined ? 0 : -1));
    if (
      this.#precedesParentBoundary(saved.position, saved.markerIndex) &&
      (this.#parentInventoryBoundary?.reviewed === true ||
        !this.#parentIsEligible(this.#parentProgress) ||
        this.#parentProgress.progress.filesCompleted === 0 ||
        (inventoryWitness !== undefined &&
          (compareSourceOrder(source, inventoryWitness) ?? 0) < 0)) &&
      relation >= 0
    )
      return "proven";
    if (
      (this.#parentIsEligible(this.#parentProgress) &&
        this.#parentProgress.progress.filesCompleted > 0) ||
      !this.#savedParentProgressIsCurrent(saved) ||
      (command !== undefined &&
        command.live === this.#acceptedParent &&
        command.live.position === null &&
        this.#parentProgress !== null &&
        saved.position < command.after &&
        this.#afterParentFrontier(saved.position, saved.markerIndex))
    )
      return "retained";
    return "current";
  }

  #reportSessionProgress(
    session: SessionUsage,
    parent: boolean,
    command?: UnresolvedParentCommand,
    inventoryWitness?: ProgressOrder,
  ): void {
    if (this.#options.onProgress === undefined || session.threadId === null) {
      return;
    }
    const live = this.#acceptedParent;
    const current = this.#parentProgress;
    const unresolvedCommandState =
      parent &&
      command?.live === live &&
      live?.position === null &&
      current !== null;
    // Parent rows are source evidence, not a notification queue. Admission or
    // temporary scope exclusion cannot discard an unresolved occurrence.
    // Worker receipts are independent and retain their compact summaries below.
    for (const saved of parent
      ? session.progress
      : session.progress.splice(0)) {
      const progress = saved.update;
      const inventory = parent
        ? this.#parentInventoryAdmission(
            saved,
            command,
            undefined,
            inventoryWitness,
          )
        : undefined;
      if (inventory === "retained") continue;
      const inventoryMarker = inventory !== undefined;
      const provenInventory = inventory === "proven";
      // Source order governs equal-count phases. Fresh and parked receipts can
      // both add coverage after a scope correction makes that coverage eligible.
      const greaterCoverage =
        progress.filesCompleted > this.#highestFilesCompleted;
      if (
        parent &&
        !saved.duplicate &&
        !inventoryMarker &&
        !this.#unboundParentCopy(saved)
      )
        this.#rememberParentFact({
          progress,
          order: (saved.order ??= ++this.#progressOrder),
          position: saved.position,
          markerIndex: saved.markerIndex,
          source: saved,
        });
      if (
        unresolvedCommandState &&
        saved.position < (command?.after ?? Infinity) &&
        this.#afterParentFrontier(saved.position, saved.markerIndex) &&
        !provenInventory &&
        progress.filesCompleted <= this.#highestFilesCompleted
      ) {
        // Keep lossy-output ambiguity across marker-free anchors; a current
        // state or greater coverage must supply the missing progress evidence.
        continue;
      }
      if (
        parent &&
        !provenInventory &&
        !greaterCoverage &&
        !this.#savedParentProgressIsCurrent(saved)
      )
        continue;
      if (saved.duplicate) {
        if (
          parent &&
          saved.completion &&
          this.#afterParentFrontier(saved.position, saved.markerIndex)
        )
          this.#parentFrontier = {
            position: saved.position,
            markerIndex: saved.markerIndex,
          };
        continue;
      }
      const expectedFilesTotal = this.#expectedFilesTotal;
      const parentInventory = inventoryMarker;
      const order = (saved.order ??= ++this.#progressOrder);
      if (
        (!parent &&
          session.filesTotal !== null &&
          progress.filesTotal !== session.filesTotal) ||
        (!parentInventory && progress.filesCompleted < session.filesCompleted)
      )
        continue;
      if (
        !parentInventory &&
        ((expectedFilesTotal !== undefined &&
          progress.filesTotal > expectedFilesTotal) ||
          (parent &&
            progress.filesTotal >
              (saved.scopeFilesTotal ?? Number.MAX_SAFE_INTEGER)))
      ) {
        if (!parent) {
          const pending = session.pendingWorkerProgress.get(
            progress.filesTotal,
          );
          if (
            pending === undefined ||
            progress.filesCompleted >= pending.progress.filesCompleted
          )
            session.pendingWorkerProgress.set(progress.filesTotal, {
              progress,
              order,
            });
        }
        continue;
      }
      session.filesTotal = progress.filesTotal;
      session.filesCompleted = progress.filesCompleted;
      if (!parent) session.latestWorkerProgress = { progress, order };
      if (parentInventory && this.#highestFilesCompleted > 0) {
        // An inventory behind admitted review changes scope without replaying
        // its earlier phase. At zero coverage it follows normal source-ordered
        // phase admission below, including when the inventory total changes.
        if (
          !this.#parentIsEligible(this.#parentProgress) ||
          this.#parentProgress.progress.filesCompleted === 0
        ) {
          const candidate = {
            progress,
            order,
            position: saved.position,
            markerIndex: saved.markerIndex,
          };
          if (
            this.#parentProgress === null ||
            this.#parentProgress.progress.phase !== "discovery" ||
            compareProgressOrder(candidate, this.#parentProgress) >= 0
          )
            this.#parentProgress = candidate;
        }
        const position = {
          position: saved.position,
          markerIndex: saved.markerIndex,
        };
        if (this.#afterParentFrontier(saved.position, saved.markerIndex))
          this.#parentFrontier = position;
        this.#inventoryFrontier = {
          ...position,
          order,
          progress,
          source: saved,
        };
        this.#projectParentInventory();
        continue;
      }
      // Parent markers already describe global coverage, including its workers.
      // Only worker-local counts belong in the delegated shard sum.
      if (!parent)
        this.#workerProgress.set(session.threadId, progress.filesCompleted);
      const filesCompleted = parent
        ? progress.filesCompleted
        : Math.min(
            expectedFilesTotal ?? Number.MAX_SAFE_INTEGER,
            this.#workerProgress
              .values()
              .reduce((total, reviewed) => total + reviewed, 0),
          );
      if (filesCompleted < this.#highestFilesCompleted) {
        // A provisional worker can exceed this global parent receipt, then
        // become ineligible when the parent's earlier inventory is recovered.
        // Keep the parsed parent fact for that correction, without displaying
        // a count decrease while the worker coverage remains eligible.
        continue;
      }
      // A worker-local phase cannot replace eligible global parent authority
      // when the aggregate count adds no reviewed files. Counts remain above.
      if (
        !parent &&
        this.#parentIsEligible(this.#parentProgress) &&
        filesCompleted === this.#parentProgress.progress.filesCompleted
      )
        continue;
      if (parent)
        this.#recordParentBoundary(
          progress,
          saved.position,
          saved.markerIndex,
          false,
          saved.scopeFilesTotal,
        );
      // Known parent positions outrank observation order: polling can park a
      // newer completion before an earlier live completion is displayed.
      const displayed = this.#displayedProgress;
      const provenance = {
        order,
        position: saved.position,
        markerIndex: saved.markerIndex,
        source: saved,
      };
      const newerProgress =
        parent &&
        displayed !== null &&
        displayed.owner !== "worker" &&
        filesCompleted === displayed.update.filesCompleted &&
        compareProgressOrder(provenance, displayed) < 0
          ? displayed
          : null;
      const update = newerProgress?.update ?? {
        ...progress,
        filesCompleted,
        filesTotal: parent
          ? progress.filesTotal
          : (expectedFilesTotal ??
            Math.max(progress.filesTotal, filesCompleted)),
      };
      // Retaining a newer parent phase retains that whole receipt, including
      // its actual inventory. Mixing an older total with its phase would discard
      // valid parent coverage when a later inventory correction arrives.
      if (parent && newerProgress === null)
        this.#parentProgress = { progress, ...provenance };
      const key = progressKey(update);
      if (parent) {
        // An original multipart response can expose progress absent from its
        // concatenated native projection. Its admitted source position still
        // prevents an older live completion from replaying over that progress.
        if (this.#afterParentFrontier(saved.position, saved.markerIndex))
          this.#parentFrontier = {
            position: saved.position,
            markerIndex: saved.markerIndex,
          };
        if (parentInventory) {
          if (newerProgress === null) saved.inventoryAdmitted = true;
          this.#inventoryFrontier = {
            position: saved.position,
            markerIndex: saved.markerIndex,
            order,
            progress,
            source: saved,
          };
        }
      }
      this.#highestFilesCompleted = update.filesCompleted;
      this.#displayedProgress =
        newerProgress !== null
          ? { ...newerProgress, update }
          : {
              update,
              owner: parent ? "parent" : "worker",
              order,
              ...(parent
                ? {
                    position: saved.position,
                    markerIndex: saved.markerIndex,
                    source: saved,
                  }
                : {}),
            };
      // Distinct equal-valued receipts still advance source ownership/order.
      if (displayed !== null && progressKey(displayed.update) === key) continue;
      this.#options.onProgress(
        update,
        parent ? { reconciled: true } : undefined,
      );
    }
  }

  #reportCost(cost: ScanCost | null, complete = true): void {
    if (cost === null) return;
    const signature = JSON.stringify([cost, complete]);
    if (signature === this.#lastCost) return;
    this.#lastCost = signature;
    this.#options.onCost?.(cost, complete);
  }

  #reportUsage(usage: ScanTokenUsage | null): void {
    if (usage === null) return;
    const signature = JSON.stringify(usage);
    if (signature === this.#lastUsage) return;
    this.#lastUsage = signature;
    this.#options.onUsage?.(usage);
  }
}

export async function* sessionFiles(
  directory: string,
  compressed = false,
): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      yield* sessionFiles(path, compressed);
    } else if (
      entry.isFile() &&
      (entry.name.endsWith(".jsonl") ||
        (compressed && entry.name.endsWith(".jsonl.zst")))
    ) {
      yield path;
    }
  }
}

async function readSessionUsage(
  path: string,
  session: SessionUsage,
  repository?: string,
  progressThread?: string,
  throughOffset?: number,
): Promise<void> {
  if (session.unreadable) return;
  let file;
  try {
    if ((await stat(path)).size === session.offset) return;
    file = await open(path, "r");
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  try {
    const buffer = Buffer.alloc(SESSION_READ_SIZE);
    while (throughOffset === undefined || session.offset < throughOffset) {
      const { bytesRead } = await file.read(
        buffer,
        0,
        throughOffset === undefined
          ? buffer.length
          : Math.min(buffer.length, throughOffset - session.offset),
        session.offset,
      );
      if (bytesRead === 0) return;
      session.offset += bytesRead;
      try {
        const lines = session.decoder
          .write(buffer.subarray(0, bytesRead))
          .split("\n");
        session.pendingLine.push(lines[0]!);
        for (const line of lines.slice(1)) {
          readSessionEvent(
            session.pendingLine.join(""),
            session,
            repository,
            progressThread,
          );
          session.pendingLine = [line];
        }
      } catch (error) {
        session.unreadable = true;
        session.pendingLine = [];
        throw error;
      }
    }
  } finally {
    await file.close();
  }
}

function readSessionEvent(
  line: string,
  session: SessionUsage,
  repository?: string,
  progressThread?: string,
): void {
  if (line.length === 0) return;
  const event = parseJson(() => line);
  if (!isRecord(event) || !isRecord(event["payload"])) return;
  const payload = event["payload"];
  if (event["type"] === "session_meta") {
    if (session.threadId !== null) {
      session.replaying = payload["id"] !== session.threadId;
      if (!session.replaying) session.events?.push(event);
      return;
    }
    if (typeof payload["id"] === "string") {
      session.threadId = payload["id"];
    }
    if (typeof payload["cwd"] === "string") {
      session.workingDirectory = payload["cwd"];
    }
    session.startedAt = sessionStartedAt(payload["timestamp"]);
    session.parentThreadId = sessionParentThreadId(payload);
    session.events?.push(event);
    return;
  }
  if (session.replaying) {
    if (event["type"] !== "event_msg") return;
    if (payload["type"] === "token_count" && isRecord(payload["info"])) {
      const usage = tokenUsage(payload["info"]["total_token_usage"]);
      if (usage !== null) session.inheritedUsage = usage;
    }
    if (
      payload["type"] === "task_started" &&
      sessionOwnsTurn(session, payload)
    ) {
      session.replaying = false;
      session.events?.push(event);
    }
    return;
  }
  session.events?.push(event);
  const position = ++session.position;
  if (event["type"] === "token_usage_record") {
    const responseId = payload["response_id"];
    if (
      payload["thread_id"] !== session.threadId ||
      typeof responseId !== "string" ||
      session.responseIds.has(responseId)
    ) {
      return;
    }
    const usage = tokenUsage(payload["usage"]);
    if (usage === null) return;
    session.responseIds.add(responseId);
    session.responseUsage = addTokenUsage(session.responseUsage, usage);
    // Native thread totals include compaction and any earlier turns. They are
    // scoped to thread_id, unlike inherited legacy token_count snapshots.
    const total = tokenUsage(payload["thread_token_usage"]);
    const recorded =
      total !== null && total.total_tokens >= session.responseUsage.total_tokens
        ? total
        : session.responseUsage;
    if (
      session.usage === null ||
      recorded.total_tokens >= session.usage.total_tokens
    ) {
      session.usage = recorded;
    }
    return;
  }
  if (event["type"] === "response_item") {
    const receipt =
      payload["type"] === "function_call_output" ||
      payload["type"] === "custom_tool_call_output" ||
      payload["type"] === "local_shell_call_output";
    const message =
      payload["type"] === "message" &&
      payload["role"] === "assistant" &&
      Array.isArray(payload["content"])
        ? payload["content"]
            .filter(isRecord)
            .map((part) =>
              typeof part["text"] === "string" ? part["text"] : "",
            )
            .join("")
        : null;
    const updates = sessionProgressUpdates(payload);
    const duplicateMessage =
      message !== null &&
      repeatedMessageProjection(session, digest(message), "response", updates);
    // Code-mode notifications and the final output can share a call ID.
    // Each appended output record remains a distinct completion receipt.
    for (const [markerIndex, update] of (duplicateMessage
      ? []
      : updates
    ).entries()) {
      session.progress.push({
        update,
        position,
        completion: false,
        markerIndex,
        receipt,
        duplicate: false,
      });
    }
    if (repository === undefined) return;
    if (
      payload["type"] === "reasoning" &&
      typeof payload["id"] === "string" &&
      Array.isArray(payload["summary"]) &&
      payload["summary"].length > 1 &&
      session.reasoning?.raw !== true
    ) {
      for (const [index, summary] of payload["summary"].entries()) {
        const activity = scanActivityFromSessionEvent(
          {
            ...event,
            payload: {
              ...payload,
              id: `${payload["id"]}:${index}`,
              summary: [summary],
            },
          },
          repository,
        );
        if (
          activity === null ||
          session.prose.has(`${activity.kind}:${activity.description}`)
        ) {
          continue;
        }
        session.reasoning = createSessionReasoning(
          activity.id,
          activity.description,
        );
        recordReasoningActivity(session, activity);
      }
      return;
    }
    const activity = scanActivityFromSessionEvent(event, repository);
    if (activity !== null) {
      if (activity.kind === "reasoning") {
        const reasoning = (session.reasoning ??= createSessionReasoning(
          activity.id,
          activity.description,
        ));
        recordReasoningActivity(session, {
          ...activity,
          id: reasoning.id,
          description:
            reasoning.raw && reasoning.activity !== null
              ? reasoning.activity.description
              : activity.description,
        });
        return;
      }
      session.reasoning = null;
      if (
        activity.kind === "message" &&
        session.prose.has(`${activity.kind}:${activity.description}`)
      ) {
        return;
      }
      if (activity.kind === "message") {
        session.prose.add(`${activity.kind}:${activity.description}`);
      }
      if (activity.status === "running") {
        session.calls.set(activity.id, activity);
      }
      session.activities.push(activity);
      return;
    }
    if (
      (payload["type"] === "function_call_output" ||
        payload["type"] === "custom_tool_call_output") &&
      typeof payload["call_id"] === "string"
    ) {
      const call = session.calls.get(payload["call_id"]);
      if (call !== undefined) {
        session.activities.push({
          ...call,
          status: payload["status"] === "failed" ? "failed" : "completed",
        });
        session.calls.delete(call.id);
      }
    }
    return;
  }
  if (
    session.threadId === progressThread &&
    event["type"] === "event_msg" &&
    payload["type"] === "item_completed"
  ) {
    const item = nativeProgressItem(payload["item"]);
    const value = payload["item"];
    const duplicateCompletion =
      item?.kind === "message" &&
      repeatedMessageProjection(session, item.outputDigest, "native");
    let completion: SessionCompletion | undefined;
    if (
      isRecord(value) &&
      (value["type"] === "CommandExecution" ||
        value["type"] === "AgentMessage") &&
      !duplicateCompletion
    ) {
      const signature =
        item === null
          ? null
          : {
              kind: item.kind,
              outputDigest: item.outputDigest,
              persistedOutputDigest: item.persistedOutputDigest,
              ...(item.commandDigest === undefined
                ? {}
                : { commandDigest: item.commandDigest }),
            };
      completion = {
        position,
        item: signature,
        kind: item?.kind,
      };
      session.completions.push(completion);
    }
    if (item !== null) {
      const duplicate =
        item.kind === "message" &&
        repeatedMessageProjection(
          session,
          item.outputDigest,
          "native",
          item.updates,
        );
      for (const [markerIndex, update] of item.updates.entries()) {
        const saved = {
          update,
          position,
          completion: true,
          markerIndex,
          receipt: false,
          duplicate,
        };
        session.progress.push(saved);
        if (completion !== undefined && item.kind === "command")
          completion.lastCommandProgress = saved;
      }
    }
  }
  if (
    event["type"] === "event_msg" &&
    (payload["type"] === "agent_reasoning" ||
      payload["type"] === "agent_reasoning_delta" ||
      payload["type"] === "agent_reasoning_raw_content" ||
      payload["type"] === "agent_reasoning_raw_content_delta" ||
      payload["type"] === "agent_message")
  ) {
    if (
      payload["type"] === "agent_message" &&
      typeof payload["message"] === "string"
    ) {
      const updates = scanProgressUpdatesFromText(payload["message"]);
      const duplicate = repeatedMessageProjection(
        session,
        digest(payload["message"]),
        "event",
        updates,
      );
      // Legacy rollouts persist the finalized message instead of the native
      // item. It provides the same compact output signature for live matching.
      if (
        session.threadId === progressThread &&
        !repeatedMessageProjection(session, digest(payload["message"]), "event")
      )
        session.completions.push({
          position,
          item: progressSignature("message", payload["message"]),
        });
      for (const [markerIndex, update] of (duplicate
        ? []
        : updates
      ).entries()) {
        session.progress.push({
          update,
          position,
          completion: false,
          markerIndex,
          receipt: false,
          duplicate: false,
        });
      }
    }
    if (repository === undefined) return;
    if (payload["type"] !== "agent_message") {
      readSessionReasoning(event, payload, session, repository);
      return;
    }
    session.reasoning = null;
    const activity = scanActivityFromSessionEvent(event, repository);
    if (
      activity !== null &&
      !session.prose.has(`${activity.kind}:${activity.description}`)
    ) {
      session.prose.add(`${activity.kind}:${activity.description}`);
      session.activities.push(activity);
    }
    return;
  }
  if (
    event["type"] !== "event_msg" ||
    payload["type"] !== "token_count" ||
    !isRecord(payload["info"])
  ) {
    return;
  }
  const usage = tokenUsage(payload["info"]["total_token_usage"]);
  if (usage === null) return;
  const ownUsage =
    session.inheritedUsage === null
      ? usage
      : subtractTokenUsage(usage, session.inheritedUsage);
  // Older runtimes only emit token_count. In newer rollouts these snapshots can
  // lag compaction receipts, so do not replace a more complete native total.
  if (
    ownUsage !== null &&
    (session.usage === null ||
      ownUsage.total_tokens > session.usage.total_tokens ||
      (session.responseUsage === null &&
        ownUsage.total_tokens === session.usage.total_tokens))
  ) {
    session.usage = ownUsage;
  }
}

function readSessionReasoning(
  event: Readonly<Record<string, unknown>>,
  payload: Readonly<Record<string, unknown>>,
  session: SessionUsage,
  repository: string,
): void {
  const type = payload["type"];
  const raw =
    type === "agent_reasoning_raw_content" ||
    type === "agent_reasoning_raw_content_delta";
  const delta =
    type === "agent_reasoning_delta" ||
    type === "agent_reasoning_raw_content_delta";
  const text = payload[delta ? "delta" : "text"];
  if (typeof text !== "string") return;

  if (
    !delta &&
    !raw &&
    session.reasoning?.raw !== true &&
    session.reasoning?.activity?.status === "completed" &&
    session.reasoning.text !== text
  ) {
    session.reasoning = null;
  }
  const reasoning = (session.reasoning ??= createSessionReasoning(
    `reasoning-${++session.reasoningCount}`,
  ));
  if (reasoning.raw && !raw) return;
  if (raw && !reasoning.raw) {
    reasoning.text = "";
    reasoning.raw = true;
  }
  reasoning.text = delta ? `${reasoning.text}${text}` : text;

  const activity = scanActivityFromSessionEvent(
    {
      ...event,
      payload: {
        ...payload,
        [delta ? "delta" : "text"]: reasoning.text,
      },
    },
    repository,
  );
  if (activity === null) return;
  recordReasoningActivity(session, { ...activity, id: reasoning.id });
}

function recordReasoningActivity(
  session: SessionUsage,
  activity: ScanActivity,
): void {
  const reasoning = session.reasoning!;
  if (
    reasoning.activity?.description === activity.description &&
    reasoning.activity.status === activity.status
  ) {
    return;
  }
  reasoning.activity = activity;
  session.prose.add(`${activity.kind}:${activity.description}`);
  session.activities.push(activity);
}

const PERSISTED_OUTPUT_GAP =
  "\n... command output truncated for persistence ...\n";

// Native Codex 0.162.1 persists command output with a 64 KiB UTF-8 budget.
// This signature mirrors that representation; emitted diagnostics stay intact.
const PERSISTED_COMMAND_OUTPUT_BYTES = 64 * 1024;
const PERSISTED_OUTPUT_GAP_BYTES = Buffer.byteLength(PERSISTED_OUTPUT_GAP);
const PERSISTED_COMMAND_PREFIX_BYTES = Math.floor(
  (PERSISTED_COMMAND_OUTPUT_BYTES - PERSISTED_OUTPUT_GAP_BYTES) / 2,
);
const PERSISTED_COMMAND_SUFFIX_BYTES =
  PERSISTED_COMMAND_OUTPUT_BYTES -
  PERSISTED_OUTPUT_GAP_BYTES -
  PERSISTED_COMMAND_PREFIX_BYTES;

function digest(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

function persistedOutputDigest(text: string, fullDigest: string): string {
  if (Buffer.byteLength(text) <= PERSISTED_COMMAND_OUTPUT_BYTES)
    return fullDigest;
  const bytes = Buffer.from(text);
  let prefixEnd = PERSISTED_COMMAND_PREFIX_BYTES;
  let suffixStart = bytes.length - PERSISTED_COMMAND_SUFFIX_BYTES;
  while ((bytes[prefixEnd]! & 0xc0) === 0x80) prefixEnd--;
  while ((bytes[suffixStart]! & 0xc0) === 0x80) suffixStart++;
  return createHash("sha256")
    .update(bytes.subarray(0, prefixEnd))
    .update(PERSISTED_OUTPUT_GAP)
    .update(bytes.subarray(suffixStart))
    .digest("hex");
}

function progressSignature(
  kind: ProgressItem["kind"],
  text: string,
  command?: readonly string[],
): ProgressItem {
  const outputDigest = digest(text);
  return {
    kind,
    outputDigest,
    persistedOutputDigest:
      kind === "command"
        ? persistedOutputDigest(text, outputDigest)
        : outputDigest,
    ...(command === undefined
      ? {}
      : { commandDigest: digest(JSON.stringify(command)) }),
  };
}

function repeatedMessageProjection(
  session: SessionUsage,
  textDigest: string,
  projection: "native" | "event" | "response",
  updates?: readonly ScanProgress[],
): boolean {
  if (updates?.length === 0) return false;
  // Completion matching counts every native/legacy message, even without
  // progress. Keep those occurrences separate from parsed progress copies:
  // multipart responses can recover updates absent from their native copy.
  const key =
    updates === undefined
      ? textDigest
      : `${textDigest}:${digest(JSON.stringify(updates))}`;
  if (updates !== undefined) {
    let queue = session.messageProgressProjections.get(key);
    if (queue === undefined) {
      queue = { occurrences: [], next: { native: 0, event: 0, response: 0 } };
      session.messageProgressProjections.set(key, queue);
    }
    // Copies retain their order within each projection. A missing earlier copy
    // cannot consume an identical message after that projection has advanced.
    // These ordinals identify progress copies only, never completion positions.
    while (queue.next[projection] < queue.occurrences.length) {
      const order = queue.occurrences[queue.next[projection]++]!;
      if (order <= session.messageProgressFrontiers[projection]) continue;
      session.messageProgressFrontiers[projection] = order;
      return true;
    }
    const order = ++session.messageProgressOrder;
    queue.occurrences.push(order);
    queue.next[projection] = queue.occurrences.length;
    session.messageProgressFrontiers[projection] = order;
    return false;
  }
  let counts = session.messageProjections.get(key);
  if (counts === undefined) {
    counts = { native: 0, event: 0, response: 0 };
    session.messageProjections.set(key, counts);
  }
  const previous = Math.max(counts.native, counts.event, counts.response);
  counts[projection]++;
  return counts[projection] <= previous;
}

function progressKey(progress: ScanProgress): string {
  return `${progress.phase}:${progress.filesCompleted}:${progress.filesTotal}`;
}

function streamedProgressItem(
  event: Readonly<Record<string, unknown>>,
): ProgressItem | null {
  const item = event["item"];
  if (!isRecord(item)) return null;
  if (item["type"] === "agent_message" && typeof item["text"] === "string")
    return progressSignature("message", item["text"]);
  if (
    item["type"] !== "command_execution" ||
    typeof item["aggregated_output"] !== "string" ||
    typeof item["command"] !== "string"
  )
    return null;
  const command = splitCommand(item["command"]);
  return command === null
    ? null
    : progressSignature("command", item["aggregated_output"], command);
}

function nativeProgressItem(value: unknown): NativeProgressItem | null {
  if (!isRecord(value)) return null;
  let kind: ProgressItem["kind"];
  let text: string;
  let command: string[] | undefined;
  if (value["type"] === "AgentMessage" && Array.isArray(value["content"])) {
    kind = "message";
    text = value["content"]
      .filter(
        (part): part is { text: string } =>
          isRecord(part) &&
          part["type"] === "Text" &&
          typeof part["text"] === "string",
      )
      .map((part) => part.text)
      .join("");
  } else if (
    value["type"] === "CommandExecution" &&
    typeof value["aggregated_output"] === "string" &&
    Array.isArray(value["command"]) &&
    value["command"].every((arg): arg is string => typeof arg === "string")
  ) {
    kind = "command";
    text = value["aggregated_output"];
    command = value["command"];
  } else return null;
  let progressText = text;
  if (kind === "command") {
    const bytes = Buffer.from(text);
    // Native UTF-8 boundary adjustment can shorten each fragment by up to
    // three bytes. An earlier literal sentinel is ordinary command output.
    const gap = bytes.indexOf(
      PERSISTED_OUTPUT_GAP,
      PERSISTED_COMMAND_PREFIX_BYTES - 3,
    );
    const suffixBytes = bytes.length - gap - PERSISTED_OUTPUT_GAP_BYTES;
    if (
      gap !== -1 &&
      gap <= PERSISTED_COMMAND_PREFIX_BYTES &&
      suffixBytes >= PERSISTED_COMMAND_SUFFIX_BYTES - 3 &&
      suffixBytes <= PERSISTED_COMMAND_SUFFIX_BYTES
    ) {
      // Complete original prefix lines have known fence state. The gap inserts
      // its own newline, so the partial prefix line and tail remain unproven.
      // Literal text at these exact boundaries is indistinguishable on disk.
      const prefix = bytes.subarray(0, gap).toString("utf8");
      progressText = prefix.slice(0, prefix.lastIndexOf("\n") + 1);
    }
  }
  return {
    ...progressSignature(kind, text, command),
    updates: scanProgressUpdatesFromText(progressText),
  };
}

function progressItemKey(item: ProgressItem, persisted = false): string {
  return `${item.kind}:${item.commandDigest ?? ""}:${persisted ? item.persistedOutputDigest : item.outputDigest}`;
}

function progressItemKeys(item: ProgressItem): string[] {
  const keys = [progressItemKey(item)];
  if (item.outputDigest !== item.persistedOutputDigest)
    keys.push(progressItemKey(item, true));
  return keys;
}

// Min-heap keeps compatible live occurrences ordered without rescanning the
// unmatched prefix or sorting every completion batch.
function insertIndex(heap: number[], index: number): void {
  let child = heap.length;
  heap.push(index);
  while (child > 0) {
    const parent = (child - 1) >>> 1;
    if (heap[parent]! <= index) break;
    heap[child] = heap[parent]!;
    child = parent;
  }
  heap[child] = index;
}

function takeFirstIndex(heap: number[]): number {
  const first = heap[0]!;
  const last = heap.pop()!;
  if (heap.length === 0) return first;
  let parent = 0;
  while (parent * 2 + 1 < heap.length) {
    let child = parent * 2 + 1;
    if (child + 1 < heap.length && heap[child + 1]! < heap[child]!) child++;
    if (last <= heap[child]!) break;
    heap[parent] = heap[child]!;
    parent = child;
  }
  heap[parent] = last;
  return first;
}

/** Decode the quoted argv rendering emitted by native command completions. */
function splitCommand(command: string): string[] | null {
  const words: string[] = [];
  let word = "";
  let started = false;
  let quote: "'" | '"' | null = null;
  for (let index = 0; index < command.length; index++) {
    const character = command[index]!;
    if (character === "\\" && quote !== "'") {
      const next = command[++index];
      if (next === undefined) return null;
      if (quote === '"' && !["$", "`", '"', "\\", "\n"].includes(next))
        word += "\\";
      if (next !== "\n") word += next;
      started = true;
    } else if (quote !== null) {
      if (character === quote) quote = null;
      else word += character;
    } else if (character === "'" || character === '"') {
      quote = character;
      started = true;
    } else if (" \t\r\n".includes(character)) {
      if (started) words.push(word);
      word = "";
      started = false;
    } else {
      word += character;
      started = true;
    }
  }
  if (quote !== null) return null;
  if (started) words.push(word);
  return words;
}

function sessionProgressUpdates(
  payload: Readonly<Record<string, unknown>>,
): ScanProgress[] {
  if (payload["type"] === "message" && payload["role"] === "assistant") {
    return scanProgressUpdatesFromText(sessionContentText(payload["content"]));
  }
  if (
    payload["type"] !== "function_call_output" &&
    payload["type"] !== "custom_tool_call_output" &&
    payload["type"] !== "local_shell_call_output"
  ) {
    return [];
  }
  const value = payload["output"];
  const output =
    typeof value === "string"
      ? value
      : sessionContentText(value, ["output_text", "input_text"]);
  if (payload["status"] === "failed") {
    return [];
  }
  return scanProgressUpdatesFromText(output);
}

function addTokenUsage(
  previous: ScanTokenUsage | null,
  next: ScanTokenUsage,
): ScanTokenUsage {
  if (previous === null) return next;
  return {
    input_tokens: previous.input_tokens + next.input_tokens,
    cached_input_tokens:
      previous.cached_input_tokens + next.cached_input_tokens,
    cache_write_input_tokens:
      previous.cache_write_input_tokens + next.cache_write_input_tokens,
    ...(previous.cache_write_input_tokens_reported === false ||
    next.cache_write_input_tokens_reported === false
      ? { cache_write_input_tokens_reported: false }
      : {}),
    output_tokens: previous.output_tokens + next.output_tokens,
    reasoning_output_tokens:
      previous.reasoning_output_tokens + next.reasoning_output_tokens,
    total_tokens: previous.total_tokens + next.total_tokens,
  };
}

function subtractTokenUsage(
  usage: ScanTokenUsage,
  inherited: ScanTokenUsage,
): ScanTokenUsage | null {
  return tokenUsage({
    input_tokens: usage.input_tokens - inherited.input_tokens,
    cached_input_tokens:
      usage.cached_input_tokens - inherited.cached_input_tokens,
    cache_write_input_tokens:
      usage.cache_write_input_tokens - inherited.cache_write_input_tokens,
    ...(usage.cache_write_input_tokens_reported === false ||
    inherited.cache_write_input_tokens_reported === false
      ? { cache_write_input_tokens_reported: false }
      : {}),
    output_tokens: usage.output_tokens - inherited.output_tokens,
    reasoning_output_tokens:
      usage.reasoning_output_tokens - inherited.reasoning_output_tokens,
  });
}

function isMissingFile(error: unknown): boolean {
  return isRecord(error) && error["code"] === "ENOENT";
}
