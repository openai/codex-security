"""Project saved worker coverage and reconcile its published parent copies."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _normalize_unsealed_open_questions,
    _read_json,
    _require_portable_relative_path,
    _validate_resolved_deferred,
    _validate_schema_node,
)


def _has_candidate_metadata(row: dict[str, Any]) -> bool:
    return any(key in row for key in ("candidateId", "candidate", "finding"))


def _coverage_rows(coverage: dict[str, Any], field: str) -> list[Any]:
    rows = coverage.get(field, [])
    return rows if isinstance(rows, list) else []


def _inherit_coverage_sources(
    row: Any,
    originals: list[Any],
    sources: dict[int, tuple[dict[str, Any], list[str]]],
) -> None:
    if not isinstance(row, dict):
        return
    for original in originals:
        saved = sources.get(id(original))
        if saved is None:
            continue
        # Retain the object as well as its ID while copies are reconciled.
        paths = sources.setdefault(id(row), (row, []))[1]
        for relative in saved[1]:
            if relative not in paths:
                paths.append(relative)


def _saved_coverage_id(item: dict[str, Any]) -> str:
    if candidate_id := item.get("candidateId"):
        return candidate_id
    payload = json.dumps(
        item, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return f"saved-{hashlib.sha256(payload).hexdigest()[:16]}"


def _project_worker_coverage_row(item: Any, worker_id: str | None, field: str) -> Any:
    row = copy.deepcopy(item)
    if worker_id is None or not isinstance(row, dict):
        return row
    row["workerId"] = worker_id
    if field == "openQuestions":
        return row
    # Reconcile raw checkpoint identities first. Anonymous output rows use the
    # existing content identity, never their position in an earlier snapshot.
    row.setdefault("id", _saved_coverage_id(row))
    if isinstance(row.get("id"), str):
        row["id"] = f"{worker_id}/{row['id']}"
    if field == "deferred" and isinstance(row.get("surfaceIds"), list):
        row["surfaceIds"] = [
            f"{worker_id}/{identity}" if isinstance(identity, str) else identity
            for identity in row["surfaceIds"]
        ]
    return row


def _coverage_comparison_row(row: Any, field: str) -> Any:
    if field == "surfaces" and isinstance(row, dict):
        row = {"receiptRefs": [], **row}
        if isinstance(row["receiptRefs"], list):
            refs = []
            for ref in row["receiptRefs"]:
                if isinstance(ref, str):
                    try:
                        ref = _require_portable_relative_path(ref, "Saved coverage receipt")
                    except ContractError:
                        pass  # Leave malformed refs to the existing per-record recovery.
                refs.append(ref)
            row["receiptRefs"] = refs
        return row
    if field == "openQuestions":
        coverage = {"openQuestions": [copy.deepcopy(row)]}
        _normalize_unsealed_open_questions(coverage)
        return next(iter(coverage["openQuestions"]), row)
    return row


def _aggregate_worker_coverage_rows(rows: list[Any], worker_id: str, field: str) -> list[Any]:
    """Match accepted aggregate IDs without changing raw recovery identities."""
    reserved = {
        row["id"] for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    emitted: set[str] = set()
    projected = []
    for index, original in enumerate(rows):
        row = copy.deepcopy(original)
        if isinstance(row, dict) and field != "openQuestions":
            generated = not isinstance(row.get("id"), str)
            identity = str(index) if generated else row["id"]
            base = identity
            if generated or identity in emitted:
                suffix = 2
                while identity in reserved:
                    identity = f"{base}-{suffix}"
                    suffix += 1
            reserved.add(identity)
            emitted.add(identity)
            row["id"] = identity
        projected.append(
            _coverage_comparison_row(_project_worker_coverage_row(row, worker_id, field), field)
        )
    return projected


def _prepare_worker_coverage_recovery(
    sources: list[tuple[str, dict[str, Any], str | None]],
    parent: dict[str, Any] | None,
    source_order: dict[str, tuple[int, int]],
    *,
    enabled: bool,
    receipt_resolver=None,
) -> tuple[
    bool, list[tuple[dict[str, Any], str, dict[str, Any], dict[str, Any], dict[str, Any] | None]]
]:
    """Put bound worker evidence in parent coordinates without changing source files."""
    workers = {owner for _, _, owner in sources if owner is not None}
    parents = [
        draft
        for _, draft, owner in sorted(
            sources, key=lambda source: source_order[source[0]], reverse=True
        )
        if owner is None
    ]
    if parent is not None:
        # Prefer the selected parent over historical copies of a task's surface.
        parents.insert(0, parent)
    fields = ("surfaces", "explicitExclusions", "deferred", "openQuestions")
    if not enabled:
        enabled = any(
            isinstance(row, dict)
            and isinstance(row.get("workerId"), str)
            and row["workerId"] in workers
            and (
                field == "openQuestions"
                or (isinstance(row.get("id"), str) and row["id"].startswith(f"{row['workerId']}/"))
            )
            for draft in parents
            for field in fields
            for row in (
                draft["coverage"].get(field, [])
                if isinstance(draft["coverage"].get(field, []), list)
                else []
            )
        )
    if not enabled:
        return False, []
    projected: dict[str, list[Any]] = {field: [] for field in fields}
    surface_sources: list[tuple[dict[str, Any], dict[str, Any]]] = []
    task_sources: list[tuple[dict[str, Any], dict[str, Any]]] = []
    surface_links: list[
        tuple[dict[str, Any], str, dict[str, Any], dict[str, Any], dict[str, Any] | None]
    ] = []
    for relative, draft, owner in sources:
        if owner is None:
            continue
        directory = Path(relative).parent
        if directory.name == "checkpoints":
            directory = directory.parent
        for field in fields:
            rows = draft["coverage"].get(field, [])
            if not isinstance(rows, list):
                continue
            for index, row in enumerate(rows):
                if field == "openQuestions" and isinstance(row, str):
                    row = {"question": row}
                    rows[index] = row
                if not isinstance(row, dict):
                    continue
                row["workerId"] = owner
                if field == "surfaces" and receipt_resolver is not None:
                    row["receiptRefs"] = receipt_resolver(relative, row, owner)
                elif field == "surfaces" and isinstance(row.get("receiptRefs"), list):
                    refs = []
                    for ref in row["receiptRefs"]:
                        if isinstance(ref, str):
                            try:
                                normalized = _require_portable_relative_path(
                                    ref, "Worker coverage receipt"
                                )
                            except ContractError:
                                pass  # Leave malformed refs to the existing per-record recovery.
                            else:
                                if normalized.startswith("artifacts/"):
                                    ref = f"{directory.as_posix()}/{normalized}"
                        refs.append(ref)
                    row["receiptRefs"] = refs
                if field == "surfaces":
                    row.setdefault("receiptRefs", [])
            aggregate_rows = _aggregate_worker_coverage_rows(rows, owner, field)
            projected[field].extend(aggregate_rows)
            if field in {"surfaces", "deferred"}:
                originals = surface_sources if field == "surfaces" else task_sources
                originals.extend(
                    (aggregate, row)
                    for aggregate, row in zip(aggregate_rows, rows)
                    if isinstance(aggregate, dict) and isinstance(row, dict)
                )
    # A canonical aggregate contains copies of the same worker evidence. Let
    # the existing per-worker chronology reconcile those originals exactly once.
    # Keep parent-only evidence when its bound worker source is unavailable.
    for draft in parents:
        if not draft["coverage"]:
            continue
        for field in fields:
            rows = draft["coverage"].get(field, [])
            if isinstance(rows, list):
                if field == "surfaces":
                    tasks = draft["coverage"].get("deferred", [])
                    for row in rows:
                        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                            continue
                        matching_sources = [
                            original
                            for aggregate, original in surface_sources
                            if aggregate == _coverage_comparison_row(row, field)
                        ]
                        if not matching_sources:
                            continue
                        for task in tasks if isinstance(tasks, list) else []:
                            if (
                                isinstance(task, dict)
                                and isinstance(task.get("surfaceIds"), list)
                                and row["id"] in task["surfaceIds"]
                            ):
                                surface_links.extend(
                                    (
                                        task,
                                        row["id"],
                                        source,
                                        row,
                                        next(
                                            (
                                                original
                                                for aggregate, original in task_sources
                                                if aggregate == task
                                            ),
                                            None,
                                        ),
                                    )
                                    for source in matching_sources
                                )
                draft["coverage"][field] = [
                    row
                    for row in rows
                    if _coverage_comparison_row(row, field) not in projected[field]
                ]
    return True, surface_links


class SavedCoverageProjection:
    """Keep worker source links stable while legacy and accepted rows converge."""

    def __init__(self, project_worker_coverage, legacy_surface_links, sources):
        self.project_worker_coverage = project_worker_coverage
        self.legacy_surface_links = legacy_surface_links
        self.legacy_source_outputs: dict[int, dict[str, Any]] = {}
        self.worker_row_owners: dict[int, str] = {}
        self.worker_surface_outputs: dict[tuple[str, str], dict[int, dict[str, Any]]] = {}
        self.source_owner_by_id = {
            id(row): owner
            for _, draft, owner in sources
            for field in ("surfaces", "deferred")
            for rows in (draft["coverage"].get(field, []),)
            if isinstance(rows, list)
            for row in rows
            if isinstance(row, dict)
        }

    def record_coverage_owner(self, retained, original, owner, field):
        if self.project_worker_coverage and owner is not None and isinstance(retained, dict):
            self.worker_row_owners[id(retained)] = owner
            if field == "surfaces" and isinstance(original.get("id"), str):
                self.worker_surface_outputs.setdefault((owner, original["id"]), {})[
                    id(retained)
                ] = retained

    def retain_coverage_row(self, output, item, owner, field, original=None, qualified=False):
        retained = (
            copy.deepcopy(item)
            if qualified or not self.project_worker_coverage
            else _project_worker_coverage_row(item, owner, field)
        )
        if retained not in output:
            output.append(retained)
        retained = output[output.index(retained)]
        if isinstance(retained, dict) and original is not None:
            self.legacy_source_outputs[id(original)] = retained
        self.record_coverage_owner(
            retained, original if original is not None else item, owner, field
        )
        return retained

    def retained_record(self, coverage, field, item, canonical_record):
        item = canonical_record(field, item)
        if field == "surfaces":
            # Canonical IDs can change while source content and ownership stay the same.
            item = {key: value for key, value in item.items() if key != "id"}
        records = coverage.get(field, [])
        for record in records if isinstance(records, list) else []:
            if not isinstance(record, dict):
                continue
            original = dict(canonical_record(field, record))
            if "id" not in item:
                original.pop("id", None)  # Canonical publication can assign an ID.
            if field == "openQuestions":
                # Compare the same canonical form that publication writes.
                previous_question = {"openQuestions": [original]}
                source_question = {"openQuestions": [item]}
                _normalize_unsealed_open_questions(previous_question)
                _normalize_unsealed_open_questions(source_question)
                if previous_question == source_question:
                    return record
            elif original == item:
                return record
        return None

    def linked_surface(self, surface, outputs, named_outputs):
        retained = outputs.get(id(surface))
        owner = self.source_owner_by_id.get(id(surface), surface.get("workerId"))
        if retained is None and isinstance(owner, str) and isinstance(surface.get("id"), str):
            matches = named_outputs.get((owner, surface["id"]), {})
            if len(matches) == 1:
                retained = next(iter(matches.values()))
        return retained

    def is_reviewed_worker(self, canonical, worker):
        if (
            worker is None
            or not {"status", "merge_state", "attempt"}.issubset(worker.keys())
            or worker["status"] != "succeeded"
            or worker["merge_state"] != "merged"
        ):
            return False
        reviews = canonical.get("reviews", [])
        return any(
            isinstance(review, dict)
            and review.get("workerId") == worker["id"]
            and review.get("attempt") == worker["attempt"]
            for review in (reviews if isinstance(reviews, list) else [])
        )

    def repair_reviewed_surface(self, coverage, canonical, worker, source, surface):
        if not self.is_reviewed_worker(canonical, worker):
            return None
        published = next(
            (
                row
                for row in canonical.get("surfaces", [])
                if isinstance(row, dict)
                and isinstance(provenance := row.get("provenance"), dict)
                and provenance.get("workerId") == worker["id"]
                and provenance.get("attempt") == worker["attempt"]
                and provenance.get("sourceId") == surface.get("id")
                and row.get("disposition") == surface.get("disposition")
            ),
            None,
        )
        if published is None:
            return None
        retained = next(
            (
                row
                for row in coverage["surfaces"]
                if row.get("id") == published.get("id")
                and row.get("provenance") == published.get("provenance")
            ),
            None,
        )
        if retained is None:
            retained = copy.deepcopy(published)
        # Receipt repair can recover earlier evidence without replacing the
        # accepted surface's identity, disposition, or host-owned provenance.
        retained["receiptRefs"] = surface["receiptRefs"]
        return self.retain_coverage_row(
            coverage["surfaces"], retained, worker["id"], "surfaces", source, True
        )

    def linked_tasks(self, task, published_id, source_task, candidates):
        expected = None
        if source_task is not None:
            expected = self.legacy_source_outputs.get(id(source_task))
            if expected is None:
                expected = _project_worker_coverage_row(
                    source_task, self.source_owner_by_id.get(id(source_task)), "deferred"
                )
        return [
            retained
            for owner, retained in candidates
            if retained == task
            or (
                expected is not None
                and (
                    retained is expected
                    or (
                        owner == self.source_owner_by_id.get(id(source_task))
                        and isinstance(retained, dict)
                        and retained.get("id") == expected.get("id")
                        and isinstance(retained.get("surfaceIds"), list)
                        and published_id in retained["surfaceIds"]
                    )
                )
            )
        ]

    def finalize(
        self,
        coverage,
        canonical_rows,
        digest,
        *,
        preserve_canonical_parent,
        all_sources,
        source_order,
        coverage_sources,
        surface_ids_by_source,
        retained_surface_rows,
        resolved,
    ):

        source_owners = {relative: owner for relative, _, owner in all_sources}
        recovered_worker_ids = {
            worker_id for _, _, worker_id in all_sources if worker_id is not None
        }
        surface_positions: dict[str, int] = {}
        resolved_surface_targets: dict[tuple[str | None, str], list[str]] = {}

        def remember_surface_id(item: dict[str, Any], local_id: str) -> None:
            final_id = item["id"]
            surface_positions.setdefault(final_id, len(surface_positions))
            shadowed_alias = (
                self.project_worker_coverage
                and id(item) not in named_surface_outputs
                and (named := worker_surfaces.get((self.worker_row_owners.get(id(item)), local_id)))
                is not None
                and id(named) in named_surface_outputs
            )
            for relative in coverage_sources.get(id(item), (item, []))[1]:
                # A candidate-derived ID cannot claim a link explicitly naming another surface.
                if not shadowed_alias:
                    targets = surface_ids_by_source.setdefault((relative, local_id), [])
                    if final_id not in targets:
                        targets.append(final_id)
                candidate_id = item.get("candidateId")
                if isinstance(candidate_id, str):
                    key = (source_owners[relative], candidate_id)
                    if key in resolved and resolved[key] == item.get("disposition"):
                        targets = resolved_surface_targets.setdefault(key, [])
                        if final_id not in targets:
                            targets.append(final_id)

        retained_legacy_surface_links: dict[
            int, tuple[dict[str, Any], dict[str, dict[str, Any]]]
        ] = {}
        output_tasks = coverage.get("deferred", [])
        task_candidates = [
            (self.worker_row_owners.get(id(row)), row)
            for row in (output_tasks if isinstance(output_tasks, list) else [])
        ]
        for task, published_id, surface, _, task_source in self.legacy_surface_links:
            retained_surface = self.linked_surface(
                surface, self.legacy_source_outputs, self.worker_surface_outputs
            )
            if retained_surface is None or not isinstance(retained_surface.get("id"), str):
                continue
            for retained_task in self.linked_tasks(
                task, published_id, task_source, task_candidates
            ):
                _, links = retained_legacy_surface_links.setdefault(
                    id(retained_task), (retained_task, {})
                )
                links.setdefault(published_id, retained_surface)
        # A newer worker checkpoint may omit a surface still needed by a retained
        # task. Restore its parent copy only when no worker replacement survived.
        for task, published_id, surface, parent_surface, task_source in self.legacy_surface_links:
            for retained_task in self.linked_tasks(
                task, published_id, task_source, task_candidates
            ):
                _, links = retained_legacy_surface_links.setdefault(
                    id(retained_task), (retained_task, {})
                )
                if published_id not in links and isinstance(coverage.get("surfaces"), list):
                    retained_surface = self.retain_coverage_row(
                        coverage["surfaces"], parent_surface, None, "surfaces"
                    )
                    self.record_coverage_owner(
                        retained_surface,
                        surface,
                        self.source_owner_by_id.get(id(surface), surface.get("workerId")),
                        "surfaces",
                    )
                    _inherit_coverage_sources(retained_surface, [parent_surface], coverage_sources)
                    links[published_id] = retained_surface
        if self.project_worker_coverage:
            worker_surfaces: dict[tuple[str, str], dict[str, Any]] = {}
            named_surface_outputs = {
                identity for outputs in self.worker_surface_outputs.values() for identity in outputs
            }
            surfaces = coverage.get("surfaces", [])
            for surface in surfaces if isinstance(surfaces, list) else []:
                if not isinstance(surface, dict):
                    continue
                owner, identity = self.worker_row_owners.get(id(surface)), surface.get("id")
                if isinstance(owner, str) and isinstance(identity, str):
                    key = (owner, identity)
                    existing = worker_surfaces.get(key)
                    # An anonymous candidate ID can collide with an explicit surface ID.
                    # Bind a named worker link to the explicitly named source.
                    if existing is None or (
                        id(surface) in named_surface_outputs
                        and id(existing) not in named_surface_outputs
                    ):
                        worker_surfaces[key] = surface
            for task in output_tasks if isinstance(output_tasks, list) else []:
                if (
                    not isinstance(task, dict)
                    or (owner := self.worker_row_owners.get(id(task))) is None
                    or not isinstance(task.get("surfaceIds"), list)
                ):
                    continue
                for identity in task["surfaceIds"]:
                    if (
                        isinstance(identity, str)
                        and (surface := worker_surfaces.get((owner, identity))) is not None
                    ):
                        _, links = retained_legacy_surface_links.setdefault(id(task), (task, {}))
                        links.setdefault(identity, surface)
        for field in ("surfaces", "explicitExclusions", "deferred"):
            used: set[str] = set()
            items = coverage.setdefault(field, [])
            reserved = {
                row["id"]
                for row in (items if isinstance(items, list) else [])
                if isinstance(row, dict) and isinstance(row.get("id"), str)
            }
            normalized_items = []
            for item in items if isinstance(items, list) else []:
                normalized_items.append(item)
                if not isinstance(item, dict):
                    continue
                if id(item) in canonical_rows:
                    if isinstance(item.get("id"), str):
                        used.add(item["id"])
                        if field == "surfaces":
                            remember_surface_id(item, item["id"])
                    continue
                item.setdefault("id", _saved_coverage_id(item))
                if not isinstance(item["id"], str):
                    # Preserve malformed rows for per-record recovery, including frozen replay.
                    continue
                local_id = item["id"]
                scoped = (
                    preserve_canonical_parent
                    and isinstance(worker_id := item.get("workerId"), str)
                    and worker_id in recovered_worker_ids
                )
                if scoped:
                    # Resolve worker-local candidate/deferred history before scoping IDs.
                    item["id"] = f"{worker_id}/{item['id']}"
                if isinstance(item.get("surfaceIds"), list):
                    links: list[Any] = []
                    for surface_id in item["surfaceIds"]:
                        targets: list[str] = []
                        declared = False
                        if field == "deferred" and isinstance(surface_id, str):
                            for relative in coverage_sources.get(id(item), (item, []))[1]:
                                source_key = (relative, surface_id)
                                history_keys = [source_key]
                                if source_key not in surface_ids_by_source:
                                    # A deferred-only checkpoint can refer to an earlier
                                    # observation from this logical worker, including retries.
                                    # Reused IDs can denote several retained observations.
                                    history_keys = [
                                        (historical, surface_id)
                                        for historical, _, owner in all_sources
                                        if owner == source_owners[relative]
                                        and source_order[historical] <= source_order[relative]
                                    ]
                                for key in history_keys:
                                    declared |= key in surface_ids_by_source
                                    for target in surface_ids_by_source.get(key, []):
                                        if target not in targets:
                                            targets.append(target)
                        if targets:
                            targets.sort(key=surface_positions.__getitem__)
                            for target in targets:
                                if target not in links:
                                    links.append(target)
                        elif not declared:
                            links.append(
                                f"{worker_id}/{surface_id}"
                                if scoped and isinstance(surface_id, str)
                                else surface_id
                            )
                    item["surfaceIds"] = links
                if scoped:
                    if preserve_canonical_parent and item in normalized_items[:-1]:
                        # A previous finish may have published files before its DB commit.
                        if field == "surfaces":
                            remember_surface_id(item, local_id)
                        normalized_items.pop()
                        continue
                if item["id"] in used:
                    if self.project_worker_coverage:
                        base = item["id"]
                        suffix = 2
                        while item["id"] in used or item["id"] in reserved:
                            item["id"] = f"{base}-{suffix}"
                            suffix += 1
                    else:
                        item["id"] = f"{item['id']}-{digest(item)[:16]}"
                if preserve_canonical_parent and item in normalized_items[:-1]:
                    if field == "surfaces":
                        remember_surface_id(item, local_id)
                    normalized_items.pop()
                    continue
                used.add(item["id"])
                if field == "surfaces":
                    item.setdefault("receiptRefs", [])
                    remember_surface_id(item, local_id)
            if preserve_canonical_parent and isinstance(items, list):
                coverage[field] = normalized_items
            if field == "surfaces":
                # Candidate resolution replaces pending surfaces independently of generic
                # tasks. Preserve their original links, even when the outcome changes ID
                # or a distinct retained surface shares the old source-local ID.
                for relative, draft, owner in all_sources:
                    originals = draft["coverage"].get("surfaces", [])
                    for original in originals if isinstance(originals, list) else []:
                        if (
                            not isinstance(original, dict)
                            or id(original) in retained_surface_rows
                            or original.get("disposition") != "needs_follow_up"
                            or not isinstance(local_id := original.get("id"), str)
                            or not isinstance(candidate_id := original.get("candidateId"), str)
                        ):
                            continue
                        targets = surface_ids_by_source.setdefault((relative, local_id), [])
                        for target in resolved_surface_targets.get((owner, candidate_id), []):
                            if target not in targets:
                                targets.append(target)
        for task, links in retained_legacy_surface_links.values():
            task["surfaceIds"] = [
                links[identity]["id"]
                if isinstance(identity, str) and identity in links
                else identity
                for identity in task["surfaceIds"]
            ]

    def fallback_surfaces(
        self,
        coverage,
        all_sources,
        prospective_tasks,
        *,
        surface_is_retained,
        ambiguous_surface_ids,
    ):
        fallback_surfaces = []
        if self.legacy_surface_links and isinstance(coverage.get("surfaces"), list):
            # Plan the surviving associations before historical receipts can claim
            # a spelling needed by a surface that must be restored for its task.
            prospective_tasks = [
                (owner, _project_worker_coverage_row(row, owner, "deferred"))
                for owner, row in prospective_tasks
            ]
            prospective_surfaces = {}
            prospective_named = {}
            for relative, draft, owner in all_sources:
                rows = draft["coverage"].get("surfaces", [])
                for row in rows if isinstance(rows, list) else []:
                    if owner is None or not isinstance(row, dict):
                        continue
                    emitted = surface_is_retained(relative, owner, row)
                    ambiguous = (
                        isinstance(row.get("id"), str)
                        and (owner, row["id"]) in ambiguous_surface_ids
                        and row.get("disposition") == "needs_follow_up"
                        and not any(key in row for key in ("candidateId", "candidate", "finding"))
                    )
                    if not emitted and not ambiguous:
                        continue
                    projected = _project_worker_coverage_row(row, owner, "surfaces")
                    if isinstance(row.get("id"), str):
                        named = prospective_named.setdefault((owner, row["id"]), {})
                        projected = next(
                            (existing for existing in named.values() if existing == projected),
                            projected,
                        )
                        named[id(projected)] = projected
                    if emitted:
                        prospective_surfaces[id(row)] = projected
            bound = {
                (id(retained), published_id)
                for task, published_id, surface, _, task_source in self.legacy_surface_links
                if self.linked_surface(surface, prospective_surfaces, prospective_named) is not None
                for retained in self.linked_tasks(
                    task, published_id, task_source, prospective_tasks
                )
            }
            for task, published_id, _, parent_surface, task_source in self.legacy_surface_links:
                for retained in self.linked_tasks(
                    task, published_id, task_source, prospective_tasks
                ):
                    key = (id(retained), published_id)
                    if key not in bound:
                        fallback_surfaces.append(parent_surface)
                        bound.add(key)
        return fallback_surfaces


def prepare_saved_coverage_projection(
    sources,
    parent,
    source_order,
    *,
    project_worker_coverage,
    receipt_resolver,
    preserve_canonical_parent=False,
):
    if preserve_canonical_parent:
        return SavedCoverageProjection(False, [], sources)
    # Older parent publications use worker/id identities. Reconcile those copies
    # against their bound sources before projecting accepted attempt provenance.
    projected_metadata = {
        id(row): ("workerId" in row, row.get("workerId"))
        for relative, draft, _ in sources
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions")
        for rows in (draft["coverage"].get(field, []),)
        if isinstance(rows, list)
        for row in rows
        if isinstance(row, dict)
    }
    project_worker_coverage, legacy_surface_links = _prepare_worker_coverage_recovery(
        sources,
        parent,
        source_order,
        enabled=project_worker_coverage,
        receipt_resolver=receipt_resolver,
    )
    for _, draft, _ in sources:
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
            rows = draft["coverage"].get(field, [])
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                present, value = projected_metadata.get(id(row), (False, None))
                if present:
                    row["workerId"] = value
                else:
                    row.pop("workerId", None)
    return SavedCoverageProjection(project_worker_coverage, legacy_surface_links, sources)


def _deferred_rows(coverage: dict[str, Any]) -> list[Any]:
    rows = coverage.get("deferred", [])
    return rows if isinstance(rows, list) else []


def _resolved_deferred_rows(draft: dict[str, Any], schema: dict[str, Any]) -> list[dict[str, Any]]:
    if draft.get("complete") is False:
        return []
    coverage = draft["coverage"]
    rows = coverage.get("resolvedDeferred", [])
    try:
        # Invalid closure metadata cannot discard the evidence it names.
        _validate_schema_node(rows, schema, "coverage.resolvedDeferred")
        _validate_resolved_deferred({**coverage, "deferred": _deferred_rows(coverage)})
    except ContractError:
        return []
    return rows


def _project_worker_closure(
    relative: str,
    owner: str,
    closure: dict[str, Any],
    worker_attempts: dict[str, tuple[str, int]],
    source_order: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    directory = Path(relative).parent
    if directory.name == "checkpoints":
        directory = directory.parent
    _, attempt = worker_attempts.get(directory.as_posix(), (owner, source_order[relative][0]))
    return {
        "id": f"{owner}-attempt-{attempt}-resolved-{closure['id']}",
        "reason": closure["reason"],
    }


def _projected_worker_closure_sources(
    sources: list[tuple[str, dict[str, Any], str | None]],
    source_order: dict[str, tuple[int, int]],
    worker_attempts: dict[str, tuple[str, int]],
    schema: dict[str, Any],
) -> dict[tuple[str, str], tuple[str, dict[str, Any], str]]:
    projected: dict[tuple[str, str], tuple[str, dict[str, Any], str]] = {}
    for relative, draft, owner in sources:
        if owner is None:
            continue
        for closure in _resolved_deferred_rows(draft, schema):
            row = _project_worker_closure(relative, owner, closure, worker_attempts, source_order)
            # Both fields identify the full strict closeout row, including its reason.
            key = (row["id"], row["reason"])
            previous = projected.get(key)
            if previous is None or source_order[relative] > source_order[previous[2]]:
                projected[key] = (owner, closure, relative)
    return projected


def _parent_observation_content(parent: dict[str, Any]) -> dict[str, Any]:
    # Frozen recovery ancestry does not change the observed scan result.
    return {
        key: value
        for key, value in parent.items()
        if key not in {"previousParentCheckpoints", "canonicalParent"}
    }


def _merge_tied_parent_observations(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    merged = copy.deepcopy(current)
    for finding in previous["findings"]:
        if finding not in merged["findings"]:
            merged["findings"].append(copy.deepcopy(finding))
    coverage = merged["coverage"]
    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        rows = previous["coverage"].get(field, [])
        output = coverage.setdefault(field, [])
        if isinstance(rows, list) and isinstance(output, list):
            for row in rows:
                if row not in output:
                    output.append(copy.deepcopy(row))
    pending_ids = {
        identity
        for row in _deferred_rows(coverage)
        if isinstance(row, dict)
        for identity in (row.get("id"), row.get("candidateId"))
        if isinstance(identity, str)
    }
    closure_schema = _read_json(
        Path(__file__).resolve().parents[2] / "schemas" / "coverage.schema.json"
    )["properties"]["resolvedDeferred"]
    closures = {}
    for observed in (current, previous):
        for row in _resolved_deferred_rows(observed, closure_schema):
            if row["id"] not in pending_ids:
                closures.setdefault(row["id"], copy.deepcopy(row))
    coverage.pop("resolvedDeferred", None)
    if closures:
        coverage["resolvedDeferred"] = list(closures.values())
    if current.get("complete") is False or previous.get("complete") is False:
        merged["complete"] = False
    coverage.pop("completeness", None)
    return merged
