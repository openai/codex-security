#!/usr/bin/env python3
"""Build a portable evidence-backed explorer. Python 3.12+, standard library only."""

import argparse
import hashlib
import json
import math
import re
from itertools import pairwise
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(model, assessment):
    def indexed(key):
        items = model.get(key, [])
        require(isinstance(items, list), f"{key} must be a list")
        ids = [item.get("id") for item in items]
        require(all(isinstance(i, str) and i for i in ids), f"{key}: nonempty string IDs required")
        require(len(ids) == len(set(ids)), f"{key}: duplicate IDs")
        return dict(zip(ids, items))

    nodes, edges, scenarios, evidence = (
        indexed(k) for k in ("nodes", "edges", "scenarios", "evidence")
    )
    regions = indexed("regions")
    require(nodes, "At least one node is required")
    if "metadata" in model:
        metadata = model["metadata"]
        require(isinstance(metadata, list), "metadata must be an array of {label, value} objects")
        for i, item in enumerate(metadata):
            require(
                isinstance(item, dict)
                and all(isinstance(item.get(k), str) for k in ("label", "value")),
                f"metadata[{i}] must have string label and value",
            )

    def number(v, label):
        require(
            isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v),
            f"{label}: finite number required",
        )

    for axis in ("width", "height"):
        v = model["canvas"][axis]
        number(v, f"canvas.{axis}")
        require(v > 0, f"canvas.{axis} must be positive")
    for item in [*nodes.values(), *regions.values()]:
        for k in ("x", "y", "w", "h"):
            number(item[k], f"{item['id']}.{k}")
        require(item["w"] > 0 and item["h"] > 0, f"{item['id']}: dimensions must be positive")
        require(isinstance(item.get("title"), str), f"{item['id']}.title must be a string")
    for e in edges.values():
        require(
            e.get("label") is None or isinstance(e["label"], str),
            f"{e['id']}.label must be a string when supplied",
        )
        require(e["from"] in nodes and e["to"] in nodes, f"{e['id']}: unresolved endpoint")
        require(len(e["points"]) >= 2, f"{e['id']}: at least two route points required")
        for point in e["points"]:
            require(len(point) == 2, f"{e['id']}: point needs x,y")
            for v in point:
                number(v, e["id"])
        for k in ("labelX", "labelY"):
            number(e[k], f"{e['id']}.{k}")
    if "overviewEdges" in model:
        values = model["overviewEdges"]
        require(
            isinstance(values, list)
            and all(isinstance(i, str) and i in edges for i in values)
            and len(values) == len(set(values)),
            "overviewEdges must contain unique resolved edge IDs (may be empty)",
        )

    def refs(item):
        values = item.get("evidence", [])
        require(
            isinstance(values, list) and all(isinstance(ref, str) for ref in values),
            f"{item['id']}: evidence must be an array of string IDs",
        )
        for ref in values:
            require(ref in evidence, f"{item['id']}: unresolved evidence {ref}")

    for n in nodes.values():
        require(
            n.get("subtitle") is None or isinstance(n["subtitle"], str),
            f"{n['id']}.subtitle must be a string when supplied",
        )
        refs(n)

    def source_roles(items, label, participant=False, routes=()):
        require(isinstance(items, list), f"{label}: source roles must be an array")
        ids = [item.get("id") for item in items]
        require(
            all(isinstance(i, str) and i for i in ids) and len(ids) == len(set(ids)),
            f"{label}: source role IDs must be unique nonempty strings",
        )
        for item in items:
            node = item.get("node")
            require(
                "node" in item and (node in nodes or (node is None and not participant)),
                f"{label}: source node must resolve or explicitly be null",
            )
            kinds = (
                {"authorized-user"}
                if participant
                else {"adversary", "compromised-component", "untrusted-input", "unknown"}
            )
            require(item.get("kind") in kinds, f"{label}: invalid source role kind")
            if participant:
                require(
                    nodes[node].get("kind") == "actor",
                    f"{label}: authorized user needs an actor node, not its receiving component",
                )
            for key in (
                ("label", "description") if participant else ("label", "description", "authority")
            ):
                require(
                    isinstance(item.get(key), str) and item[key].strip(),
                    f"{label}: source role requires {key}",
                )
            require(
                isinstance(item.get("evidence"), list) and item["evidence"],
                f"{label}: source role requires assessment evidence",
            )
            refs(item)
            if not participant:
                require(
                    item.get("basis") in {"scenario-assumption", "assessment-observed", "unknown"},
                    f"{label}: source role requires explicit basis",
                )
                if "routeIds" in item:
                    require(
                        isinstance(item["routeIds"], list)
                        and item["routeIds"]
                        and len(set(item["routeIds"])) == len(item["routeIds"])
                        and all(r in routes for r in item["routeIds"]),
                        f"{label}: source routeIds must resolve to scenario routes",
                    )

    source_roles(model.get("participants", []), "participants", participant=True)

    def chain(item, scenario_id, route_id):
        ids = item.get("edges", [])
        require(
            isinstance(ids, list) and ids and all(i in edges for i in ids),
            f"{scenario_id}: route needs resolved edges",
        )
        require(len(ids) == len(set(ids)), f"{scenario_id}: route cannot repeat an edge")
        require(
            all(edges[a]["to"] == edges[b]["from"] for a, b in pairwise(ids)),
            f"{scenario_id}: disconnected route",
        )
        require(item.get("evidence"), f"{scenario_id}: route requires assessment evidence")
        refs(dict(item, id=route_id))
        return ids

    def applicable_routes(control, routes, sources):
        return [
            route
            for route in routes
            if (not control.get("routeIds") or route["id"] in control["routeIds"])
            and (
                not control.get("sourceIds")
                or any(
                    source["id"] in control["sourceIds"]
                    and (not source.get("routeIds") or route["id"] in source["routeIds"])
                    for source in sources
                )
            )
        ]

    for s in scenarios.values():
        refs(s)
        require(isinstance(s.get("steps"), list), f"{s['id']}: steps array required (may be empty)")
        require(
            all(i in nodes for i in s.get("affectedNodes", [])),
            f"{s['id']}: unresolved affected node",
        )
        require(
            all(i in edges for i in s.get("affectedEdges", [])),
            f"{s['id']}: unresolved affected edge",
        )
        if "focusNodes" in s:
            require(
                isinstance(s["focusNodes"], list) and all(i in nodes for i in s["focusNodes"]),
                f"{s['id']}: unresolved focus node",
            )
        routes = s.get("routes", [])
        require(isinstance(routes, list), f"{s['id']}: routes must be an array")
        require(len({r["id"] for r in routes}) == len(routes), f"{s['id']}: duplicate route ID")
        source_roles(s.get("sources", []), s["id"], routes={r["id"] for r in routes})
        if len(s.get("sources", [])) > 1 or "sourceMode" in s:
            require(
                s.get("sourceMode") in {"alternatives", "combined"},
                f"{s['id']}: multiple sources need explicit sourceMode",
            )
        for source in s.get("sources", []):
            for field, resolved in (("relatedNodes", nodes), ("relatedEdges", edges)):
                if field in source:
                    require(
                        s.get("sourceMode") == "alternatives" and not s["steps"] and not routes,
                        f"{source['id']}: source relationships require alternative unordered views without routes",
                    )
                    values = source[field]
                    require(
                        isinstance(values, list)
                        and all(isinstance(i, str) and i in resolved for i in values)
                        and len(values) == len(set(values)),
                        f"{source['id']}: {field} must contain unique resolved IDs (may be empty)",
                    )
        for route in routes:
            require(
                isinstance(route.get("id"), str) and route["id"] and route.get("label"),
                f"{s['id']}: route ID and label required",
            )
            require(
                "focusNodes" in s, f"{s['id']}: routes require explicit focusNodes (may be empty)"
            )
            ids = chain(route, s["id"], route["id"])
            positions = [ids.index(t["edge"]) if t["edge"] in ids else -1 for t in s["steps"]]
            require(
                all(i >= 0 for i in positions) and positions == sorted(set(positions)),
                f"{s['id']}: route must contain the scenario steps in order",
            )
            attached = {n for i in ids for n in (edges[i]["from"], edges[i]["to"])}
            for branch in route.get("branches", []):
                branch_ids = chain(branch, s["id"], route["id"])
                require(
                    edges[branch_ids[0]]["from"] in attached, f"{s['id']}: unattached route branch"
                )
                require(
                    not set(branch_ids) & set(ids), f"{s['id']}: branch repeats a main route edge"
                )
                require(
                    not ("beforeStep" in branch and "afterStep" in branch),
                    f"{s['id']}: branch cannot have both beforeStep and afterStep",
                )
                if "afterStep" in branch:
                    step = branch["afterStep"]
                    require(
                        isinstance(step, int)
                        and not isinstance(step, bool)
                        and 1 <= step <= len(s["steps"]),
                        f"{s['id']}: afterStep must be a one-based scenario step",
                    )
                if "beforeStep" in branch:
                    step = branch["beforeStep"]
                    require(
                        isinstance(step, int)
                        and not isinstance(step, bool)
                        and 1 <= step <= len(s["steps"]),
                        f"{s['id']}: beforeStep must be a one-based scenario step",
                    )
                    decision_edge = edges[s["steps"][step - 1]["edge"]]
                    decision_index = ids.index(decision_edge["id"])
                    prefix_nodes = {
                        n
                        for i in ids[: decision_index + 1]
                        for n in (edges[i]["from"], edges[i]["to"])
                    }
                    require(
                        edges[branch_ids[0]]["from"] in prefix_nodes,
                        f"{s['id']}: beforeStep branch must start on the route at or before its decision",
                    )
                attached.update(n for i in branch_ids for n in (edges[i]["from"], edges[i]["to"]))
        for step in s["steps"]:
            require(
                step["from"] in nodes and step["to"] in nodes, f"{s['id']}: unresolved step node"
            )
            require(step.get("edge") in edges, f"{s['id']}: unresolved step edge")
            edge = edges[step["edge"]]
            require(
                (edge["from"], edge["to"]) == (step["from"], step["to"]),
                f"{s['id']}: step edge does not connect stated nodes",
            )
        controls = s.get("controls", [])
        require(
            len({c["id"] for c in controls}) == len(controls), f"{s['id']}: duplicate control ID"
        )
        for c in controls:
            require(c["kind"] in ("existing", "proposed"), f"{c['id']}: invalid control kind")
            refs(c)
            require(
                all(i in nodes for i in c.get("nodes", [])), f"{c['id']}: unresolved control node"
            )
            require(
                all(i in edges for i in c.get("edges", [])), f"{c['id']}: unresolved control edge"
            )
            for field, resolved in (
                ("sourceIds", {source["id"] for source in s.get("sources", [])}),
                ("routeIds", {route["id"] for route in routes}),
            ):
                if field in c:
                    values = c[field]
                    require(
                        isinstance(values, list)
                        and values
                        and all(isinstance(i, str) and i in resolved for i in values)
                        and len(values) == len(set(values)),
                        f"{c['id']}: {field} must contain nonempty unique resolved IDs",
                    )
                    if field == "sourceIds":
                        require(
                            s.get("sourceMode") == "alternatives",
                            f"{c['id']}: source-scoped controls require alternative sources; combined semantics are not inferred",
                        )
            effect = c.get("effect")
            if effect is None:
                continue  # Legacy descriptive overlays never acquire blocking semantics.
            require(isinstance(effect, dict), f"{c['id']}: effect must be an object")
            require(
                effect.get("outcome")
                in ("blocks", "limits", "detects", "does-not-block", "unknown"),
                f"{c['id']}: invalid control outcome",
            )
            require(
                effect.get("basis") in ("declared", "verified", "hypothetical", "unverified"),
                f"{c['id']}: invalid effect basis",
            )
            require(
                (c["kind"] == "proposed") == (effect["basis"] == "hypothetical"),
                f"{c['id']}: proposals require hypothetical basis; existing controls cannot use it",
            )
            require(c.get("evidence"), f"{c['id']}: effects require assessment evidence")
            for field in ("label", "reason", "conditions", "residual"):
                require(
                    isinstance(effect.get(field), str) and effect[field].strip(),
                    f"{c['id']}: effect.{field} is required",
                )
            if "traffic" in effect:
                require(
                    effect["outcome"] == "blocks" and effect["traffic"] in ("stops", "continues"),
                    f"{c['id']}: traffic must be stops or continues on a blocking effect",
                )
            if "arrival" in effect:
                require(
                    effect["outcome"] == "blocks"
                    and effect.get("traffic", "stops") == "stops"
                    and isinstance(effect["arrival"], bool),
                    f"{c['id']}: arrival must be a boolean on a traffic-stopping block",
                )
            if "edge" in effect:
                require(effect["edge"] in edges, f"{c['id']}: unresolved effect edge")
                scoped = (
                    {step["edge"] for step in s["steps"]}
                    | set(s.get("affectedEdges", []))
                    | {edge for route in routes for edge in route["edges"]}
                    | {
                        edge
                        for route in routes
                        for branch in route.get("branches", [])
                        for edge in branch["edges"]
                    }
                )
                require(
                    effect["edge"] in scoped, f"{c['id']}: effect edge is outside this scenario"
                )
                if effect.get("traffic") == "continues" and routes:
                    for route in applicable_routes(c, routes, s.get("sources", [])):
                        route_edges = set(route["edges"]) | {
                            edge for branch in route.get("branches", []) for edge in branch["edges"]
                        }
                        require(
                            effect["edge"] in route_edges,
                            f"{c['id']}: continuing effect edge must occur in each applicable route",
                        )
            if "step" in effect:
                step = effect["step"]
                require(
                    isinstance(step, int)
                    and not isinstance(step, bool)
                    and 1 <= step <= len(s["steps"]),
                    f"{c['id']}: effect.step must be a one-based scenario step",
                )
                require(
                    s["steps"][step - 1]["edge"] == effect.get("edge"),
                    f"{c['id']}: effect edge must match its scenario step",
                )
            if effect["outcome"] == "blocks":
                require(
                    effect["basis"] != "unverified", f"{c['id']}: unverified effect cannot block"
                )
            if effect["outcome"] == "blocks" and effect.get("traffic", "stops") == "stops":
                require(
                    "step" in effect and "marker" in effect,
                    f"{c['id']}: blocking needs a step and marker",
                )
                require(
                    routes or all(a["to"] == b["from"] for a, b in zip(s["steps"], s["steps"][1:])),
                    f"{c['id']}: blocking needs a continuous ordered path; separate independent branches",
                )
                route = [step["edge"] for step in s["steps"]]
                require(
                    len(route) == len(set(route)),
                    f"{c['id']}: blocking cannot reuse an edge; separate repeated traversals",
                )
                if not effect.get("arrival", False):
                    for route in applicable_routes(c, routes, s.get("sources", [])):
                        for branch in route.get("branches", []):
                            require(
                                not (
                                    branch.get("beforeStep") == effect["step"]
                                    and edges[branch["edges"][0]]["from"]
                                    == edges[effect["edge"]]["to"]
                                ),
                                f"{c['id']}: beforeStep branch at the stopping decision destination requires arrival:true",
                            )
            marker = effect.get("marker")
            if marker is not None:
                require("edge" in effect, f"{c['id']}: marker needs an effect edge")
                for field in ("at", "x", "y", "w"):
                    number(marker.get(field), f"{c['id']}.marker.{field}")
                require(0 < marker["at"] < 1, f"{c['id']}: marker.at must be inside the edge")
                require(marker["w"] >= 180, f"{c['id']}: marker width must be at least 180")
                require(
                    0 <= marker["x"] <= model["canvas"]["width"] - marker["w"]
                    and 0 <= marker["y"] <= model["canvas"]["height"] - 72,
                    f"{c['id']}: marker label must fit the canvas (height 72)",
                )
                points = edges[effect["edge"]]["points"]
                require(
                    any(a != b for a, b in pairwise(points)),
                    f"{c['id']}: marker edge must have nonzero length",
                )
    lines = assessment.splitlines(keepends=True)
    for e in evidence.values():
        require(
            isinstance(e.get("quote"), str) and e["quote"].strip(), f"{e['id']}: quotation required"
        )
        require(e["quote"] in assessment, f"{e['id']}: quotation is not exact assessment text")
        if "startLine" in e or "endLine" in e:
            a, b = e.get("startLine"), e.get("endLine")
            require(
                isinstance(a, int) and isinstance(b, int) and 1 <= a <= b <= len(lines),
                f"{e['id']}: invalid assessment line range",
            )
            require(
                e["quote"] in "".join(lines[a - 1 : b]),
                f"{e['id']}: quotation outside stated range",
            )
        paths = e.get("paths", [])
        require(
            isinstance(paths, list) and all(isinstance(path, str) for path in paths),
            f"{e['id']}: paths must be an array of strings",
        )
        for path in paths:
            require(path in e["quote"], f"{e['id']}: cited path not present in quotation: {path}")
    if model.get("assessmentSha256"):
        require(
            hashlib.sha256(assessment.encode("utf-8")).hexdigest() == model["assessmentSha256"],
            "Assessment SHA256 mismatch",
        )


def embedded(value):
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def layout_diagnostic(model, area=None):
    """Heuristic only: no font shaping, browser layout or collision detection."""
    lines = [
        (
            "Layout estimate (not browser measurements): label width ≈ 0.6 × font size × character count; "
            "node text has 10 units padding on each side. Glyphs and fonts vary."
        )
    ]
    risks = []
    for node in model["nodes"]:
        for field, size in (("title", 17), ("subtitle", 14)):
            value = node.get(field)
            label = "" if value is None else str(value)
            estimate = len(label) * size * 0.6
            available = max(0, node["w"] - 20)
            if estimate > available:
                risks.append(f"{node['id']}.{field} ({estimate:.0f} > {available:.0f} units)")
    lines.append(
        "Possible node label overflow: "
        + (
            ", ".join(risks[:12]) + (f" (+{len(risks) - 12} more)" if len(risks) > 12 else "")
            if risks
            else "none estimated"
        )
    )
    if area:
        width, height = area
        require(
            all(math.isfinite(v) and v > 0 for v in area), "fit area must be positive and finite"
        )
        scale = min(width / model["canvas"]["width"], height / model["canvas"]["height"])
        lines.append(
            f"Assumed diagram area {width:g} × {height:g} CSS px; two-axis fit {scale:.3f}; "
            f"estimated title/subtitle/connector {17 * scale:.1f}/{14 * scale:.1f}/{13 * scale:.1f} CSS px "
            "(11 px target for each)."
        )
    else:
        lines.append(
            "Supply --fit-area WIDTH HEIGHT using the actual diagram area to estimate fitted text size."
        )
    lines.append(
        "Inspect actual rendered text and selected views; estimates do not test readability or collisions."
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path)
    parser.add_argument("--assessment", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--fit-area",
        type=float,
        nargs=2,
        metavar=("WIDTH", "HEIGHT"),
        help="assumed diagram area in CSS pixels for a two-axis fit estimate",
    )
    args = parser.parse_args()
    try:
        model = json.loads(args.model.read_text(encoding="utf-8"))
        assessment = args.assessment.read_bytes().decode("utf-8")
        validate(model, assessment)
        diagnostic = layout_diagnostic(model, args.fit_area)
        assets = Path(__file__).resolve().parents[1] / "assets"
        template = (assets / "explorer.html").read_text(encoding="utf-8")
        replacements = {
            "__MODEL_JSON__": embedded(model),
            "__ASSESSMENT_JSON__": embedded(assessment),
        }
        for placeholder, filename in (
            ("__CONTROL_EFFECTS_JS__", "control-effects.js"),
            ("__ROUTE_PATHS_JS__", "route-paths.js"),
            ("__SOURCE_ROLES_JS__", "source-roles.js"),
            ("__EXPLORER_CSS__", "explorer.css"),
            ("__EXPLORER_JS__", "explorer.js"),
        ):
            replacements[placeholder] = (assets / filename).read_text(encoding="utf-8")
        # Replace only template tokens, never token-like text in inserted source data.
        result = re.sub(
            "|".join(map(re.escape, replacements)),
            lambda match: replacements[match.group()],
            template,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
        print(
            f"Built {args.output} ({len(model['nodes'])} nodes, {len(model['scenarios'])} scenarios)"
        )
        print(diagnostic)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Build error: {exc}\n")


if __name__ == "__main__":
    main()
