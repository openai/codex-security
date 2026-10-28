"""Semantic guard checks for control effects. Python 3.12+."""

import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "builder", Path(__file__).parents[1] / "skills/threat-model-visualize/scripts/build_explorer.py"
)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ControlValidation(unittest.TestCase):
    def setUp(self):
        self.model = {
            "brand": "Synthetic assessment",
            "title": "Policy boundary",
            "subtitle": "Synthetic request path",
            "snapshotLabel": "Test fixture",
            "mapTitle": "Request flow",
            "mapDescription": "One caller and two components.",
            "overviewTitle": "Architecture",
            "overview": "Requests pass from a through b to c.",
            "evidenceBoundary": "Synthetic assessment evidence.",
            "footer": "Test fixture",
            "canvas": {"width": 800, "height": 500},
            "nodes": [
                {"id": name, "title": name, "x": i * 200, "y": 100, "w": 100, "h": 60}
                for i, name in enumerate("abc")
            ],
            "edges": [
                {
                    "id": edge,
                    "from": a,
                    "to": b,
                    "label": edge,
                    "points": [[100 + i * 200, 130], [200 + i * 200, 130]],
                    "labelX": 150 + i * 200,
                    "labelY": 120,
                }
                for i, (edge, a, b) in enumerate([("ab", "a", "b"), ("bc", "b", "c")])
            ],
            "evidence": [{"id": "ev", "label": "Policy", "quote": "policy denies this caller"}],
            "scenarios": [
                {
                    "id": "H1",
                    "title": "Denied caller",
                    "status": "Hypothesis",
                    "summary": "The supplied policy denies this caller.",
                    "steps": [
                        {"title": "Request", "from": "a", "to": "b", "edge": "ab"},
                        {"title": "Forward", "from": "b", "to": "c", "edge": "bc"},
                    ],
                    "controls": [
                        {
                            "id": "c1",
                            "kind": "existing",
                            "title": "Caller policy",
                            "description": "Deny the selected caller.",
                            "evidence": ["ev"],
                            "effect": {
                                "outcome": "blocks",
                                "basis": "declared",
                                "step": 1,
                                "edge": "ab",
                                "label": "Caller denied",
                                "reason": "Policy denies this caller.",
                                "conditions": "Policy is applied and enforced.",
                                "residual": "Other callers remain permitted.",
                                "marker": {"at": 0.5, "x": 80, "y": 220, "w": 240},
                            },
                        }
                    ],
                }
            ],
        }

    def check(self, model=None):
        builder.validate(self.model if model is None else model, "policy denies this caller")

    def effect(self):
        return self.model["scenarios"][0]["controls"][0]["effect"]

    def build_html(self, assessment, *extra_args):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            model_file, source, output = (
                folder / "model.json",
                folder / "assessment.md",
                folder / "output.html",
            )
            model_file.write_text(json.dumps(self.model, ensure_ascii=False), encoding="utf-8")
            source.write_bytes(assessment.encode("utf-8"))
            original_model = model_file.read_bytes()
            subprocess.run(
                [
                    sys.executable,
                    str(Path(builder.__file__)),
                    str(model_file),
                    "--assessment",
                    str(source),
                    "--output",
                    str(output),
                    *extra_args,
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual(model_file.read_bytes(), original_model)
            self.assertEqual(source.read_bytes(), assessment.encode("utf-8"))
            return output.read_text(encoding="utf-8")

    def embedded_data(self, html, element_id):
        match = re.search(
            rf'<script id="{element_id}" type="application/json">(.*?)</script>', html, re.S
        )
        self.assertIsNotNone(match)
        return json.loads(match.group(1))

    def test_valid_and_legacy_models(self):
        self.check()
        self.model["nodes"][0]["subtitle"] = None
        self.model["edges"][0]["label"] = None
        self.check()  # Optional captions may be omitted without breaking the renderer.
        del self.model["scenarios"][0]["controls"][0]["effect"]
        self.check()

    def test_metadata_requires_array_of_label_value_strings(self):
        # The observed round-one object reaches JS .map and prevents initialization.
        for bad in (
            {"fidelity": "simple"},
            None,
            "simple",
            [None],
            [{"label": "Scope"}],
            [{"label": "Scope", "value": 1}],
        ):
            self.model["metadata"] = bad
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "metadata"):
                self.check()
        for good in (
            [],
            [
                {"label": "Fidelity", "value": "simple"},
                {"label": "Scope", "value": "Selected path"},
            ],
        ):
            self.model["metadata"] = good
            self.check()

    def test_builder_rejects_unrenderable_fields_before_writing_html(self):
        missing = object()
        cases = [
            (("metadata",), {"fidelity": "simple"}, "metadata must be an array"),
            (("nodes", 0, "title"), missing, "a.title must be a string"),
            (
                ("regions",),
                [{"id": "boundary", "x": 0, "y": 0, "w": 600, "h": 200}],
                "boundary.title must be a string",
            ),
            (("nodes", 0, "subtitle"), {"text": "Caller"}, "a.subtitle must be a string"),
            (("edges", 0, "label"), {"text": "Request"}, "ab.label must be a string"),
            *[
                (path + ("evidence",), {"ev": True}, "evidence must be an array of string IDs")
                for path in (("nodes", 0), ("scenarios", 0), ("scenarios", 0, "controls", 0))
            ],
        ]
        for path, value, message in cases:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as folder:
                folder = Path(folder)
                model = copy.deepcopy(self.model)
                target = model
                for key in path[:-1]:
                    target = target[key]
                if value is missing:
                    del target[path[-1]]
                else:
                    target[path[-1]] = value
                model_file, assessment, output = (
                    folder / "model.json",
                    folder / "assessment.md",
                    folder / "output.html",
                )
                assessment.write_text("policy denies this caller", encoding="utf-8")
                model_file.write_text(json.dumps(model), encoding="utf-8")
                original_model = model_file.read_bytes()
                original_assessment = assessment.read_bytes()
                command = [
                    sys.executable,
                    str(Path(builder.__file__)),
                    str(model_file),
                    "--assessment",
                    str(assessment),
                    "--output",
                    str(output),
                ]
                result = subprocess.run(command, text=True, capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)
                self.assertFalse(output.exists())
                self.assertEqual(model_file.read_bytes(), original_model)
                self.assertEqual(assessment.read_bytes(), original_assessment)

    def test_overview_edges_require_unique_resolved_ids(self):
        self.model["overviewEdges"] = ["ab"]
        self.check()
        for bad in (["ab", "ab"], ["missing"], "ab", [None]):
            self.model["overviewEdges"] = bad
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "overviewEdges"):
                self.check()
        self.model["overviewEdges"] = []
        self.check()

    def test_evidence_topology_and_marker_boundaries(self):
        effect = ("scenarios", 0, "controls", 0, "effect")
        marker = effect + ("marker",)
        cases = [
            (("evidence", 0, "quote"), "policy allows this caller", "quotation is not exact"),
            (("scenarios", 0, "steps", 0, "to"), "c", "step edge does not connect"),
            (effect + ("step",), 2, "must match"),
            (effect + ("edge",), "missing", "unresolved effect edge"),
            *[
                ((key,), self.model[key] + [self.model[key][0]], "duplicate IDs")
                for key in ("nodes", "edges", "scenarios", "evidence")
            ],
            *[
                (marker + (axis,), value, "marker label must fit")
                for axis, value in [("x", -1), ("x", 561), ("y", -1), ("y", 429)]
            ],
        ]
        for path, value, message in cases:
            with self.subTest(
                path=path, value="duplicate ID" if isinstance(value, list) else value
            ):
                model = copy.deepcopy(self.model)
                target = model
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.check(model)
        # A 240 × 72 marker fits exactly at either corner of the 800 × 500 canvas.
        for x, y in ((0, 0), (560, 428)):
            self.effect()["marker"].update(x=x, y=y)
            self.check()

    def test_unknown_effect_is_not_a_block(self):
        self.effect()["basis"] = "unverified"
        with self.assertRaisesRegex(ValueError, "unverified effect cannot block"):
            self.check()
        self.effect()["outcome"] = "unknown"
        self.check()

    def test_proposed_cannot_be_verified(self):
        self.model["scenarios"][0]["controls"][0]["kind"] = "proposed"
        self.effect()["basis"] = "verified"
        with self.assertRaisesRegex(ValueError, "hypothetical"):
            self.check()

    def test_effect_requires_evidence(self):
        self.model["scenarios"][0]["controls"][0]["evidence"] = []
        with self.assertRaisesRegex(ValueError, "require assessment evidence"):
            self.check()

    def test_evidence_paths_require_an_array_of_strings(self):
        evidence = self.model["evidence"][0]
        for invalid in ("policy", {"policy": True}, None, [1], ["policy", None]):
            evidence["paths"] = invalid
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "paths must be an array of strings"),
            ):
                self.check()
        for valid in ([], ["policy"], ["policy", "caller"]):
            evidence["paths"] = valid
            self.check()
        evidence["paths"] = ["not quoted"]
        with self.assertRaisesRegex(ValueError, "cited path not present"):
            self.check()
        del evidence["paths"]
        self.check()

    def test_disconnected_steps_do_not_hide_an_independent_branch(self):
        self.model["scenarios"][0]["steps"][1] = {"from": "a", "to": "b", "edge": "ab"}
        with self.assertRaisesRegex(ValueError, "continuous ordered path"):
            self.check()

    def test_repeated_edge_cannot_hide_an_earlier_traversal(self):
        self.model["edges"].append(
            {
                "id": "ba",
                "from": "b",
                "to": "a",
                "points": [[200, 150], [100, 150]],
                "labelX": 150,
                "labelY": 160,
            }
        )
        self.model["scenarios"][0]["steps"] = [
            {"from": "a", "to": "b", "edge": "ab"},
            {"from": "b", "to": "a", "edge": "ba"},
            {"from": "a", "to": "b", "edge": "ab"},
        ]
        with self.assertRaisesRegex(ValueError, "cannot reuse an edge"):
            self.check()

    def routed(self):
        s = self.model["scenarios"][0]
        s["focusNodes"] = ["c"]
        s["routes"] = [
            {"id": "r", "label": "Public request", "edges": ["ab", "bc"], "evidence": ["ev"]}
        ]
        return s

    def test_routes_preserve_all_intermediaries(self):
        s = self.routed()
        self.check()
        s["routes"][0]["edges"] = ["bc", "ab"]
        with self.assertRaisesRegex(ValueError, "disconnected route"):
            self.check()

    def test_route_cannot_omit_controlled_transition(self):
        s = self.routed()
        s["routes"][0]["edges"] = ["bc"]
        with self.assertRaisesRegex(ValueError, "steps in order"):
            self.check()

    def test_route_requires_evidence_and_explicit_focus(self):
        s = self.routed()
        del s["focusNodes"]
        with self.assertRaisesRegex(ValueError, "explicit focusNodes"):
            self.check()
        s["focusNodes"] = []
        s["routes"][0]["evidence"] = []
        with self.assertRaisesRegex(ValueError, "route requires assessment evidence"):
            self.check()

    def test_unattached_dependency_rejected(self):
        s = self.routed()
        self.model["nodes"].extend(
            [{"id": n, "title": n, "x": 0, "y": 0, "w": 20, "h": 20} for n in "xy"]
        )
        self.model["edges"].append(
            {
                "id": "xy",
                "from": "x",
                "to": "y",
                "points": [[0, 0], [20, 0]],
                "labelX": 0,
                "labelY": 0,
            }
        )
        s["routes"][0]["branches"] = [{"edges": ["xy"], "evidence": ["ev"]}]
        with self.assertRaisesRegex(ValueError, "unattached"):
            self.check()

    def test_prerequisite_branch_must_identify_its_decision(self):
        s = self.routed()
        self.effect()["arrival"] = True
        self.model["nodes"].append({"id": "d", "title": "d", "x": 0, "y": 0, "w": 20, "h": 20})
        self.model["edges"].append(
            {
                "id": "bd",
                "from": "b",
                "to": "d",
                "points": [[0, 0], [20, 0]],
                "labelX": 0,
                "labelY": 0,
            }
        )
        branch = {"edges": ["bd"], "evidence": ["ev"], "beforeStep": 1}
        s["routes"][0]["branches"] = [branch]
        self.check()
        for invalid in (0, 3, True, "1"):
            branch["beforeStep"] = invalid
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "one-based scenario step"),
            ):
                self.check()
        branch["beforeStep"] = 2
        self.check()  # b is an earlier, explicitly ordered prerequisite origin.
        self.model["edges"][-1]["from"] = "c"
        branch["beforeStep"] = 1
        with self.assertRaisesRegex(ValueError, "at or before its decision"):
            self.check()

    def test_decision_destination_prerequisite_requires_arrival(self):
        s = self.routed()
        s["routes"][0]["branches"] = [{"edges": ["bc"], "evidence": ["ev"], "beforeStep": 1}]
        s["routes"][0]["edges"] = ["ab"]
        s["steps"] = s["steps"][:1]
        for kind in ("existing", "proposed"):
            s["controls"][0]["kind"] = kind
            self.effect()["basis"] = "declared" if kind == "existing" else "hypothetical"
            for arrival in (None, False, True):
                with self.subTest(kind=kind, arrival=arrival):
                    if arrival is None:
                        self.effect().pop("arrival", None)
                    else:
                        self.effect()["arrival"] = arrival
                    if arrival is True:
                        self.check()
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "destination requires arrival:true"
                        ):
                            self.check()

    def test_prerequisite_arrival_guard_honors_control_scope(self):
        s = self.routed()
        s["steps"] = s["steps"][:1]
        s["routes"][0]["edges"] = ["ab"]
        s["routes"].append(
            {
                "id": "other",
                "label": "Other path",
                "edges": ["ab"],
                "evidence": ["ev"],
                "branches": [{"edges": ["bc"], "evidence": ["ev"], "beforeStep": 1}],
            }
        )
        source = self.origin()
        source["routeIds"] = ["r"]
        s["sources"].append(dict(source, id="second", routeIds=["other"]))
        s["sourceMode"] = "alternatives"
        control = s["controls"][0]
        control["sourceIds"] = ["origin"]
        self.check()  # This source cannot select the route with the destination branch.
        control["sourceIds"] = ["second"]
        with self.assertRaisesRegex(ValueError, "destination requires arrival:true"):
            self.check()
        control["routeIds"] = ["r"]
        self.check()  # The additional route restriction excludes that branch again.

    def test_later_branch_guard_requires_one_unambiguous_step(self):
        s = self.routed()
        self.model["nodes"].append({"id": "d", "title": "d", "x": 0, "y": 0, "w": 20, "h": 20})
        self.model["edges"].append(
            {
                "id": "bd",
                "from": "b",
                "to": "d",
                "points": [[0, 0], [20, 0]],
                "labelX": 0,
                "labelY": 0,
            }
        )
        branch = {"edges": ["bd"], "evidence": ["ev"], "afterStep": 2}
        s["routes"][0]["branches"] = [branch]
        self.check()
        for invalid in (0, 3, True, "1"):
            branch["afterStep"] = invalid
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "afterStep must be a one-based"),
            ):
                self.check()
        branch["afterStep"] = 1
        branch["beforeStep"] = 1
        with self.assertRaisesRegex(ValueError, "cannot have both"):
            self.check()

    def test_layout_diagnostic_estimates_both_axes_and_warns_on_labels(self):
        node = self.model["nodes"][0]
        node.update(title="A long title that will not fit", subtitle="Short")
        result = builder.layout_diagnostic(self.model, (800, 250))
        self.assertIn("a.title", result)
        self.assertIn("two-axis fit 0.500", result)
        self.assertIn("8.5/7.0/6.5 CSS px", result)
        node["subtitle"] = None  # Legacy models may omit a visible caption.
        builder.layout_diagnostic(self.model)
        with self.assertRaisesRegex(ValueError, "positive and finite"):
            builder.layout_diagnostic(self.model, (800, float("nan")))

    def test_block_traffic_and_arrival_are_explicit_and_compatible(self):
        effect = self.effect()
        effect["arrival"] = True
        self.check()
        effect["arrival"] = "yes"
        with self.assertRaisesRegex(ValueError, "arrival must be a boolean"):
            self.check()
        effect["arrival"] = True
        effect["traffic"] = "continues"
        with self.assertRaisesRegex(ValueError, "arrival must be a boolean"):
            self.check()
        del effect["arrival"]
        for key in ("step", "edge", "marker"):
            del effect[key]
        self.model["scenarios"][0]["steps"] = []
        self.check()  # Data-only prevention need not invent a sequence.
        effect["traffic"] = "maybe"
        with self.assertRaisesRegex(ValueError, "traffic must be stops or continues"):
            self.check()
        effect["traffic"] = "continues"
        effect["outcome"] = "limits"
        with self.assertRaisesRegex(ValueError, "traffic must be stops or continues"):
            self.check()

    def test_builder_embeds_new_contract_and_assessment_in_standalone_html(self):
        self.effect()["traffic"] = "continues"
        html = self.build_html("policy denies this caller", "--fit-area", "800", "250")
        assets = Path(builder.__file__).parents[1] / "assets"
        scripts = [
            code
            for attrs, code in re.findall(r"<script\b([^>]*)>(.*?)</script>", html, re.S | re.I)
            if "application/json" not in attrs.lower()
        ]
        expected = ["control-effects.js", "route-paths.js", "source-roles.js", "explorer.js"]
        self.assertEqual(
            [script.strip() for script in scripts],
            [(assets / name).read_text(encoding="utf-8").strip() for name in expected],
        )
        style = re.search(r"<style\b[^>]*>(.*?)</style>", html, re.S | re.I)
        self.assertIsNotNone(style)
        self.assertEqual(
            style.group(1).strip(), (assets / "explorer.css").read_text(encoding="utf-8").strip()
        )
        self.assertNotRegex(html, re.compile(r"<script\b[^>]*\bsrc\s*=", re.I))

    def test_template_tokens_in_input_are_preserved_without_resubstitution(self):
        tokens = "__MODEL_JSON__ __ASSESSMENT_JSON__ __EXPLORER_JS__ __EXPLORER_CSS__"
        assessment = (
            "policy denies this caller\n" + tokens + "\n</script><script>unsafe()</script> & café"
        )
        self.model["title"] = tokens
        self.model["metadata"] = [{"label": "Scope", "value": "Quoted tokens"}]
        self.model["evidence"][0]["quote"] = assessment
        html = self.build_html(assessment)
        self.assertEqual(self.embedded_data(html, "model-data"), self.model)
        self.assertEqual(self.embedded_data(html, "assessment-data"), assessment)
        self.assertNotIn("</script><script>unsafe()</script>", html)

    def test_utf8_assessment_hash_and_ranged_quote_preserve_line_endings(self):
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=repr(newline)):
                assessment = newline.join(
                    ["Context: café", "policy denies this caller", "Details: 日本語", ""]
                )
                evidence = self.model["evidence"][0]
                evidence.update(
                    quote=newline.join(["policy denies this caller", "Details: 日本語"]),
                    startLine=2,
                    endLine=3,
                )
                self.model["assessmentSha256"] = hashlib.sha256(
                    assessment.encode("utf-8")
                ).hexdigest()
                html = self.build_html(assessment)
                self.assertEqual(self.embedded_data(html, "assessment-data"), assessment)
                evidence["endLine"] = 2
                with self.assertRaisesRegex(ValueError, "quotation outside stated range"):
                    builder.validate(self.model, assessment)

    def test_assessment_hash_does_not_accept_newline_normalization(self):
        assessment = "policy denies this caller\r\n"
        self.model["assessmentSha256"] = hashlib.sha256(
            assessment.replace("\r\n", "\n").encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "Assessment SHA256 mismatch"):
            builder.validate(self.model, assessment)

    def test_continuing_effect_honors_source_and_route_intersection(self):
        s = self.routed()
        s["routes"].append(
            {"id": "other", "label": "Other path", "edges": ["ab", "bc"], "evidence": ["ev"]}
        )
        self.effect()["traffic"] = "continues"
        self.check()  # The effect is valid on both routes without source annotations.
        s["steps"] = []
        s["routes"][1]["edges"] = ["bc"]
        source = self.origin()
        source["routeIds"] = ["r"]
        s["sources"].append(dict(source, id="second", routeIds=["other"]))
        s["sourceMode"] = "alternatives"
        control = s["controls"][0]
        self.effect().pop("step")
        cases = [
            ({}, False),
            ({"sourceIds": ["origin"]}, True),
            ({"sourceIds": ["second"]}, False),
            ({"routeIds": ["r"]}, True),
            ({"routeIds": ["other"]}, False),
            ({"sourceIds": ["origin"], "routeIds": ["r", "other"]}, True),
            ({"sourceIds": ["origin", "second"], "routeIds": ["r"]}, True),
            ({"sourceIds": ["origin", "second"], "routeIds": ["other"]}, False),
        ]
        for scope, valid in cases:
            with self.subTest(scope=scope):
                control.pop("sourceIds", None)
                control.pop("routeIds", None)
                control.update(scope)
                if valid:
                    self.check()
                else:
                    with self.assertRaisesRegex(ValueError, "each applicable route"):
                        self.check()
        control.pop("routeIds")
        control["sourceIds"] = ["origin"]
        source.pop("routeIds")
        with self.assertRaisesRegex(ValueError, "each applicable route"):
            self.check()

    def test_prerequisite_on_a_revisited_decision_node_is_valid(self):
        s = self.routed()
        self.model["nodes"].append({"id": "d", "title": "d", "x": 0, "y": 0, "w": 20, "h": 20})
        self.model["edges"].extend(
            [
                {"id": i, "from": a, "to": b, "points": [[0, 0], [20, 0]], "labelX": 0, "labelY": 0}
                for i, a, b in [("cb", "c", "b"), ("bd", "b", "d")]
            ]
        )
        s["steps"] = [
            {"from": "b", "to": "c", "edge": "bc"},
            {"from": "c", "to": "b", "edge": "cb"},
        ]
        s["routes"][0]["edges"] = ["ab", "bc", "cb"]
        s["routes"][0]["branches"] = [{"edges": ["bd"], "evidence": ["ev"], "beforeStep": 2}]
        self.effect()["edge"] = "bc"
        self.check()
        # An earlier visit does not establish receipt of this later decision.
        self.effect().update(step=2, edge="cb")
        with self.assertRaisesRegex(ValueError, "destination requires arrival:true"):
            self.check()
        self.effect()["arrival"] = True
        self.check()

    def test_route_bridges_conceptual_steps(self):
        s = self.routed()
        self.model["edges"].extend(
            [
                {"id": i, "from": a, "to": b, "points": [[0, 0], [20, 0]], "labelX": 0, "labelY": 0}
                for i, a, b in [("ba", "b", "a"), ("ac", "a", "c")]
            ]
        )
        s["steps"][1] = {"from": "a", "to": "c", "edge": "ac"}
        s["routes"][0]["edges"] = ["ab", "ba", "ac"]
        self.effect()["step"] = 2
        self.effect()["edge"] = "ac"
        self.check()

    def origin(self):
        source = {
            "id": "origin",
            "node": "a",
            "kind": "adversary",
            "basis": "scenario-assumption",
            "label": "Viewer",
            "description": "Viewer attempts the scenario.",
            "authority": "Valid session",
            "evidence": ["ev"],
        }
        self.model["scenarios"][0]["sources"] = [source]
        return source

    def test_source_keeps_unmapped_actor_explicit(self):
        source = self.origin()
        source["node"] = None
        self.check()
        source["node"] = "listener-that-is-not-present"
        with self.assertRaisesRegex(ValueError, "source node"):
            self.check()

    def test_source_requires_evidence_and_starting_authority(self):
        source = self.origin()
        source["evidence"] = []
        with self.assertRaisesRegex(ValueError, "source role requires assessment evidence"):
            self.check()
        source["evidence"] = ["ev"]
        source["authority"] = ""
        with self.assertRaisesRegex(ValueError, "requires authority"):
            self.check()

    def test_source_basis_and_role_are_explicit(self):
        source = self.origin()
        source["basis"] = "inferred-safe"
        with self.assertRaisesRegex(ValueError, "explicit basis"):
            self.check()
        source["basis"] = "unknown"
        source["kind"] = "authenticated-therefore-benign"
        with self.assertRaisesRegex(ValueError, "invalid source role"):
            self.check()

    def test_source_cannot_leak_to_unrelated_route(self):
        self.routed()
        source = self.origin()
        source["routeIds"] = ["r"]
        self.check()
        source["routeIds"] = ["other-scenario-route"]
        with self.assertRaisesRegex(ValueError, "source routeIds"):
            self.check()

    def test_privileged_component_cannot_stand_in_for_authorized_user(self):
        self.model["participants"] = [
            {
                "id": "user",
                "node": "b",
                "kind": "authorized-user",
                "label": "Operator",
                "description": "Normal use.",
                "evidence": ["ev"],
            }
        ]
        with self.assertRaisesRegex(ValueError, "authorized user needs an actor"):
            self.check()
        self.model["nodes"][1]["kind"] = "actor"
        self.check()

    def test_multiple_sources_cannot_silently_become_joint_footholds(self):
        source = self.origin()
        scenario = self.model["scenarios"][0]
        scenario["sources"].append(dict(source, id="other"))
        with self.assertRaisesRegex(ValueError, "explicit sourceMode"):
            self.check()
        scenario["sourceMode"] = "alternatives"
        self.check()

    def test_source_relationship_overrides_require_unordered_alternatives(self):
        source = self.origin()
        scenario = self.model["scenarios"][0]
        scenario["sourceMode"] = "alternatives"
        source["relatedNodes"] = []
        source["relatedEdges"] = []
        with self.assertRaisesRegex(ValueError, "unordered views"):
            self.check()
        scenario["steps"] = []
        scenario["controls"] = []
        self.check()
        source["relatedNodes"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "unique resolved"):
            self.check()
        source["relatedNodes"] = ["a", "a"]
        with self.assertRaisesRegex(ValueError, "unique resolved"):
            self.check()
        source["relatedNodes"] = ["a"]
        source["relatedEdges"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "unique resolved"):
            self.check()
        source["relatedEdges"] = ["ab"]
        self.check()
        scenario["sourceMode"] = "combined"
        with self.assertRaisesRegex(ValueError, "unordered views"):
            self.check()
        scenario["sourceMode"] = "alternatives"
        scenario["focusNodes"] = []
        scenario["routes"] = [{"id": "r", "label": "Flow", "edges": ["ab"], "evidence": ["ev"]}]
        with self.assertRaisesRegex(ValueError, "without routes"):
            self.check()

    def test_control_scope_requires_resolved_nonempty_unique_ids(self):
        self.origin()
        scenario = self.routed()
        scenario["sourceMode"] = "alternatives"
        c = scenario["controls"][0]
        c["sourceIds"] = ["origin"]
        c["routeIds"] = ["r"]
        self.check()
        for field in ("sourceIds", "routeIds"):
            original = c[field]
            for invalid in ([], ["missing"], original * 2, "not-array"):
                c[field] = invalid
                with self.assertRaisesRegex(ValueError, "nonempty unique resolved"):
                    self.check()
            c[field] = original
        scenario["sourceMode"] = "combined"
        with self.assertRaisesRegex(ValueError, "combined semantics"):
            self.check()
        del c["sourceIds"]
        self.check()  # Combined sources may still have route-scoped controls.


if __name__ == "__main__":
    unittest.main()
