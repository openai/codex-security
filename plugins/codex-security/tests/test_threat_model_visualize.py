"""Semantic guard checks for control effects. Python 3.12+."""

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "builder", Path(__file__).parents[1] / "skills/threat-model-visualize/scripts/build_explorer.py"
)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class EmbeddedHtml(HTMLParser):
    """Extract script and style bodies while preserving their exact contents."""

    def __init__(self, html):
        super().__init__(convert_charrefs=False)
        self.elements = []
        self.current = None
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.current = (tag, dict(attrs), [])

    def handle_data(self, data):
        if self.current is not None:
            self.current[2].append(data)

    def handle_endtag(self, tag):
        if self.current is not None and tag == self.current[0]:
            self.elements.append((*self.current[:2], "".join(self.current[2])))
            self.current = None


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
        builder.validate(self.model if model is None else model, b"policy denies this caller")

    def effect(self):
        return self.model["scenarios"][0]["controls"][0]["effect"]

    def build_html(
        self, assessment_bytes, *, error=None, existing_html=None, model_encoding="utf-8"
    ):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            model_file, source, output = (
                folder / "model.json",
                folder / "assessment.md",
                folder / "output.html",
            )
            model_file.write_text(
                json.dumps(self.model, ensure_ascii=False), encoding=model_encoding
            )
            source.write_bytes(assessment_bytes)
            if existing_html is not None:
                output.write_text(existing_html, encoding="utf-8")
            original_model = model_file.read_bytes()
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(builder.__file__)),
                    str(model_file),
                    "--assessment",
                    str(source),
                    "--output",
                    str(output),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(model_file.read_bytes(), original_model)
            self.assertEqual(source.read_bytes(), assessment_bytes)
            if error:
                self.assertEqual(result.returncode, 2)
                self.assertIn(error, result.stderr)
                actual = output.read_text(encoding="utf-8") if output.exists() else None
                self.assertEqual(actual, existing_html)
                return None
            self.assertEqual(result.returncode, 0, result.stderr)
            return output.read_text(encoding="utf-8")

    def embedded_data(self, html, element_id):
        values = [
            code
            for tag, attrs, code in EmbeddedHtml(html).elements
            if tag == "script"
            and attrs.get("id") == element_id
            and (attrs.get("type") or "").lower() == "application/json"
        ]
        self.assertEqual(len(values), 1)
        return json.loads(values[0])

    def test_valid_and_legacy_models(self):
        self.check()
        self.model["nodes"][0]["subtitle"] = None
        self.model["edges"][0]["label"] = None
        self.check()  # Optional captions may be omitted without breaking the renderer.
        del self.model["scenarios"][0]["controls"][0]["effect"]
        self.check()

    def test_missing_required_arrays_preserve_existing_output(self):
        minimal = dict(self.model, edges=[], scenarios=[], evidence=[])
        self.check(minimal)
        for field in ("nodes", "edges", "scenarios", "evidence"):
            invalid = minimal.copy()
            del invalid[field]
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, f"{field} must be a list"),
            ):
                self.check(invalid)
        del self.model["scenarios"]
        self.build_html(
            b"policy denies this caller",
            error="scenarios must be a list",
            existing_html="<html>Previous explorer</html>",
        )

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
            (
                ("scenarios", 0, "affectedNodes"),
                "ab",
                "affectedNodes must be an array of string IDs",
            ),
            (
                ("scenarios", 0, "affectedEdges"),
                {"ab": True},
                "affectedEdges must be an array of string IDs",
            ),
            (
                ("scenarios", 0, "controls", 0, "nodes"),
                "ab",
                "nodes must be an array of string IDs",
            ),
            (
                ("scenarios", 0, "controls", 0, "edges"),
                ["ab", None],
                "edges must be an array of string IDs",
            ),
        ]
        for path, value, message in cases:
            with self.subTest(path=path):
                model = copy.deepcopy(self.model)
                target = model
                for key in path[:-1]:
                    target = target[key]
                if value is missing:
                    del target[path[-1]]
                else:
                    target[path[-1]] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.check(model)

        self.model["nodes"][0]["title"] = None
        self.build_html(b"policy denies this caller", error="a.title must be a string")

    def test_builder_rejects_output_aliasing_either_input(self):
        for input_name in ("model", "assessment"):
            for alias in ("direct", "symlink", "hardlink"):
                with (
                    self.subTest(input=input_name, alias=alias),
                    tempfile.TemporaryDirectory() as folder,
                ):
                    folder = Path(folder)
                    inputs = {
                        "model": folder / "model.json",
                        "assessment": folder / "assessment.md",
                    }
                    inputs["model"].write_text(json.dumps(self.model), encoding="utf-8")
                    inputs["assessment"].write_text("policy denies this caller", encoding="utf-8")
                    original = {name: path.read_bytes() for name, path in inputs.items()}
                    target = inputs[input_name]
                    output = target if alias == "direct" else folder / "output.html"
                    if alias == "symlink":
                        try:
                            output.symlink_to(target)
                        except OSError as error:
                            self.skipTest(
                                f"creating a symbolic link requires host support: {error}"
                            )
                    elif alias == "hardlink":
                        output.hardlink_to(target)
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(Path(builder.__file__)),
                            str(inputs["model"]),
                            "--assessment",
                            str(inputs["assessment"]),
                            "--output",
                            str(output),
                        ],
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("output must not overwrite", result.stderr)
                    for name, path in inputs.items():
                        self.assertEqual(path.read_bytes(), original[name])

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
            (("evidence", 0, "quote"), "\ud800", "quotation is not exact"),
            (("scenarios", 0, "steps", 0, "to"), "c", "step edge does not connect"),
            (effect + ("step",), 2, "must match"),
            (effect + ("edge",), "missing", "unresolved effect edge"),
            (marker, None, "blocking needs a step and marker"),
            (marker, [], "marker must be an object"),
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
            with self.subTest(path=path, value=message if len(path) == 1 else value):
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
        self.effect().update(outcome="detects", marker=None)
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

    def test_connector_warnings_distinguish_bent_legs_and_node_interiors(self):
        ab, bc = self.model["edges"]
        ab["points"] = [[100, 130], [100, 130], [150, 127], [150, 150], [200, 152]]
        bc["points"] = [[300, 130], [380, 130], [420, 130], [420, 160]]
        self.assertEqual(
            list(builder.connector_warnings(self.model)),
            [
                "ab: diagonal source leg meets an axis-aligned segment. Check the adjacent bend.",
                "ab: diagonal destination leg meets an axis-aligned segment. Check the adjacent bend.",
                "bc: enters node c. Route outside its box.",
            ],
        )
        # Two direct diagonals cross in the gap, touching the boxes only at their ports.
        ab["points"] = [[100, 100], [200, 160]]
        self.model["nodes"][2].update(x=0, y=200)
        bc["points"] = [[200, 100], [100, 200]]
        self.assertEqual(list(builder.connector_warnings(self.model)), [])

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
        assessment = "policy denies this caller"
        html = self.build_html(assessment.encode("utf-8"))
        assets = Path(builder.__file__).parents[1] / "assets"
        expected = [
            "control-effects.js",
            "route-paths.js",
            "source-roles.js",
            "svg-layout.js",
            "explorer.js",
        ]
        for closing_space in ("", " \t\n"):
            with self.subTest(closing_space=repr(closing_space)):
                document = html.replace("</script>", f"</script{closing_space}>").replace(
                    "</style>", f"</style{closing_space}>"
                )
                elements = EmbeddedHtml(document).elements
                scripts = [
                    code
                    for tag, attrs, code in elements
                    if tag == "script" and (attrs.get("type") or "").lower() != "application/json"
                ]
                self.assertEqual(
                    [script.strip() for script in scripts],
                    [(assets / name).read_text(encoding="utf-8").strip() for name in expected],
                )
                self.assertEqual(
                    [code.strip() for tag, _, code in elements if tag == "style"],
                    [(assets / "explorer.css").read_text(encoding="utf-8").strip()],
                )
                self.assertFalse(
                    any(tag == "script" and "src" in attrs for tag, attrs, _ in elements)
                )
                self.assertEqual(self.embedded_data(document, "model-data"), self.model)
                self.assertEqual(self.embedded_data(document, "assessment-data"), assessment)

    def test_template_tokens_in_input_are_preserved_without_resubstitution(self):
        tokens = "__MODEL_JSON__ __ASSESSMENT_JSON__ __EXPLORER_JS__ __EXPLORER_CSS__"
        assessment = (
            "\ufeffpolicy denies this caller\n"
            + tokens
            + "\n</script><script>unsafe()</script> & café"
        )
        self.model["title"] = tokens
        self.model["metadata"] = [{"label": "Scope", "value": "Quoted tokens"}]
        self.model["evidence"][0]["quote"] = assessment
        html = self.build_html(assessment.encode("utf-8"), model_encoding="utf-8-sig")
        self.assertEqual(self.embedded_data(html, "model-data"), self.model)
        self.assertEqual(self.embedded_data(html, "assessment-data"), assessment)
        self.assertNotIn("</script><script>unsafe()</script>", html)

    def test_utf8_assessment_hash_and_ranged_quote_preserve_line_endings(self):
        non_line_breaks = "\v\f\x1c\x1d\x1e\x85\u2028\u2029"
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=repr(newline)):
                quote = f"policy denies this caller{newline}Details: 日本語"
                assessment = f"Context: café{non_line_breaks}continued{newline}{quote}{newline}"
                assessment_bytes = assessment.encode("utf-8")
                evidence = self.model["evidence"][0]
                evidence.update(quote=quote, startLine=2, endLine=3)
                self.model["assessmentSha256"] = hashlib.sha256(assessment_bytes).hexdigest()
                html = self.build_html(assessment_bytes)
                self.assertEqual(self.embedded_data(html, "assessment-data"), assessment)
                evidence["endLine"] = 2
                with self.assertRaisesRegex(ValueError, "quotation outside stated range"):
                    builder.validate(self.model, assessment_bytes)
                # str.splitlines() incorrectly counts eight extra lines in the context.
                evidence.update(startLine=10, endLine=11)
                with self.assertRaisesRegex(ValueError, "invalid assessment line range"):
                    builder.validate(self.model, assessment_bytes)

    def test_builder_reports_invalid_utf8_before_checking_quotes(self):
        self.build_html(b"x" * 8192 + b"\xff", error="byte 0xff in position 8192")

    def test_assessment_hash_does_not_accept_newline_normalization(self):
        assessment = b"policy denies this caller\r\n"
        self.model["assessmentSha256"] = hashlib.sha256(
            assessment.replace(b"\r\n", b"\n")
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "Assessment SHA256 mismatch"):
            builder.validate(self.model, assessment)

    def test_effect_edge_honors_source_and_route_intersection(self):
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

        # A detector attached to an edge only runs on routes that use it.
        self.effect().pop("traffic")
        self.effect()["outcome"] = "detects"
        with self.assertRaisesRegex(ValueError, "each applicable route"):
            self.check()
        control["routeIds"] = ["r"]
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

    def test_unordered_effect_honors_each_source_relationship_override(self):
        source = self.origin()
        scenario = self.model["scenarios"][0]
        second = dict(source, id="second", node="b")
        scenario["sources"].append(second)
        scenario["sourceMode"] = "alternatives"
        scenario["steps"] = []
        control = scenario["controls"][0]
        effect = self.effect()
        effect.pop("step")
        cases = [
            (["ab"], ["bc"], ["second"], "ab", "blocks", False),
            ([], ["bc"], ["second"], "bc", "detects", True),
            (["ab"], [], ["second"], "ab", "blocks", False),
            (["ab"], None, ["second"], "ab", "blocks", True),
            (["ab"], ["bc"], None, "ab", "blocks", False),
            (["ab", "bc"], ["bc"], None, "bc", "detects", True),
        ]
        for shared, related, source_ids, edge, outcome, valid in cases:
            with self.subTest(shared=shared, related=related, sources=source_ids, edge=edge):
                scenario["affectedEdges"] = shared
                second.pop("relatedEdges", None)
                if related is not None:
                    second["relatedEdges"] = related
                control.pop("sourceIds", None)
                if source_ids is not None:
                    control["sourceIds"] = source_ids
                effect.update(edge=edge, outcome=outcome)
                effect.pop("traffic", None)
                if outcome == "blocks":
                    effect["traffic"] = "continues"
                if valid:
                    self.check()
                else:
                    with self.assertRaisesRegex(ValueError, "effect edge"):
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
