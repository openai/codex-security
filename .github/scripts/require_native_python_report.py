"""Require at least one test case and zero skipped cases in reports/python.xml."""

from xml.etree import ElementTree

report = ElementTree.parse("reports/python.xml")
if report.find(".//testcase") is None:
    raise SystemExit("No native platform tests ran")
if report.find(".//testcase/skipped") is not None:
    raise SystemExit("Native platform tests must run without skips")
