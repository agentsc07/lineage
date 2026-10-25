import json

from lineage.inspect import tool_description, tool_intent
from tests.fixtures.builders import make_poisoned_tool


def by_id(fs):
    return {f.id: f for f in fs}


def test_benign_tool_is_clean(toy_tool):
    assert tool_description.scan(toy_tool / "manifest.json") == []
    assert tool_intent.scan(toy_tool / "manifest.json", toy_tool) == []


def test_poisoned_description(tmp_path):
    d = make_poisoned_tool(tmp_path / "t")
    fs = by_id(tool_description.scan(d / "manifest.json"))
    inv = fs["TOOL.DESC.INVISIBLE_UNICODE"]
    assert inv.severity == "critical" and "id_rsa" in inv.evidence[0].detail
    instr = [f for f in tool_description.scan(d / "manifest.json") if f.id == "TOOL.DESC.AGENT_INSTRUCTION"]
    assert instr[0].severity == "critical" and instr[0].evidence[0].ref == "manifest.json#description"
    assert fs["TOOL.DESC.MARKDOWN_IMAGE"].evidence[0].detail == "manifest.json#inputSchema.properties.notes.description"


def test_plain_urls_are_low(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"name": "x", "description": "Docs at https://example.com/docs"}))
    [f] = tool_description.scan(p)
    assert f.id == "TOOL.DESC.URL" and f.severity == "low"


def test_ordinary_parameter_advice_is_not_critical(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"name": "x", "description": "Reads a file.",
                             "inputSchema": {"properties": {"path": {"description": "You must pass an absolute path."}}}}))
    fs = tool_description.scan(p)
    assert [f.severity for f in fs] == ["medium"]


def test_unreadable_manifest(tmp_path):
    p = tmp_path / "m.json"
    p.write_text("{nope")
    assert tool_description.scan(p)[0].id == "TOOL.DESC.UNREADABLE"


def test_intent_gap_undeclared_network(tmp_path):
    d = make_poisoned_tool(tmp_path / "t")
    fs = by_id(tool_intent.scan(d / "manifest.json", d))
    f = fs["TOOL.INTENT.UNDECLARED_NETWORK"]
    assert f.severity == "high" and f.evidence[0].ref == "server.py:6"
    assert "TOOL.INTENT.UNDECLARED_ENV_SECRETS" not in fs


def test_declared_permission_closes_the_gap(tmp_path):
    d = make_poisoned_tool(tmp_path / "t", declared=["network:egress"])
    assert tool_intent.scan(d / "manifest.json", d) == []


def test_unused_declaration_is_info_only(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps({"name": "x", "description": "d", "permissions": ["network"]}))
    (d / "server.py").write_text("def f():\n    return 1\n")
    [f] = tool_intent.scan(d / "manifest.json", d)
    assert f.id == "TOOL.INTENT.UNUSED_NETWORK" and f.severity == "info" and f.score == 0
