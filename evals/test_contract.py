"""Contract evals: every registered tool must honor the shared contract.

These tests parametrize over whatever is actually registered on the server, so
the suite is green with only the _example fixture and gets stronger for free as
real tool modules merge in.
"""

import inspect
import re
from pathlib import Path

import pytest
from moto import mock_aws

from aws_audit_mcp.common import SEVERITIES

TOOLS_DIR = Path(__file__).resolve().parents[1] / "src" / "aws_audit_mcp" / "tools"

NAME_PATTERN = re.compile(r"^(audit_|account_|example_)")

# Any call to a boto3 method starting with a mutating verb. Matching on source
# text makes the read-only promise machine-checked: a tool module cannot merge
# a mutation without this eval going red.
MUTATING_CALL = re.compile(
    r"\.(create_|put_|delete_|update_|attach_|detach_|start_|stop_|terminate_"
    r"|authorize_|revoke_|enable_|disable_|modify_)\w+\("
)


def _tool_ids(tools):
    return [t.name for t in tools]


def pytest_generate_tests(metafunc):
    if "tool" in metafunc.fixturenames:
        tools = metafunc.config._audit_tools
        metafunc.parametrize("tool", tools, ids=_tool_ids(tools))
    if "tool_fn" in metafunc.fixturenames:
        fns = metafunc.config._audit_tool_fns
        metafunc.parametrize("tool_fn", fns, ids=[f.__name__ for f in fns])
    if "module_path" in metafunc.fixturenames:
        paths = sorted(p for p in TOOLS_DIR.glob("*.py") if not p.name.startswith("_"))
        metafunc.parametrize("module_path", paths, ids=[p.name for p in paths])


def test_annotations_read_only(tool):
    """MCP clients must see an explicit read-only, non-destructive declaration."""
    assert tool.annotations is not None, f"{tool.name} has no annotations"
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.destructive_hint is False


def test_description_is_real(tool):
    """Agents pick tools by description; a stub docstring is a broken tool."""
    desc = tool.description or ""
    assert len(desc) >= 80, f"{tool.name} description too short ({len(desc)} chars)"
    assert "findings" in desc.lower(), f"{tool.name} description does not mention findings"


def test_name_discipline(tool):
    assert NAME_PATTERN.match(tool.name), f"{tool.name} violates naming discipline"


def test_params_typed_with_defaults(tool_fn):
    """Every parameter needs a type and a default so agents can call with no args."""
    sig = inspect.signature(tool_fn)
    for name, param in sig.parameters.items():
        assert param.annotation is not inspect.Parameter.empty, (
            f"{tool_fn.__name__} parameter {name!r} has no type annotation"
        )
        assert param.default is not inspect.Parameter.empty, (
            f"{tool_fn.__name__} parameter {name!r} has no default"
        )


def test_returns_report_envelope(tool_fn):
    """Called with no args against a mocked (empty) account, every tool must
    return the report() envelope with internally consistent fields."""
    with mock_aws():
        result = tool_fn()
    assert isinstance(result, dict), f"{tool_fn.__name__} did not return a dict"
    for key in ("check", "ok", "findings", "scanned"):
        assert key in result, f"{tool_fn.__name__} envelope missing {key!r}"
    assert result["ok"] == (result["findings"] == [])
    assert isinstance(result["scanned"], int)
    for f in result["findings"]:
        for key in ("check", "severity", "title", "resource", "detail"):
            assert key in f, f"finding from {tool_fn.__name__} missing {key!r}"
        assert f["severity"] in SEVERITIES


def test_source_has_no_mutating_calls(module_path):
    """Machine-checked read-only guarantee over every real tool module's source."""
    source = module_path.read_text()
    hits = MUTATING_CALL.findall(source)
    assert not hits, f"{module_path.name} contains mutating boto3 calls: {hits}"


def test_at_least_one_tool_registered(registered_tools):
    assert registered_tools, "no tools registered; the eval fixture should always be present"


@pytest.fixture
def registered_tools(request):
    return request.config._audit_tools
