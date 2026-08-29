"""Shared eval fixtures.

Builds a fresh server, autoloads every real tool module, and explicitly
registers the _example fixture module so the contract evals always have at
least one tool even before any real module lands. Tool metadata comes from the
server's own async list_tools(), so the evals test exactly what MCP clients see.
"""

import importlib
import inspect
import os
import pkgutil

import anyio
import pytest

from aws_audit_mcp import tools as tools_pkg
from aws_audit_mcp.server import MCPServer, load_tools
from aws_audit_mcp.tools import _example

# Dummy credentials and region so boto3 never touches the network; moto
# intercepts everything at the client layer.
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ.pop("AWS_PROFILE", None)


def _build_server() -> MCPServer:
    server = MCPServer(name="aws-audit-mcp-evals")
    load_tools(server)
    _example.register(server)
    return server


def _tool_functions(tool_names: set[str]) -> list:
    """The plain Python functions behind the registered tools.

    Contract tests call these directly inside mock_aws, bypassing the MCP
    transport, so envelope checks see the raw return values.
    """
    modules = [_example]
    for info in pkgutil.iter_modules(tools_pkg.__path__):
        if not info.name.startswith("_"):
            modules.append(importlib.import_module(f"{tools_pkg.__name__}.{info.name}"))
    fns = []
    for module in modules:
        for name, obj in inspect.getmembers(module, inspect.isfunction):
            if name in tool_names:
                fns.append(obj)
    return sorted(fns, key=lambda f: f.__name__)


def pytest_configure(config):
    server = _build_server()
    tools = anyio.run(server.list_tools)
    config._audit_server = server
    config._audit_tools = tools
    config._audit_tool_fns = _tool_functions({t.name for t in tools})


@pytest.fixture(scope="session")
def server(request):
    return request.config._audit_server


@pytest.fixture(scope="session")
def registered_tool_names(request):
    return {t.name for t in request.config._audit_tools}
