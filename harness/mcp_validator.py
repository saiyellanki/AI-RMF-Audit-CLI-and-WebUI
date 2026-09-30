Tool Schema & Privilege Escalation Interceptor for agent-sandbox-harness)
This module validates that an autonomous agent attempting Model Context Protocol (MCP) tool execution stays strictly within its assigned JSON schema and role permissions.
"""
agent-sandbox-harness: MCP Tool Schema & Privilege Boundary Interceptor
Author: Sai Yellanki, MSc, CISA, ISO/IEC 27001 Lead Auditor
Description: Enforces strict Model Context Protocol (MCP) privilege boundaries
             and intercept unpermitted tool invocations.
"""

import json
from typing import Dict, Any, List

class MCPBoundaryValidator:
    """Intercepts and validates agentic MCP tool execution against explicit privilege manifests."""

    def __init__(self, manifest_path: str):
        with open(manifest_path, "r") as f:
            self.manifest = json.load(f)
        self.allowed_tools: List[str] = self.manifest.get("allowed_mcp_tools", [])
        self.forbidden_parameters: List[str] = self.manifest.get("forbidden_parameters", [])

    def validate_tool_invocation(self, tool_call: Dict[str, Any]) -> tuple[bool, str]:
        """Validates tool name, parameters, and privilege scope."""
        tool_name = tool_call.get("tool_name")
        parameters = tool_call.get("parameters", {})

        # 1. Check if the tool is explicitly whitelisted
        if tool_name not in self.allowed_tools:
            return False, f"PRIVILEGE_VIOLATION: Tool '{tool_name}' is not allowed by MCP manifest."

        # 2. Inspect parameters for unauthorized file paths or command injections
        param_str = json.dumps(parameters)
        for forbidden in self.forbidden_parameters:
            if forbidden in param_str:
                return False, f"SECURITY_VIOLATION: Forbidden keyword '{forbidden}' detected in parameter scope."

        return True, "AUTHORIZED"


if __name__ == "__main__":
    # Example MCP Agent Manifest
    manifest_data = {
        "agent_id": "customer_support_agent_01",
        "allowed_mcp_tools": ["read_kb_article", "search_product_catalog"],
        "forbidden_parameters": ["../", "/etc/passwd", "DROP TABLE", "rm -rf"]
    }
    
    import tempfile
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
        json.dump(manifest_data, tmp)
        tmp_path = tmp.name

    validator = MCPBoundaryValidator(tmp_path)

    # Test Case 1: Valid Execution
    valid, msg = validator.validate_tool_invocation({
        "tool_name": "read_kb_article",
        "parameters": {"article_id": "10492"}
    })
    print(f"Test 1 (Valid Tool): {valid} -> {msg}")

    # Test Case 2: Unpermitted Tool Execution Attempt
    valid, msg = validator.validate_tool_invocation({
        "tool_name": "execute_shell_command",
        "parameters": {"cmd": "ls -la"}
    })
    print(f"Test 2 (Unpermitted Tool): {valid} -> {msg}")

    # Test Case 3: Parameter Traversal Attempt
    valid, msg = validator.validate_tool_invocation({
        "tool_name": "read_kb_article",
        "parameters": {"path": "../../etc/passwd"}
    })
    print(f"Test 3 (Path Traversal): {valid} -> {msg}")
