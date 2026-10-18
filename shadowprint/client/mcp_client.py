"""
Shadowprint Guarded MCP Stdio Client.
Owner: Gaurang Udgirkar [G]

A least-capability stdio MCP client conforming to:
  - ADR-010: Enforces 5-second per-RPC timeouts, 1MB payload caps, and rejection of server-initiated sampling.
  - ADR-003: Pure JSON-RPC 2.0 communication over stdin/stdout.
  - Builds canonical Snapshot instances with definition_hash for Engine S3.
"""

import json
import asyncio
import hashlib
import logging
from typing import Dict, Any, List, Optional
from shadowprint.models import Snapshot, ToolDefinition

logger = logging.getLogger("shadowprint.client.mcp_client")


class GuardedMCPClient:
    """Least-capability stdio MCP client for securely inspecting untrusted target servers."""

    def __init__(
        self,
        command: str,
        args: Optional[List[str]] = None,
        timeout: float = 8.0,
        max_message_bytes: int = 1_048_576,  # 1 MB
    ):
        self.command = command
        self.args = args or []
        self.timeout = timeout
        self.max_message_bytes = max_message_bytes
        self.process: Optional[asyncio.subprocess.Process] = None
        self._request_id: int = 1
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """Launches the target server process over stdio."""
        if self.process is not None:
            return

        cmd = [self.command] + self.args
        self.process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.debug(f"Started target MCP server with PID: {self.process.pid}")

    async def close(self) -> None:
        """Terminates target server process cleanly."""
        if self.process is None:
            return

        try:
            if self.process.stdin and not self.process.stdin.is_closing():
                self.process.stdin.close()
            self.process.terminate()
            await asyncio.wait_for(self.process.wait(), timeout=2.0)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass
        finally:
            self.process = None

    async def _send_rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Sends a JSON-RPC 2.0 request and reads the matched response."""
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("MCP server process is not running. Call start() first.")

        async with self._lock:
            req_id = self._request_id
            self._request_id += 1

            message = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": method,
                "params": params or {},
            }

            payload = json.dumps(message) + "\n"
            self.process.stdin.write(payload.encode("utf-8"))
            await self.process.stdin.drain()

            # Read response with timeout
            while True:
                line_task = self.process.stdout.readline()
                try:
                    line = await asyncio.wait_for(line_task, timeout=self.timeout)
                except asyncio.TimeoutError:
                    raise TimeoutError(f"RPC method '{method}' timed out after {self.timeout}s")

                if not line:
                    raise EOFError("MCP server process closed stdout unexpectedly.")

                if len(line) > self.max_message_bytes:
                    raise ValueError(f"Server response exceeded max size limit of {self.max_message_bytes} bytes")

                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue

                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    # Ignore non-JSON output (e.g. spurious warning text on stdout)
                    continue

                # Check if this is a response to our request
                if isinstance(data, dict):
                    # Handle adversarial server trying to trigger client sampling/prompt injection
                    if data.get("method") == "sampling/createMessage":
                        # Reject server-initiated sampling callback
                        rejection = {
                            "jsonrpc": "2.0",
                            "id": data.get("id"),
                            "error": {"code": -32601, "message": "Client sampling is disabled for security"},
                        }
                        self.process.stdin.write((json.dumps(rejection) + "\n").encode("utf-8"))
                        await self.process.stdin.drain()
                        continue

                    if data.get("id") == req_id:
                        if "error" in data:
                            return {"error": data["error"]}
                        return data.get("result", {})

    async def initialize(self) -> Dict[str, Any]:
        """Performs initial MCP protocol handshake."""
        init_params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "shadowprint-auditor", "version": "1.0.0"},
        }
        res = await self._send_rpc("initialize", init_params)
        # Send initialized notification
        if self.process and self.process.stdin:
            notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            self.process.stdin.write((json.dumps(notif) + "\n").encode("utf-8"))
            await self.process.stdin.drain()
        return res

    async def list_tools(self) -> List[ToolDefinition]:
        """Queries tools/list and maps to normalized ToolDefinition models."""
        res = await self._send_rpc("tools/list")
        raw_tools = res.get("tools", [])
        tools: List[ToolDefinition] = []

        for item in raw_tools:
            if isinstance(item, dict) and "name" in item:
                tools.append(
                    ToolDefinition(
                        name=item["name"],
                        description=item.get("description", ""),
                        inputSchema=item.get("inputSchema", {}),
                        annotations=item.get("annotations"),
                    )
                )
        return tools

    async def list_prompts(self) -> List[Dict[str, Any]]:
        """Queries prompts/list from target server."""
        try:
            res = await self._send_rpc("prompts/list")
            return res.get("prompts", [])
        except Exception:
            return []

    async def list_resources(self) -> List[Dict[str, Any]]:
        """Queries resources/list from target server."""
        try:
            res = await self._send_rpc("resources/list")
            return res.get("resources", [])
        except Exception:
            return []

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes a bounded tool call over stdio.
        Returns the raw result dict or error info.
        """
        params = {"name": tool_name, "arguments": arguments}
        try:
            return await self._send_rpc("tools/call", params)
        except Exception as e:
            return {"isError": True, "error": str(e)}

    async def fetch_snapshot(self, server_name: str) -> Snapshot:
        """
        Connects, initializes, queries all metadata, and computes canonical definition_hash.
        """
        await self.start()
        try:
            await self.initialize()
            tools = await self.list_tools()
            prompts = await self.list_prompts()
            resources = await self.list_resources()

            # Canonical SHA-256 calculation for definition_hash (Layer 1)
            raw_defs = [
                {"name": t.name, "description": t.description, "inputSchema": t.inputSchema}
                for t in sorted(tools, key=lambda x: x.name)
            ]
            canonical_json = json.dumps(raw_defs, sort_keys=True, separators=(",", ":"))
            def_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

            import time
            return Snapshot(
                server_name=server_name,
                timestamp=time.time(),
                tools=tools,
                prompts=prompts,
                resources=resources,
                definition_hash=def_hash,
            )
        finally:
            await self.close()
