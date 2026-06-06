import os
import json
import requests


class MCPClient:
    """MCP client using Streamable HTTP transport (MCP spec 2025-03-26).

    Sends JSON-RPC 2.0 requests to the Azure Function MCP server.
    Each tool call is one stateless POST — no SSE session required for
    request/response tools.
    """

    def __init__(self):
        self._url = os.environ["MCP_FUNCTION_URL"]
        self._key = os.environ["MCP_FUNCTION_KEY"]
        self._seq = 0

    def _call(self, tool: str, params: dict) -> dict:
        self._seq += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._seq,
            "method": "tools/call",
            "params": {"name": tool, "arguments": params},
        }
        response = requests.post(
            self._url,
            params={"code": self._key},
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            timeout=30,
        )
        response.raise_for_status()
        body = response.json()

        if "error" in body:
            raise RuntimeError(f"MCP tool '{tool}' failed: {body['error']['message']}")

        content = body.get("result", {}).get("content", [])
        if content and content[0].get("type") == "text":
            return json.loads(content[0]["text"])
        return body.get("result", {})

    def get_pr_metadata(self, pr_number: int) -> dict:
        return self._call("get_pr_metadata", {
            "repo": os.environ["GITHUB_REPO"],
            "pr_number": pr_number,
        })

    def get_pr_diff(self, pr_number: int) -> str:
        result = self._call("get_pr_diff", {
            "repo": os.environ["GITHUB_REPO"],
            "pr_number": pr_number,
        })
        parts = []
        for f in result["files"]:
            parts.append(f"--- File: {f['filename']} ---")
            parts.append(f"Status: {f['status']}")
            parts.append(f"Additions: {f['additions']}, Deletions: {f['deletions']}")
            if f["patch"]:
                parts.append(f["patch"])
            parts.append("")
        return "\n".join(parts)

    def post_review_comment(self, pr_number: int, body: str, event: str = "COMMENT"):
        self._call("post_review_comment", {
            "repo": os.environ["GITHUB_REPO"],
            "pr_number": pr_number,
            "body": body,
            "event": event,
        })
        print(f"Posted review to PR #{pr_number} with event: {event}")

    def post_inline_comment(self, pr_number: int, path: str, line: int, body: str):
        self._call("post_inline_comment", {
            "repo": os.environ["GITHUB_REPO"],
            "pr_number": pr_number,
            "path": path,
            "line": line,
            "body": body,
        })
