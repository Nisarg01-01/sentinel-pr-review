import os
import requests


class MCPClient:
    def __init__(self):
        self._url = os.environ["MCP_FUNCTION_URL"]
        self._key = os.environ["MCP_FUNCTION_KEY"]

    def _call(self, tool: str, params: dict) -> dict:
        response = requests.post(
            self._url,
            params={"code": self._key},
            json={"tool": tool, "params": params},
            timeout=30,
        )
        response.raise_for_status()
        body = response.json()
        if "error" in body:
            raise RuntimeError(f"MCP tool '{tool}' failed: {body['error']}")
        return body["result"]

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
