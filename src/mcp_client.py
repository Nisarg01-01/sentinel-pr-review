import os
import json
import requests
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceNotFoundError


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
        self._table_client = None

    def _get_table_client(self):
        if self._table_client is None:
            conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
            if conn_str:
                service = TableServiceClient.from_connection_string(conn_str)
                try:
                    service.create_table_if_not_exists("sentinelmemory")
                except Exception:
                    pass
                self._table_client = service.get_table_client("sentinelmemory")
        return self._table_client

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
            timeout=60,
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

    def get_file_content(self, file_path: str, pr_number: int) -> str:
        result = self._call("get_file_content", {
            "repo": os.environ["GITHUB_REPO"],
            "path": file_path,
            "pr_number": pr_number,
        })
        return result.get("content", "")

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

    # --- Memory layer ---

    def is_known_false_positive(self, repo: str, file_path: str, pattern_type: str) -> bool:
        """Returns True if this finding pattern was previously dismissed as a false positive."""
        tc = self._get_table_client()
        if tc is None:
            return False
        try:
            row_key = f"{file_path}#{pattern_type}".replace("/", "_")
            entity = tc.get_entity(partition_key=repo.replace("/", "_"), row_key=row_key)
            return entity.get("false_positive_count", 0) >= 2
        except ResourceNotFoundError:
            return False
        except Exception:
            return False

    def record_finding(self, repo: str, file_path: str, pattern_type: str, was_false_positive: bool):
        """Records a finding outcome to build memory over time."""
        tc = self._get_table_client()
        if tc is None:
            return
        try:
            partition_key = repo.replace("/", "_")
            row_key = f"{file_path}#{pattern_type}".replace("/", "_")
            try:
                entity = tc.get_entity(partition_key=partition_key, row_key=row_key)
            except ResourceNotFoundError:
                entity = {
                    "PartitionKey": partition_key,
                    "RowKey": row_key,
                    "false_positive_count": 0,
                    "true_positive_count": 0,
                }
            if was_false_positive:
                entity["false_positive_count"] = entity.get("false_positive_count", 0) + 1
            else:
                entity["true_positive_count"] = entity.get("true_positive_count", 0) + 1
            tc.upsert_entity(entity)
        except Exception:
            pass
