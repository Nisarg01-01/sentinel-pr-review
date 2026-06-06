import json
import os
import azure.functions as func
from github import Github, GithubException

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

TOOLS = [
    {
        "name": "get_pr_diff",
        "description": "Get the full diff for a pull request, file by file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "owner/repo"},
                "pr_number": {"type": "integer"},
            },
            "required": ["repo", "pr_number"],
        },
    },
    {
        "name": "get_pr_metadata",
        "description": "Get PR title, author, branch names, changed files, additions/deletions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "pr_number": {"type": "integer"},
            },
            "required": ["repo", "pr_number"],
        },
    },
    {
        "name": "get_file_content",
        "description": "Get the full content of a file at the PR head commit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "pr_number": {"type": "integer"},
                "path": {"type": "string"},
            },
            "required": ["repo", "pr_number", "path"],
        },
    },
    {
        "name": "post_review_comment",
        "description": "Post a review on a PR — APPROVE, REQUEST_CHANGES, or COMMENT.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "pr_number": {"type": "integer"},
                "body": {"type": "string"},
                "event": {"type": "string", "enum": ["APPROVE", "REQUEST_CHANGES", "COMMENT"]},
            },
            "required": ["repo", "pr_number", "body"],
        },
    },
    {
        "name": "post_inline_comment",
        "description": "Post a review comment at a specific line in a specific file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "pr_number": {"type": "integer"},
                "path": {"type": "string"},
                "line": {"type": "integer"},
                "body": {"type": "string"},
            },
            "required": ["repo", "pr_number", "path", "line", "body"],
        },
    },
]


def _github_client() -> Github:
    return Github(os.environ["GITHUB_TOKEN"])


def _json_response(data: dict, status: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(data),
        status_code=status,
        mimetype="application/json",
    )


def _mcp_error(req_id, code: int, message: str) -> func.HttpResponse:
    return _json_response({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    })


def _mcp_result(req_id, result: dict) -> func.HttpResponse:
    return _json_response({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    })


@app.route(route="mcp", methods=["POST"])
def mcp_server(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return _json_response({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, 400)

    req_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    # MCP handshake
    if method == "initialize":
        return _mcp_result(req_id, {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "sentinel-mcp", "version": "1.0.0"},
        })

    if method == "notifications/initialized":
        return _json_response({}, 200)

    if method == "tools/list":
        return _mcp_result(req_id, {"tools": TOOLS})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        try:
            result = _dispatch(tool_name, arguments)
            return _mcp_result(req_id, {
                "content": [{"type": "text", "text": json.dumps(result)}],
                "isError": False,
            })
        except KeyError as e:
            return _mcp_error(req_id, -32602, f"Missing required argument: {e}")
        except GithubException as e:
            return _mcp_error(req_id, -32603, f"GitHub API error: {e.data.get('message', str(e))}")
        except Exception as e:
            return _mcp_error(req_id, -32603, str(e))

    return _mcp_error(req_id, -32601, f"Method not found: {method}")


def _dispatch(tool_name: str, args: dict):
    handlers = {
        "get_pr_diff": _get_pr_diff,
        "get_pr_metadata": _get_pr_metadata,
        "get_file_content": _get_file_content,
        "post_review_comment": _post_review_comment,
        "post_inline_comment": _post_inline_comment,
    }
    if tool_name not in handlers:
        raise ValueError(f"Unknown tool: {tool_name}")
    return handlers[tool_name](args)


def _get_pr_diff(args: dict) -> dict:
    gh_repo = _github_client().get_repo(args["repo"])
    pr = gh_repo.get_pull(int(args["pr_number"]))

    files = []
    for f in pr.get_files():
        files.append({
            "filename": f.filename,
            "status": f.status,
            "additions": f.additions,
            "deletions": f.deletions,
            "patch": f.patch or "",
        })

    return {
        "pr_number": pr.number,
        "title": pr.title,
        "files": files,
        "total_additions": pr.additions,
        "total_deletions": pr.deletions,
    }


def _get_pr_metadata(args: dict) -> dict:
    gh_repo = _github_client().get_repo(args["repo"])
    pr = gh_repo.get_pull(int(args["pr_number"]))
    files = list(pr.get_files())

    return {
        "number": pr.number,
        "title": pr.title,
        "description": pr.body or "",
        "author": pr.user.login,
        "base_branch": pr.base.ref,
        "head_branch": pr.head.ref,
        "changed_files": [f.filename for f in files],
        "file_extensions": list({f.filename.split(".")[-1] for f in files if "." in f.filename}),
        "additions": pr.additions,
        "deletions": pr.deletions,
    }


def _get_file_content(args: dict) -> dict:
    gh_repo = _github_client().get_repo(args["repo"])
    pr = gh_repo.get_pull(int(args["pr_number"]))

    try:
        content = gh_repo.get_contents(args["path"], ref=pr.head.sha)
        return {
            "path": args["path"],
            "content": content.decoded_content.decode("utf-8"),
            "size": content.size,
        }
    except GithubException as e:
        return {"path": args["path"], "error": f"Could not retrieve file: {e.data.get('message', str(e))}"}


def _post_review_comment(args: dict) -> dict:
    gh_repo = _github_client().get_repo(args["repo"])
    pr = gh_repo.get_pull(int(args["pr_number"]))
    event = args.get("event", "COMMENT")

    try:
        pr.create_review(body=args["body"], event=event)
    except GithubException as e:
        if e.status == 422:
            pr.create_review(body=args["body"], event="COMMENT")
            event = "COMMENT (fallback)"
        else:
            raise

    return {"posted": True, "event": event, "pr_number": pr.number}


def _post_inline_comment(args: dict) -> dict:
    gh_repo = _github_client().get_repo(args["repo"])
    pr = gh_repo.get_pull(int(args["pr_number"]))
    commit = gh_repo.get_commit(pr.head.sha)

    try:
        pr.create_review_comment(
            body=args["body"],
            commit=commit,
            path=args["path"],
            line=int(args["line"]),
        )
        return {"posted": True, "path": args["path"], "line": args["line"]}
    except GithubException:
        pr.create_issue_comment(f"**{args['path']}:{args['line']}** — {args['body']}")
        return {"posted": True, "fallback": True, "path": args["path"], "line": args["line"]}
