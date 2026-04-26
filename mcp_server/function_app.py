import json
import os
import azure.functions as func
from github import Github, GithubException

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def _github_client():
    return Github(os.environ["GITHUB_TOKEN"])


@app.route(route="mcp", methods=["POST"])
def mcp_server(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return _error("Invalid JSON body", 400)

    tool = body.get("tool")
    params = body.get("params", {})

    handlers = {
        "list_tools": _list_tools,
        "get_pr_diff": _get_pr_diff,
        "get_pr_metadata": _get_pr_metadata,
        "get_file_content": _get_file_content,
        "post_review_comment": _post_review_comment,
        "post_inline_comment": _post_inline_comment,
    }

    if tool not in handlers:
        return _error(f"Unknown tool: {tool}. Call list_tools to see available tools.", 400)

    try:
        result = handlers[tool](params)
        return func.HttpResponse(
            json.dumps({"result": result}),
            mimetype="application/json",
        )
    except KeyError as e:
        return _error(f"Missing required parameter: {e}", 400)
    except GithubException as e:
        return _error(f"GitHub API error: {e.data.get('message', str(e))}", e.status)
    except Exception as e:
        return _error(str(e), 500)


def _error(message: str, status: int) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=status,
        mimetype="application/json",
    )


def _list_tools(params: dict) -> list:
    return [
        {
            "name": "get_pr_diff",
            "description": "Get the full diff for a pull request, file by file",
            "params": {"repo": "owner/repo", "pr_number": "integer"},
        },
        {
            "name": "get_pr_metadata",
            "description": "Get PR title, author, branch names, changed files, additions/deletions",
            "params": {"repo": "owner/repo", "pr_number": "integer"},
        },
        {
            "name": "get_file_content",
            "description": "Get the full content of a file at the PR head commit",
            "params": {"repo": "owner/repo", "pr_number": "integer", "path": "file path"},
        },
        {
            "name": "post_review_comment",
            "description": "Post a review on a PR — APPROVE, REQUEST_CHANGES, or COMMENT",
            "params": {"repo": "owner/repo", "pr_number": "integer", "body": "markdown string", "event": "APPROVE|REQUEST_CHANGES|COMMENT"},
        },
        {
            "name": "post_inline_comment",
            "description": "Post a review comment at a specific line in a specific file",
            "params": {"repo": "owner/repo", "pr_number": "integer", "path": "file path", "line": "integer", "body": "string"},
        },
    ]


def _get_pr_diff(params: dict) -> dict:
    repo = _github_client().get_repo(params["repo"])
    pr = repo.get_pull(int(params["pr_number"]))

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


def _get_pr_metadata(params: dict) -> dict:
    repo = _github_client().get_repo(params["repo"])
    pr = repo.get_pull(int(params["pr_number"]))
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


def _get_file_content(params: dict) -> dict:
    repo = _github_client().get_repo(params["repo"])
    pr = repo.get_pull(int(params["pr_number"]))

    try:
        content = repo.get_contents(params["path"], ref=pr.head.sha)
        return {
            "path": params["path"],
            "content": content.decoded_content.decode("utf-8"),
            "size": content.size,
        }
    except GithubException as e:
        return {"path": params["path"], "error": f"Could not retrieve file: {e.data.get('message', str(e))}"}


def _post_review_comment(params: dict) -> dict:
    repo = _github_client().get_repo(params["repo"])
    pr = repo.get_pull(int(params["pr_number"]))
    event = params.get("event", "COMMENT")

    try:
        pr.create_review(body=params["body"], event=event)
    except GithubException as e:
        if e.status == 422:
            pr.create_review(body=params["body"], event="COMMENT")
            event = "COMMENT (fallback)"
        else:
            raise

    return {"posted": True, "event": event, "pr_number": pr.number}


def _post_inline_comment(params: dict) -> dict:
    repo = _github_client().get_repo(params["repo"])
    pr = repo.get_pull(int(params["pr_number"]))
    commit = repo.get_commit(pr.head.sha)

    try:
        pr.create_review_comment(
            body=params["body"],
            commit=commit,
            path=params["path"],
            line=int(params["line"]),
        )
        return {"posted": True, "path": params["path"], "line": params["line"]}
    except GithubException:
        pr.create_issue_comment(f"**{params['path']}:{params['line']}** — {params['body']}")
        return {"posted": True, "fallback": True, "path": params["path"], "line": params["line"]}
