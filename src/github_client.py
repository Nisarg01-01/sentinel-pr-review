import os
from github import Github, GithubException
from dotenv import load_dotenv

load_dotenv()


class GitHubClient:
    def __init__(self):
        self.client = Github(os.environ["GITHUB_TOKEN"])
        self.repo = self.client.get_repo(os.environ["GITHUB_REPO"])

    def get_pr_diff(self, pr_number: int) -> str:
        pr = self.repo.get_pull(pr_number)
        files = pr.get_files()

        diff_parts = []
        for file in files:
            diff_parts.append(f"--- File: {file.filename} ---")
            diff_parts.append(f"Status: {file.status}")
            diff_parts.append(f"Additions: {file.additions}, Deletions: {file.deletions}")
            if file.patch:
                diff_parts.append(file.patch)
            diff_parts.append("")

        return "\n".join(diff_parts)

    def get_pr_metadata(self, pr_number: int) -> dict:
        pr = self.repo.get_pull(pr_number)
        files = pr.get_files()
        file_extensions = list(set(
            f.filename.split(".")[-1] for f in files
            if "." in f.filename
        ))

        return {
            "number": pr_number,
            "title": pr.title,
            "description": pr.body or "",
            "author": pr.user.login,
            "base_branch": pr.base.ref,
            "head_branch": pr.head.ref,
            "changed_files": [f.filename for f in files],
            "file_extensions": file_extensions,
            "additions": pr.additions,
            "deletions": pr.deletions,
        }

    def post_review_comment(self, pr_number: int, body: str, event: str = "COMMENT"):
        pr = self.repo.get_pull(pr_number)
        try:
            pr.create_review(body=body, event=event)
            print(f"Posted review to PR #{pr_number} with event: {event}")
        except GithubException as e:
            if "own pull request" in str(e).lower() or e.status == 422:
                # GitHub blocks REQUEST_CHANGES on your own PR — fall back to COMMENT
                pr.create_review(body=body, event="COMMENT")
                print(f"Posted review to PR #{pr_number} with event: COMMENT (fallback — can't request changes on own PR)")
            else:
                raise

    def post_inline_comment(self, pr_number: int, path: str, line: int, body: str):
        pr = self.repo.get_pull(pr_number)
        commit = self.repo.get_commit(pr.head.sha)

        try:
            pr.create_review_comment(
                body=body,
                commit=commit,
                path=path,
                line=line
            )
        except GithubException as e:
            print(f"Inline comment failed, posting as general comment: {e}")
            pr.create_issue_comment(f"**{path}:{line}** — {body}")
