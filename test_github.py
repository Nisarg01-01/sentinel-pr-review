import sys
from src.github_client import GitHubClient

gh = GitHubClient()

PR_NUMBER = int(sys.argv[1]) if len(sys.argv) > 1 else 1

try:
    metadata = gh.get_pr_metadata(PR_NUMBER)
    print("PR Metadata:")
    for k, v in metadata.items():
        print(f"  {k}: {v}")

    diff = gh.get_pr_diff(PR_NUMBER)
    print(f"\nDiff length: {len(diff)} characters")
    print("First 500 chars of diff:")
    print(diff[:500])
    print("\nDay 2 complete — GitHub integration working!")
except Exception as e:
    print(f"Error: {e}")
    print("Make sure GITHUB_TOKEN and GITHUB_REPO are set in .env")
    print("And that the PR number exists in your repo")
