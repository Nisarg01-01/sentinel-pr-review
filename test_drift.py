import os
import sys
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.identity import DefaultAzureCredential
from src.github_client import GitHubClient
from src.agents.drift_agent import run_drift_check

load_dotenv()

inference_endpoint = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0] + "/models"
client = ChatCompletionsClient(
    endpoint=inference_endpoint,
    credential=DefaultAzureCredential(),
    credential_scopes=["https://cognitiveservices.azure.com/.default"],
)

gh = GitHubClient()
PR_NUMBER = int(sys.argv[1]) if len(sys.argv) > 1 else 1

diff = gh.get_pr_diff(PR_NUMBER)

print("Running Drift Agent...")
report = run_drift_check(client, diff)

print(f"\nDrift Report:")
print(f"  Summary: {report.summary}")
print(f"  ADRs checked: {report.adr_references}")
print(f"  Violations: {len(report.violations)}")
for v in report.violations:
    print(f"\n  [{v.severity}] {v.title}")
    print(f"    File: {v.file_path}:{v.line_number}")
    print(f"    {v.description}")
    print(f"    Fix: {v.recommendation}")

print("\nDay 6 complete!")
