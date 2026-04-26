import os
import sys
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.identity import DefaultAzureCredential
from src.github_client import GitHubClient
from src.agents.vuln_agent import run_vuln_scan

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

print("Running Vulnerability Agent...")
report = run_vuln_scan(client, diff, os.environ["GITHUB_REPO"])

print(f"\nVuln Report:")
print(f"  Has critical: {report.has_critical}")
print(f"  Summary: {report.summary}")
print(f"  Findings: {len(report.findings)}")
for f in report.findings:
    print(f"\n  [{f.severity}] {f.title}")
    print(f"    File: {f.file_path}:{f.line_number}")
    print(f"    {f.description}")
    print(f"    Fix: {f.recommendation}")

print("\nDay 5 complete!")
