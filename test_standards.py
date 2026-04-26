import os
import sys
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.identity import DefaultAzureCredential
from src.github_client import GitHubClient
from src.agents.standards_agent import run_standards_check

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

print("Running Standards Agent...")
report = run_standards_check(client, diff)

print(f"\nStandards Report:")
print(f"  Score: {report.score}/100")
print(f"  Coverage note: {report.test_coverage_note}")
print(f"  Summary: {report.summary}")
print(f"  Findings: {len(report.findings)}")
for f in report.findings:
    print(f"\n  [{f.severity}] {f.title}")
    print(f"    File: {f.file_path}:{f.line_number}")
    print(f"    {f.description}")
    print(f"    Fix: {f.recommendation}")

print("\nDay 7 complete!")
