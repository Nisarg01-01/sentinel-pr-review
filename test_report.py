import os
import sys
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.identity import DefaultAzureCredential
from src.github_client import GitHubClient
from src.agents.vuln_agent import run_vuln_scan
from src.agents.drift_agent import run_drift_check
from src.agents.standards_agent import run_standards_check
from src.agents.report_agent import synthesise_review, format_findings_for_github

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

print("Running all agents...")
vuln = run_vuln_scan(client, diff, os.environ["GITHUB_REPO"])
drift = run_drift_check(client, diff)
quality = run_standards_check(client, diff)

print("Synthesising final review...")
review = synthesise_review(vuln, drift, quality)

print(f"\nFinal verdict:  {review.recommendation}")
print(f"Severity:       {review.overall_severity}")
print(f"Quality score:  {review.quality_score}/100")
print(f"Action items:   {len(review.action_items)}")

print("\n--- GitHub PR Comment Preview ---\n")
comment = format_findings_for_github(review)
print(comment)

print("\nDay 8 complete!")
