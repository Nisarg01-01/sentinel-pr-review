import os
import sys
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.identity import DefaultAzureCredential
from src.github_client import GitHubClient
from src.agents.triage_agent import run_triage

load_dotenv()

inference_endpoint = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0] + "/models"
client = ChatCompletionsClient(
    endpoint=inference_endpoint,
    credential=DefaultAzureCredential(),
    credential_scopes=["https://cognitiveservices.azure.com/.default"],
)

gh = GitHubClient()
PR_NUMBER = int(sys.argv[1]) if len(sys.argv) > 1 else 1

metadata = gh.get_pr_metadata(PR_NUMBER)
diff = gh.get_pr_diff(PR_NUMBER)

print("Running Triage Agent...")
decision = run_triage(client, metadata, diff)

print(f"\nTriage Decision:")
print(f"  Run vuln scan:      {decision.should_run_vuln_scan}")
print(f"  Run drift check:    {decision.should_run_drift_check}")
print(f"  Run standards check:{decision.should_run_standards_check}")
print(f"  Risk level:         {decision.risk_level}")
print(f"  Reason:             {decision.reason}")
print("\nDay 4 complete!")
