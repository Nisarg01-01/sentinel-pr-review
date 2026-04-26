import os
import sys
from dotenv import load_dotenv
from azure.ai.agents import AgentsClient
from azure.identity import DefaultAzureCredential

load_dotenv()

client = AgentsClient(
    endpoint=os.environ["PROJECT_ENDPOINT"],
    credential=DefaultAzureCredential(),
)

deployments = ["Phi-4-1", "llama-3.3-70b"]

print("Testing Agents threads/runs support:\n")
for name in deployments:
    sys.stdout.write(f"  {name} ... ")
    sys.stdout.flush()
    try:
        agent = client.create_agent(model=name, name="test", instructions="Reply with: OK")
        thread = client.threads.create()
        client.messages.create(thread_id=thread.id, role="user", content="test")
        run = client.runs.create_and_process(thread_id=thread.id, agent_id=agent.id)
        client.delete_agent(agent.id)
        if str(run.status) == "RunStatus.COMPLETED":
            msgs = list(client.messages.list(thread_id=thread.id))
            reply = next((m.content[0].text.value for m in msgs if str(m.role) == "MessageRole.AGENT"), "no reply")
            print(f"WORKS - reply: {reply}")
        else:
            print(f"FAILED - {run.last_error}")
    except Exception as e:
        print(f"ERROR - {e}")
