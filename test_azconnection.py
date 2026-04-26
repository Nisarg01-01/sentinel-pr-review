import os
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from azure.identity import DefaultAzureCredential

load_dotenv()
inference_endpoint = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0] + "/models"

client = ChatCompletionsClient(
    endpoint=inference_endpoint,
    credential=DefaultAzureCredential(),
    credential_scopes=["https://cognitiveservices.azure.com/.default"],
)

print(f"Endpoint: {inference_endpoint!r}")
print(f"Model: {os.environ['MODEL']!r}")

response = client.complete(
    model=os.environ["MODEL"],
    messages=[
        SystemMessage("You are a helpful assistant. Reply with exactly: CONNECTION_OK"),
        UserMessage("Are you connected?"),
    ],
)

print("Response:", response.choices[0].message.content)
print("Foundry is connected!")
