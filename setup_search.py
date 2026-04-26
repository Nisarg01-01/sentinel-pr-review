"""
One-time script to create the Azure AI Search index and upload ADR documents.
Run once: python setup_search.py
"""
import os
import glob
from dotenv import load_dotenv
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import (
    SearchIndex,
    SimpleField,
    SearchableField,
    SearchFieldDataType,
)

load_dotenv()

endpoint = os.environ["AZURE_SEARCH_ENDPOINT"]
key = os.environ["AZURE_SEARCH_KEY"]
index_name = os.environ["AZURE_SEARCH_INDEX"]

credential = AzureKeyCredential(key)
index_client = SearchIndexClient(endpoint=endpoint, credential=credential)

# Create index
fields = [
    SimpleField(name="id", type=SearchFieldDataType.String, key=True),
    SearchableField(name="title", type=SearchFieldDataType.String),
    SearchableField(name="content", type=SearchFieldDataType.String),
    SimpleField(name="filename", type=SearchFieldDataType.String, filterable=True),
]
index = SearchIndex(name=index_name, fields=fields)
index_client.create_or_update_index(index)
print(f"Index '{index_name}' created/updated.")

# Upload ADR documents
search_client = SearchClient(endpoint=endpoint, index_name=index_name, credential=credential)
documents = []
for path in glob.glob("adr_documents/*.md"):
    filename = os.path.basename(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    title = content.split("\n")[0].replace("# ", "").strip()
    doc_id = filename.replace(".md", "").replace("-", "_").replace(".", "_")
    documents.append({"id": doc_id, "title": title, "content": content, "filename": filename})
    print(f"  Queued: {filename} — {title}")

result = search_client.upload_documents(documents=documents)
print(f"\nUploaded {len(documents)} ADR documents to index '{index_name}'.")
print("Setup complete!")
