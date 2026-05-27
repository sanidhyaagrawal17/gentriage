GenAI Worker

This worker consumes `analysis_complete` messages from Kafka, calls the local Ollama LLM to generate a natural-language summary, and publishes enriched reports to `analysis_enriched`.

Run locally:

```powershell
python -m venv .venv
.\.venv\Scripts\pip.exe install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

Docker: Built via `deployments/Dockerfiles/Dockerfile.genai-worker` in the repository root.