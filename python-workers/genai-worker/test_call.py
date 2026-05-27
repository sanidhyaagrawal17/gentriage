import os
import json
from main import call_ollama

# Ensure mock server URL
os.environ['GENTRIAGE_OLLAMA_URL'] = os.environ.get('GENTRIAGE_OLLAMA_URL', 'http://127.0.0.1:11435/api/generate')

sample_report = {
    "task_id": "test-task-123",
    "file_name": "suspicious.apk",
    "file_path": "/data/apks/suspicious.apk",
    "status": "TRIAGE_SUSPICIOUS",
    "risk_score": 0.87,
    "telemetry": [{"event": "suspicious_api_call", "detail": "sendSMS"}, {"event": "permission", "detail": "SEND_SMS"}]
}

print('Calling call_ollama with sample report...')
resp = call_ollama(os.environ.get('GENTRIAGE_OLLAMA_URL','http://127.0.0.1:11434/api/generate'), sample_report)
print('Raw response from call_ollama:')
print(resp)

# If response is JSON string, try to parse
try:
    parsed = json.loads(resp)
    print('\nParsed JSON:')
    print(json.dumps(parsed, indent=2))
except Exception:
    try:
        # Sometimes call_ollama returns a JSON with 'response' field
        j = json.loads(resp)
        print('\nParsed top-level JSON:')
        print(json.dumps(j, indent=2))
    except Exception:
        print('\nCould not parse response as JSON')
