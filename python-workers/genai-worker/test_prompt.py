import json
from main import OLLAMA_MODEL

sample_report = {
    "task_id": "test-task-123",
    "file_name": "suspicious.apk",
    "file_path": "/data/apks/suspicious.apk",
    "status": "TRIAGE_SUSPICIOUS",
    "risk_score": 0.87,
    "telemetry": [{"event": "suspicious_api_call", "detail": "sendSMS"}, {"event": "permission", "detail": "SEND_SMS"}]
}

# Recreate prompt generation from main.call_ollama
telemetry = sample_report.get("telemetry")
status = sample_report.get("status")
risk = sample_report.get("risk_score")

prompt = (
    "You are a security analyst assistant. Analyze the APK analysis payload and produce a concise, factual assessment.\n"
    "Return a JSON object with these keys: 'summary' (one-paragraph concise risk summary), 'risk_explanation' (short explanation of why the risk_score is high/low), "
    "'recommended_actions' (3 short actionable steps), and 'confidence' (0-1 numeric estimate).\n"
    "Do NOT include extra text outside the JSON object. If some fields are missing, set them to empty string or 0.\n\n"
    f"Status: {status}\nRisk Score: {risk}\nFile: {sample_report.get('file_name') or sample_report.get('file_path')}\nTelemetry:\n{json.dumps(telemetry, indent=2, ensure_ascii=False)}\n\nJSON:"
)

print(prompt)
