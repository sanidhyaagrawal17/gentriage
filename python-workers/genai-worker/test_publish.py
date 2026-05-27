import json
import os
import time
from main import call_ollama

sample_event = {
    "task_id": "test-task-xyz",
    "file_name": "suspicious.apk",
    "file_path": "/data/apks/suspicious.apk",
    "status": "TRIAGE_SUSPICIOUS",
    "risk_score": 0.92,
    "telemetry": [{"event": "api_call", "detail": "sendText"}, {"event": "permission", "detail": "SEND_SMS"}]
}

print('[*] Running GenAI dry-run: calling Ollama and preparing enriched payload')
llm_text = call_ollama(sample_event)

llm_parsed = {}
if llm_text:
    try:
        llm_parsed = json.loads(llm_text)
    except Exception:
        start = llm_text.find('{')
        end = llm_text.rfind('}')
        if start != -1 and end != -1 and end > start:
            try:
                llm_parsed = json.loads(llm_text[start:end+1])
            except Exception:
                llm_parsed = {}

enriched = dict(sample_event)
enriched['llm_raw'] = llm_text
enriched['llm'] = {
    'summary': llm_parsed.get('summary', '') if isinstance(llm_parsed, dict) else '',
    'risk_explanation': llm_parsed.get('risk_explanation', '') if isinstance(llm_parsed, dict) else '',
    'recommended_actions': llm_parsed.get('recommended_actions', []) if isinstance(llm_parsed, dict) else [],
    'confidence': float(llm_parsed.get('confidence', 0.0)) if isinstance(llm_parsed, dict) else 0.0,
}
enriched['enriched_at'] = time.time()

# Try to publish to Kafka if available
try:
    from kafka import KafkaProducer
    broker = os.environ.get('GENTRIAGE_KAFKA_BROKER', 'localhost:9092')
    producer = KafkaProducer(bootstrap_servers=[broker], value_serializer=lambda v: json.dumps(v).encode('utf-8'))
    topic = os.environ.get('GENTRIAGE_GENAI_PRODUCE', 'analysis_enriched')
    print(f'[*] Attempting to publish enriched payload to Kafka topic {topic} at {broker}')
    producer.send(topic, enriched)
    producer.flush()
    print('[+] Published to Kafka')
except Exception as e:
    print('[-] Kafka publish failed or not available:', e)
    out_path = os.path.join(os.path.dirname(__file__), 'enriched_sample.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(enriched, f, indent=2)
    print(f'[*] Wrote enriched payload to {out_path}')
    print(json.dumps(enriched, indent=2))
