import json
import os
import time
from pathlib import Path

import requests
from kafka import KafkaConsumer, KafkaProducer

KAFKA_BROKER = os.environ.get("GENTRIAGE_KAFKA_BROKER", "localhost:9092")
CONSUME_TOPIC = os.environ.get("GENTRIAGE_GENAI_CONSUME", "analysis_complete")
PRODUCE_TOPIC = os.environ.get("GENTRIAGE_GENAI_PRODUCE", "analysis_enriched")
OLLAMA_URL = os.environ.get("GENTRIAGE_OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("GENTRIAGE_OLLAMA_MODEL", "llama3")
BASE_DIR = Path(__file__).resolve().parent


def setup_kafka():
    consumer = KafkaConsumer(
        CONSUME_TOPIC,
        bootstrap_servers=[KAFKA_BROKER],
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    )

    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    return consumer, producer


def call_ollama(report: dict) -> str:
    telemetry = report.get("telemetry")
    risk = report.get("risk_score")
    status = report.get("status")
    static_evidence = report.get("static_evidence") or {}
    runtime_summary = report.get("runtime_summary") or {}
    why_malicious = report.get("why_malicious") or []
    # Structured prompt: ask the LLM to return a JSON object with specific keys.
    prompt = (
        "You are a security analyst assistant. Analyze the APK analysis payload and produce a concise, factual assessment.\n"
        "Return a JSON object with these keys: 'summary' (one-paragraph concise risk summary), 'detected_patterns' (array of malware patterns), "
        "'evidence_snippets' (array of short evidence strings grounded in the payload), 'confidence_by_claim' (object mapping each claim to a 0-1 confidence), "
        "'recommended_actions' (3 short actionable steps), 'severity_justification' (short explanation of the final severity), "
        "'risk_explanation' (short explanation of why the risk_score is high/low), and 'confidence' (0-1 numeric estimate).\n"
        "Do NOT include extra text outside the JSON object. If some fields are missing, set them to empty string or 0.\n\n"
        f"Status: {status}\nRisk Score: {risk}\nFile: {report.get('file_name') or report.get('file_path')}\nTelemetry:\n{json.dumps(telemetry, indent=2, ensure_ascii=False)}\n\nJSON:"
        f"\nStatic Evidence:\n{json.dumps(static_evidence, indent=2, ensure_ascii=False)}\n\nRuntime Summary:\n{json.dumps(runtime_summary, indent=2, ensure_ascii=False)}\n\nWhy Malicious:\n{json.dumps(why_malicious, indent=2, ensure_ascii=False)}\n\nJSON:"
    )

    body = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    try:
        resp = requests.post(OLLAMA_URL, json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Ollama may return different fields; prefer 'response' then 'text'
        text = data.get("response") or data.get("text") or ""
        # If the model returned plain text, attempt to extract a JSON object
        return text
    except Exception as exc:
        print(f"[-] Ollama call failed: {exc}")
        return ""


def main():
    print("[*] Starting GenAI Enricher Worker...")
    consumer, producer = setup_kafka()

    print(f"[*] Listening on Kafka topic: {CONSUME_TOPIC}")

    for message in consumer:
        event = message.value or {}
        task_id = event.get("task_id")
        if not task_id:
            print(f"[-] Skipping invalid message: {event}")
            continue

        print(f"[+] Enriching task {task_id}")
        llm_text = call_ollama(event)

        # Attempt to parse the LLM text as JSON. Support nested JSON strings.
        llm_parsed = {}
        if llm_text:
            try:
                llm_parsed = json.loads(llm_text)
            except Exception:
                # Try to find JSON object inside the text
                start = llm_text.find('{')
                end = llm_text.rfind('}')
                if start != -1 and end != -1 and end > start:
                    try:
                        llm_parsed = json.loads(llm_text[start:end+1])
                    except Exception:
                        llm_parsed = {}

        # Normalize fields
        llm_summary_field = llm_parsed.get('summary') if isinstance(llm_parsed, dict) else None
        llm_risk_expl = llm_parsed.get('risk_explanation') if isinstance(llm_parsed, dict) else None
        llm_actions = llm_parsed.get('recommended_actions') if isinstance(llm_parsed, dict) else None
        llm_conf = llm_parsed.get('confidence') if isinstance(llm_parsed, dict) else None

        enriched = dict(event)
        enriched['llm_raw'] = llm_text
        enriched['llm'] = {
            'summary': llm_summary_field or "",
            'detected_patterns': llm_parsed.get('detected_patterns') or [],
            'evidence_snippets': llm_parsed.get('evidence_snippets') or [],
            'confidence_by_claim': llm_parsed.get('confidence_by_claim') or {},
            'severity_justification': llm_parsed.get('severity_justification') or "",
            'risk_explanation': llm_risk_expl or "",
            'recommended_actions': llm_actions or [],
            'confidence': float(llm_conf) if llm_conf is not None else 0.0,
            'analyst_priority': llm_parsed.get('analyst_priority') or "",
        }
        enriched["enriched_at"] = time.time()

        try:
            producer.send(PRODUCE_TOPIC, enriched)
            producer.flush()
            print(f"[+] Published enriched report for {task_id} to {PRODUCE_TOPIC}")
        except Exception as exc:
            print(f"[-] Failed to publish enriched report: {exc}")


if __name__ == "__main__":
    main()
