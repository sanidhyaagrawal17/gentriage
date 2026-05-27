import json
import os
import time
from kafka import KafkaConsumer, KafkaProducer
import urllib.request

KAFKA_BROKER = os.environ.get("GENTRIAGE_KAFKA_BROKER", "localhost:9094")
# simulator will listen for both the upstream triage topic and direct analyze requests
CONSUME_TOPICS = ["analyze_apk", "apk_uploaded"]
PRODUCE_TOPIC = "analysis_complete"
GATEWAY_URL = os.environ.get("GENTRIAGE_GATEWAY_URL", "http://127.0.0.1:8080")


def notify_gateway(task_id, status, details=None):
    try:
        url = f"{GATEWAY_URL}/api/v1/tasks/{task_id}/status"
        payload = {"status": status}
        if details is not None:
            payload["details"] = details
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        print(f"[*] Gateway notified: {task_id} -> {status}")
    except Exception as e:
        print(f"[-] Failed to notify gateway for {task_id}: {e}")


def run():
    print("[*] Starting simulator: consuming analyze_apk and producing analysis_complete")
    consumer = KafkaConsumer(
        *CONSUME_TOPICS,
        bootstrap_servers=[KAFKA_BROKER],
        api_version=(3, 5),
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    )
    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER],
        api_version=(3, 5),
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    for message in consumer:
        topic = getattr(message, 'topic', None)
        event = message.value or {}
        task_id = event.get("task_id")
        print(f"[+] Simulator received message on topic={topic} for task: {task_id}")

        # If we received an apk_uploaded event, simulate triage + analysis by
        # performing the same work as for analyze_apk messages.
        try:
            # simulate runtime work
            time.sleep(1)
            runtime_summary = {"network_targets": ["http://example.test/sink"], "observed_exfiltration_indicators": ["network URLs captured"]}
            report = {
                "task_id": task_id,
                "status": "ANALYSIS_COMPLETE",
                "telemetry": [],
                "runtime_summary": runtime_summary,
                "static_evidence": event.get("static_evidence", {}),
                "why_malicious": event.get("why_malicious", []),
            }
            producer.send(PRODUCE_TOPIC, report)
            producer.flush()
            notify_gateway(task_id, "ANALYSIS_COMPLETE", {"runtime_summary": runtime_summary})
        except Exception as e:
            print(f"[-] Simulator failed processing task {task_id}: {e}")


if __name__ == "__main__":
    run()
