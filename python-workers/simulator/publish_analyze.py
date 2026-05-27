import json
import sys
import os
from kafka import KafkaProducer

KAFKA_BROKER = os.environ.get("GENTRIAGE_KAFKA_BROKER", "localhost:9094")
TASKS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "apks", "tasks.json"))

def main(task_id):
    with open(TASKS_PATH, "r", encoding="utf-8") as f:
        tasks = json.load(f)

    task = tasks.get(task_id)
    if not task:
        print(f"Task {task_id} not found in tasks.json")
        return 2

    payload = {
        "task_id": task_id,
        "file_path": task.get("file_path"),
        "file_name": task.get("file_name"),
        "static_evidence": task.get("static_evidence", {}),
        "why_malicious": task.get("why_malicious", ["simulated"]),
    }

    producer = KafkaProducer(bootstrap_servers=[KAFKA_BROKER], value_serializer=lambda v: json.dumps(v).encode("utf-8"))
    producer.send("analyze_apk", payload)
    producer.flush()
    print(f"Published analyze_apk for {task_id}")
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: publish_analyze.py <task_id>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
