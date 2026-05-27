import json
import os
import subprocess
import time
from collections import Counter
from pathlib import Path

import frida

KAFKA_BROKER = os.environ.get("GENTRIAGE_KAFKA_BROKER", "localhost:9092")
CONSUME_TOPIC = "analyze_apk"
PRODUCE_TOPIC = "analysis_complete"
BASE_DIR = Path(__file__).resolve().parent
JS_SCRIPT_PATH = BASE_DIR / "frida-scripts" / "hook.js"
GATEWAY_URL = os.environ.get("GENTRIAGE_GATEWAY_URL", "http://127.0.0.1:8080")


def setup_kafka():
    try:
        from kafka import KafkaConsumer, KafkaProducer
    except Exception as exc:
        raise RuntimeError(
            "Kafka client unavailable. Install kafka-python or kafka-python-ng in the worker environment."
        ) from exc

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


def resolve_apk_path(apk_path):
    path = Path(apk_path).expanduser()
    if path.exists():
        return path.resolve()

    repo_candidate = (BASE_DIR.parents[1] / path).resolve()
    if repo_candidate.exists():
        return repo_candidate

    data_candidate = (BASE_DIR.parents[1] / "data" / "apks" / path.name).resolve()
    if data_candidate.exists():
        return data_candidate

    return path


def load_js_payload():
    if not JS_SCRIPT_PATH.exists():
        raise FileNotFoundError(f"Frida script not found: {JS_SCRIPT_PATH}")

    return JS_SCRIPT_PATH.read_text(encoding="utf-8")


def extract_package_name(apk_path):
    """Extract the package name using aapt."""
    resolved_path = resolve_apk_path(apk_path)
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", str(resolved_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        for line in result.stdout.splitlines():
            if line.startswith("package:"):
                parts = line.split(" ")
                for part in parts:
                    if part.startswith("name="):
                        return part.split("=", 1)[1].strip("'")
    except Exception as exc:
        print(f"[-] Failed to extract package name: {exc}")
    return None


def install_and_launch_apk(apk_path, package_name):
    resolved_path = resolve_apk_path(apk_path)
    print(f"[*] Installing APK: {resolved_path}")
    subprocess.run(["adb", "install", "-t", "-r", str(resolved_path)], check=True)

    time.sleep(2)

    print(f"[*] Launching package: {package_name}")
    subprocess.run(
        ["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        capture_output=True,
        check=False,
    )


def analyze_app(package_name, js_code):
    runtime_logs = []

    def on_message(message, data):
        if message["type"] == "send":
            try:
                payload = json.loads(message["payload"])
                runtime_logs.append(payload)
                print(f"[Frida -> Kafka] Captured: {payload.get('action', 'unknown')}")
            except json.JSONDecodeError:
                print(f"[-] Failed to parse message from Frida: {message['payload']}")
        elif message["type"] == "error":
            print(f"[-] Frida Error: {message['stack']}")

    try:
        device = frida.get_usb_device()
        print(f"[*] Attaching Frida to: {package_name}")

        session = device.attach(package_name)
        script = session.create_script(js_code)
        script.on("message", on_message)
        script.load()

        print("[*] Script loaded. Monitoring for 15 seconds...")
        time.sleep(15)

        session.detach()
        print("[*] Analysis window closed. Detaching.")

    except frida.ProcessNotFoundError:
        print(f"[-] Process {package_name} not found. Is the app running?")
    except Exception as exc:
        print(f"[-] Runtime analysis error: {exc}")

    return runtime_logs


def summarize_runtime_evidence(logs):
    network_targets = []
    crypto_actions = []
    encoding_actions = []
    action_counts = Counter()

    for log in logs:
        if not isinstance(log, dict):
            continue

        action = str(log.get("action") or "unknown")
        payload = log.get("data") or ""
        action_counts[action] += 1

        if action == "URL_INIT" and payload:
            if payload not in network_targets:
                network_targets.append(payload)
        elif action == "CIPHER_DO_FINAL":
            crypto_actions.append(payload)
        elif action == "BASE64_ENCODE":
            encoding_actions.append(payload)

    suspicious_network = []
    for target in network_targets:
        lowered = str(target).lower()
        if lowered.startswith(("http://", "https://")) or ":" in lowered or lowered.count(".") >= 1:
            suspicious_network.append(target)

    return {
        "network_targets": network_targets,
        "suspicious_network_targets": suspicious_network,
        "crypto_actions": crypto_actions[:20],
        "encoding_actions": encoding_actions[:20],
        "action_counts": dict(action_counts),
        "observed_exfiltration_indicators": [
            "network URLs captured" if suspicious_network else None,
            "crypto operations observed" if crypto_actions else None,
            "base64 encoding observed" if encoding_actions else None,
        ],
    }


def main():
    print("[*] Starting GenTriage Dynamic Analyzer Worker...")
    consumer, producer = setup_kafka()
    js_code = load_js_payload()

    print(f"[*] Listening on Kafka topic: {CONSUME_TOPIC}")

    for message in consumer:
        event = message.value or {}
        task_id = event.get("task_id")
        apk_path = event.get("file_path")

        if not task_id or not apk_path:
            print(f"[-] Invalid task payload received: {event}")
            continue

        print(f"\n[+] Received task {task_id} for analysis")

        package_name = extract_package_name(apk_path)
        if not package_name:
            print(f"[-] Aborting task {task_id}: Could not determine package name.")
            continue

        try:
            install_and_launch_apk(apk_path, package_name)
            logs = analyze_app(package_name, js_code)
            runtime_summary = summarize_runtime_evidence(logs)

            combined_evidence = {
                "static_evidence": event.get("static_evidence", {}),
                "why_malicious": event.get("why_malicious", []),
                "runtime_summary": runtime_summary,
            }

            report = {
                "task_id": task_id,
                "package": package_name,
                "status": "ANALYSIS_COMPLETE",
                "timestamp": time.time(),
                "telemetry": logs,
                "static_evidence": event.get("static_evidence", {}),
                "runtime_summary": runtime_summary,
                "why_malicious": event.get("why_malicious", []),
                "evidence": combined_evidence,
            }

            producer.send(PRODUCE_TOPIC, report)
            producer.flush()
            print(f"[+] Task {task_id} complete. Telemetry published to {PRODUCE_TOPIC}.")

            # update gateway task status
            try:
                import urllib.request
                url = f"{GATEWAY_URL}/api/v1/tasks/{task_id}/status"
                payload = {"status": "ANALYSIS_COMPLETE", "details": {"package": package_name, "summary": runtime_summary}}
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
                print(f"[*] Notified gateway of analysis completion for {task_id}")
            except Exception as e:
                print(f"[-] Failed to notify gateway about task {task_id}: {e}")

            subprocess.run(["adb", "uninstall", package_name], capture_output=True, check=False)

        except subprocess.CalledProcessError as exc:
            print(f"[-] ADB Operation failed for {task_id}: {exc}")


if __name__ == "__main__":
    main()