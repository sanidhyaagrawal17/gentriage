import json
import importlib
import os
import re
import zipfile
from pathlib import Path
from collections import Counter

try:
    import numpy as np
except ImportError:
    np = None

try:
    import xgboost as xgb
except ImportError:
    xgb = None

try:
    APK = importlib.import_module("androguard.core.apk").APK
except Exception:
    try:
        APK = importlib.import_module("androguard.core.bytecodes.apk").APK
    except Exception:
        APK = None

KAFKA_BROKER = os.environ.get("GENTRIAGE_KAFKA_BROKER", "localhost:9092")
GATEWAY_URL = os.environ.get("GENTRIAGE_GATEWAY_URL", "http://127.0.0.1:8080")
CONSUME_TOPIC = "apk_uploaded"
PRODUCE_TOPIC_FRIDA = "analyze_apk"
PRODUCE_TOPIC_REPORT = "analysis_complete"
TARGET_DIM = 100
SAFE_THRESHOLD = 0.45
BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parents[1]
MODEL_PATH = BASE_DIR / "model" / "xgboost_weights.json"
MODEL_METRICS_PATH = BASE_DIR / "model" / "xgboost_metrics.json"

HIGH_RISK_PERMISSION_WEIGHTS = {
    "android.permission.SEND_SMS": 0.28,
    "android.permission.READ_SMS": 0.25,
    "android.permission.RECEIVE_SMS": 0.20,
    "android.permission.CALL_PHONE": 0.14,
    "android.permission.RECORD_AUDIO": 0.16,
    "android.permission.CAMERA": 0.12,
    "android.permission.READ_CONTACTS": 0.10,
    "android.permission.WRITE_CONTACTS": 0.10,
    "android.permission.ACCESS_FINE_LOCATION": 0.10,
    "android.permission.REQUEST_INSTALL_PACKAGES": 0.22,
    "android.permission.SYSTEM_ALERT_WINDOW": 0.22,
    "android.permission.RECEIVE_BOOT_COMPLETED": 0.12,
    "android.permission.INTERNET": 0.05,
}

SUSPICIOUS_API_KEYWORDS = [
    "DexClassLoader",
    "PathClassLoader",
    "Runtime.getRuntime",
    "java.lang.Runtime",
    "System.loadLibrary",
    "java.lang.reflect",
    "SmsManager",
    "TelephonyManager",
    "Cipher",
    "Base64",
    "HttpURLConnection",
    "OkHttpClient",
    "URL(",
    "URLConnection",
    "Socket",
    "DatagramSocket",
    "SSLContext",
    "HostnameVerifier",
    "WebView",
    "setJavaScriptEnabled",
]

URL_PATTERN = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(rb"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", re.IGNORECASE)
IP_PATTERN = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _safe_call(obj, method_name, fallback=None):
    try:
        value = getattr(obj, method_name)()
        return value if value is not None else fallback
    except Exception:
        return fallback


def _normalize_string_list(values):
    if not values:
        return []
    normalized = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text not in normalized:
            normalized.append(text)
    return normalized


def _read_apk_payload(apk_file):
    payload = []
    if not apk_file.exists():
        return payload

    try:
        with zipfile.ZipFile(apk_file, "r") as archive:
            for member in archive.namelist():
                if member.endswith((".dex", ".xml", ".txt")):
                    try:
                        payload.append(archive.read(member))
                    except Exception:
                        continue
    except Exception:
        return payload
    return payload


def _extract_strings_from_payload(payload_chunks):
    urls = []
    domains = []
    ip_addresses = []
    raw_strings = []

    for chunk in payload_chunks:
        if not chunk:
            continue
        for pattern, bucket in ((URL_PATTERN, urls), (DOMAIN_PATTERN, domains), (IP_PATTERN, ip_addresses)):
            for match in pattern.findall(chunk):
                text = match.decode("utf-8", errors="ignore").strip("\x00\n\r\t ' \"")
                if text and text not in bucket:
                    bucket.append(text)

        decoded = chunk.decode("utf-8", errors="ignore")
        for candidate in re.findall(r"[\x20-\x7e]{6,}", decoded):
            candidate = candidate.strip()
            if candidate and candidate not in raw_strings:
                raw_strings.append(candidate)

    return {
        "urls": urls[:20],
        "domains": domains[:20],
        "ip_addresses": ip_addresses[:20],
        "strings": raw_strings[:50],
    }


def _extract_manifest_evidence(apk_file):
    evidence = {
        "package_name": None,
        "app_name": None,
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
    }

    if APK is None or not apk_file.exists():
        return evidence

    try:
        app = APK(str(apk_file))
        evidence["package_name"] = _safe_call(app, "get_package")
        evidence["app_name"] = _safe_call(app, "get_app_name")
        evidence["permissions"] = _normalize_string_list(_safe_call(app, "get_permissions", []))
        evidence["activities"] = _normalize_string_list(_safe_call(app, "get_activities", []))
        evidence["services"] = _normalize_string_list(_safe_call(app, "get_services", []))
        evidence["receivers"] = _normalize_string_list(_safe_call(app, "get_receivers", []))
        evidence["providers"] = _normalize_string_list(_safe_call(app, "get_providers", []))

        for group_name in ("activities", "services", "receivers", "providers"):
            for component in evidence[group_name]:
                if component and component not in evidence["exported_components"]:
                    evidence["exported_components"].append(component)
    except Exception:
        pass

    return evidence


def _extract_suspicious_api_hits(strings):
    lowered = "\n".join(strings).lower()
    hits = []
    for keyword in SUSPICIOUS_API_KEYWORDS:
        count = lowered.count(keyword.lower())
        if count:
            hits.append({"keyword": keyword, "count": count})
    return hits


def build_static_evidence(apk_file, permissions):
    payload_chunks = _read_apk_payload(apk_file)
    manifest = _extract_manifest_evidence(apk_file)
    string_signals = _extract_strings_from_payload(payload_chunks)
    suspicious_api_hits = _extract_suspicious_api_hits(string_signals["strings"])

    return {
        "package_name": manifest["package_name"],
        "app_name": manifest["app_name"],
        "permissions": permissions,
        "exported_components": manifest["exported_components"],
        "activities": manifest["activities"],
        "services": manifest["services"],
        "receivers": manifest["receivers"],
        "providers": manifest["providers"],
        "urls": string_signals["urls"],
        "domains": string_signals["domains"],
        "ip_addresses": string_signals["ip_addresses"],
        "strings": string_signals["strings"],
        "suspicious_api_hits": suspicious_api_hits,
        "suspicious_permissions": [
            permission
            for permission in permissions
            if permission in HIGH_RISK_PERMISSION_WEIGHTS and HIGH_RISK_PERMISSION_WEIGHTS[permission] >= 0.10
        ],
    }


def build_malicious_rationale(static_evidence, risk_score):
    rationale = []
    if static_evidence.get("suspicious_permissions"):
        rationale.append(
            f"High-risk permissions: {', '.join(static_evidence['suspicious_permissions'][:5])}"
        )
    if static_evidence.get("urls") or static_evidence.get("domains"):
        rationale.append(
            f"Network indicators found: {', '.join((static_evidence.get('domains') or static_evidence.get('urls') or [])[:5])}"
        )
    if static_evidence.get("suspicious_api_hits"):
        top_hits = ", ".join(item["keyword"] for item in static_evidence["suspicious_api_hits"][:4])
        rationale.append(f"Suspicious API usage detected: {top_hits}")
    if static_evidence.get("exported_components"):
        rationale.append(
            f"Exported components increase attack surface: {', '.join(static_evidence['exported_components'][:4])}"
        )
    if risk_score >= 0.7:
        rationale.append(f"Composite static score is elevated at {risk_score:.2f}.")
    return rationale or ["Static analysis did not reveal enough signals for a strong verdict."]


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
    raw_path = Path(apk_path).expanduser()
    candidates = []

    if raw_path.is_absolute():
        candidates.append(raw_path)
    else:
        candidates.extend(
            [
                raw_path,
                BASE_DIR / raw_path,
                REPO_ROOT / raw_path,
                REPO_ROOT / "data" / "apks" / raw_path.name,
                BASE_DIR / "data" / "apks" / raw_path.name,
            ]
        )

    for candidate in candidates:
        try:
            if candidate.exists():
                return candidate.resolve()
        except OSError:
            continue

    return raw_path


def load_model():
    if xgb is None:
        print("[-] XGBoost is not installed. Using heuristic triage mode.")
        return None

    if MODEL_PATH.exists() and MODEL_PATH.is_file():
        try:
            model = xgb.Booster()
            print(f"[*] Loading XGBoost model from {MODEL_PATH}")
            model.load_model(str(MODEL_PATH))
            return model
        except Exception as e:
            print(f"[-] Failed to load XGBoost model, falling back to heuristic: {e}")
            return None

    print("[-] Warning: Model file not found. Using heuristic triage mode.")
    return None


def build_feature_vector(apk_file, permissions):
    permission_set = set(permissions)
    file_size_mb = 0.0
    if apk_file.exists():
        file_size_mb = apk_file.stat().st_size / (1024 * 1024)

    feature_vector = [
        float(len(permission_set)),
        float("android.permission.INTERNET" in permission_set),
        float("android.permission.SEND_SMS" in permission_set),
        float("android.permission.READ_SMS" in permission_set),
        float("android.permission.RECORD_AUDIO" in permission_set),
        float("android.permission.CAMERA" in permission_set),
        float("android.permission.READ_CONTACTS" in permission_set),
        float("android.permission.ACCESS_FINE_LOCATION" in permission_set),
        float("android.permission.RECEIVE_BOOT_COMPLETED" in permission_set),
        float("android.permission.REQUEST_INSTALL_PACKAGES" in permission_set),
        min(file_size_mb / 100.0, 1.0),
        min(float(len(apk_file.name)) / 100.0, 1.0),
        float(apk_file.suffix.lower() == ".apk"),
    ]

    if len(feature_vector) < TARGET_DIM:
        feature_vector.extend([0.0] * (TARGET_DIM - len(feature_vector)))
    else:
        feature_vector = feature_vector[:TARGET_DIM]

    return feature_vector


def extract_features(apk_path):
    apk_file = resolve_apk_path(apk_path)
    permissions = []

    print(f"[*] Extracting static features from {apk_file}")
    if APK is not None and apk_file.exists():
        try:
            app = APK(str(apk_file))
            permissions = sorted(set(app.get_permissions() or []))
        except Exception as exc:
            print(f"[-] Static analysis failed, using heuristic features: {exc}")
    else:
        if APK is None:
            print("[-] Androguard is not installed. Using heuristic static features.")
        else:
            print(f"[-] APK file not found. Using heuristic static features: {apk_file}")

    features = build_feature_vector(apk_file, permissions)
    static_evidence = build_static_evidence(apk_file, permissions)
    if np is not None:
        return np.array([features], dtype=float), permissions, apk_file, static_evidence
    return [features], permissions, apk_file, static_evidence


def heuristic_threat_level(permissions, apk_file):
    score = 0.12
    for permission in permissions:
        score += HIGH_RISK_PERMISSION_WEIGHTS.get(permission, 0.0)

    if apk_file.exists():
        size_mb = apk_file.stat().st_size / (1024 * 1024)
        if size_mb >= 25:
            score += 0.12
        elif size_mb >= 5:
            score += 0.06

    if any(token in apk_file.name.lower() for token in ("payload", "dropper", "loader", "stealer")):
        score += 0.10

    payload_chunks = _read_apk_payload(apk_file)
    strings = _extract_strings_from_payload(payload_chunks)
    if strings["urls"]:
        score += 0.08
    if strings["ip_addresses"]:
        score += 0.05
    if _extract_suspicious_api_hits(strings["strings"]):
        score += 0.10

    score = min(score, 0.99)
    return score >= SAFE_THRESHOLD, score


def predict_threat_level(model, features, permissions, apk_file):
    if model is None or xgb is None or np is None:
        return heuristic_threat_level(permissions, apk_file)

    dmatrix = xgb.DMatrix(features)
    prediction = float(model.predict(dmatrix)[0])
    is_suspicious = prediction > 0.5
    return is_suspicious, prediction


def update_task_status(task_id, status, details=None):
    try:
        import urllib.request
        url = f"{GATEWAY_URL}/api/v1/tasks/{task_id}/status"
        payload = {"status": status}
        if details is not None:
            payload["details"] = details
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        print(f"[*] Updated task {task_id} status -> {status}")
    except Exception as e:
        print(f"[-] Failed to update task status for {task_id}: {e}")


def main():
    print("[*] Starting GenTriage XGBoost Worker...")
    consumer, producer = setup_kafka()
    model = load_model()

    print(f"[*] Listening on Kafka topic: {CONSUME_TOPIC}")

    for message in consumer:
        event = message.value or {}
        task_id = event.get("task_id")
        apk_path = event.get("file_path")

        if not task_id or not apk_path:
            print(f"[-] Invalid task payload received: {event}")
            continue

        print(f"\n[+] Processing Task ID: {task_id}")

        features, permissions, apk_file, static_evidence = extract_features(apk_path)
        if not apk_file.exists():
            print(f"[-] File not found: {apk_file}")
            continue

        is_suspicious, risk_score = predict_threat_level(model, features, permissions, apk_file)
        analysis_mode = "ml" if model is not None and xgb is not None and np is not None else "heuristic"
        print(f"[*] Triage Score: {risk_score:.4f} | Suspicious: {is_suspicious} | Mode: {analysis_mode}")

        if is_suspicious:
            rationale = build_malicious_rationale(static_evidence, risk_score)
            payload = {
                "task_id": task_id,
                "file_path": str(apk_file),
                "file_name": apk_file.name,
                "risk_score": risk_score,
                "analysis_mode": analysis_mode,
                "status": "TRIAGE_SUSPICIOUS",
                "telemetry": [
                    {
                        "static_analysis": "Suspicious APK routed to dynamic analysis.",
                        "static_evidence": static_evidence,
                        "why_malicious": rationale,
                    }
                ],
                "static_evidence": static_evidence,
                "why_malicious": rationale,
            }
            producer.send(PRODUCE_TOPIC_FRIDA, payload)
            # update status on gateway
            try:
                update_task_status(task_id, "TRIAGE_SUSPICIOUS", {"risk_score": risk_score})
            except Exception:
                pass
            print(f"[+] Task {task_id} routed to {PRODUCE_TOPIC_FRIDA}")
        else:
            payload = {
                "task_id": task_id,
                "file_path": str(apk_file),
                "file_name": apk_file.name,
                "risk_score": risk_score,
                "analysis_mode": analysis_mode,
                "status": "TRIAGE_SAFE",
                "telemetry": [
                    {
                        "static_analysis": "No malicious traits detected.",
                        "permissions": permissions,
                        "static_evidence": static_evidence,
                    }
                ],
                "static_evidence": static_evidence,
                "why_malicious": build_malicious_rationale(static_evidence, risk_score),
            }
            producer.send(PRODUCE_TOPIC_REPORT, payload)
            try:
                update_task_status(task_id, "TRIAGE_SAFE", {"risk_score": risk_score})
            except Exception:
                pass
            print(f"[+] Task {task_id} routed to {PRODUCE_TOPIC_REPORT}")

        producer.flush()


if __name__ == "__main__":
    main()