import csv
import json
from pathlib import Path

from main import build_feature_vector, extract_static_evidence, resolve_apk_path


BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parents[1]
APK_DIR = REPO_ROOT / "data" / "apks"
DATASET_PATH = BASE_DIR / "model" / "training_dataset.csv"


def heuristic_label(static_evidence):
    score = 0
    suspicious_permissions = set(static_evidence.get("suspicious_permissions") or [])
    urls = static_evidence.get("urls") or []
    domains = static_evidence.get("domains") or []
    api_hits = static_evidence.get("suspicious_api_hits") or []

    if suspicious_permissions:
        score += 1
    if urls or domains:
        score += 1
    if api_hits:
        score += 1

    return 1 if score >= 2 else 0


def main():
    apk_files = sorted(APK_DIR.glob("*.apk"))
    if not apk_files:
        raise SystemExit(f"No APK samples found in {APK_DIR}")

    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for apk_file in apk_files:
        resolved = resolve_apk_path(apk_file)
        features, permissions, _, static_evidence = build_feature_vector_and_evidence(resolved)
        label = heuristic_label(static_evidence)
        row = {f"f{i}": float(value) for i, value in enumerate(features)}
        row.update(
            {
                "apk_name": apk_file.name,
                "label": label,
                "permissions": json.dumps(permissions),
                "static_evidence": json.dumps(static_evidence),
            }
        )
        rows.append(row)

    fieldnames = [f"f{i}" for i in range(len(rows[0]) - 3)] + ["apk_name", "label", "permissions", "static_evidence"]
    with DATASET_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved dataset with {len(rows)} APK rows to {DATASET_PATH}")


def build_feature_vector_and_evidence(apk_file):
    from main import extract_features

    features, permissions, resolved_apk, static_evidence = extract_features(str(apk_file))
    if hasattr(features, "tolist"):
        feature_list = features.tolist()[0]
    else:
        feature_list = features[0]
    return feature_list, permissions, resolved_apk, static_evidence


if __name__ == "__main__":
    main()