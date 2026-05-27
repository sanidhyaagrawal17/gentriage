import csv
import json
import os
import random
from pathlib import Path

import numpy as np

MODEL_PATH = Path(__file__).resolve().parent / "model" / "xgboost_weights.json"
METRICS_PATH = Path(__file__).resolve().parent / "model" / "xgboost_metrics.json"
TRAIN_DIR = Path(os.environ.get('GENTRIAGE_TRAIN_DIR', '/data/model/train'))


def _load_dataset_from_csv(csv_path):
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    if not rows:
        return None, None, csv_path.name

    fieldnames = reader.fieldnames or []
    label_column = None
    for candidate in ("label", "y", "target", "malicious"):
        if candidate in fieldnames:
            label_column = candidate
            break

    if label_column is None:
        return None, None, csv_path.name

    feature_columns = [column for column in fieldnames if column != label_column]
    X = []
    y = []
    for row in rows:
        try:
            X.append([float(row.get(column, 0.0) or 0.0) for column in feature_columns])
            y.append(int(float(row.get(label_column, 0) or 0)))
        except Exception:
            continue

    if not X or not y:
        return None, None, csv_path.name

    return np.array(X, dtype=float), np.array(y, dtype=int), csv_path.name


def _load_dataset():
    if TRAIN_DIR.exists():
        if (TRAIN_DIR / "features.npy").exists() and (TRAIN_DIR / "labels.npy").exists():
            X = np.load(TRAIN_DIR / "features.npy")
            y = np.load(TRAIN_DIR / "labels.npy")
            return X, y, "npy"

        for csv_path in sorted(TRAIN_DIR.glob("*.csv")):
            loaded = _load_dataset_from_csv(csv_path)
            if loaded[0] is not None:
                return loaded

    return None, None, None


def _train_test_split(X, y, test_ratio=0.2, seed=42):
    indices = list(range(len(X)))
    random.Random(seed).shuffle(indices)
    split_index = max(1, int(len(indices) * (1 - test_ratio)))
    train_indices = indices[:split_index]
    test_indices = indices[split_index:] or indices[-1:]
    return X[train_indices], X[test_indices], y[train_indices], y[test_indices]


def _confusion_matrix(y_true, y_pred):
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    return [[tn, fp], [fn, tp]]


def _precision_recall_f1(y_true, y_pred):
    tp = float(np.sum((y_true == 1) & (y_pred == 1)))
    fp = float(np.sum((y_true == 0) & (y_pred == 1)))
    fn = float(np.sum((y_true == 1) & (y_pred == 0)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return precision, recall, f1


def _roc_auc_score(y_true, y_prob):
    order = np.argsort(y_prob)
    y_true = y_true[order]
    y_prob = y_prob[order]
    n_pos = float(np.sum(y_true == 1))
    n_neg = float(np.sum(y_true == 0))
    if not n_pos or not n_neg:
        return 0.0

    ranks = np.arange(1, len(y_prob) + 1, dtype=float)
    pos_rank_sum = float(np.sum(ranks[y_true == 1]))
    return (pos_rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)

dataset_X, dataset_y, dataset_source = _load_dataset()

if dataset_X is None or dataset_y is None:
    print(f"[i] No labeled dataset found at {TRAIN_DIR}. Training synthetic baseline model for demo purposes.")
    dataset_source = "synthetic"
    rng = np.random.default_rng(42)
    dataset_X = rng.random((5000, 100))
    dataset_y = (rng.random(5000) < 0.12).astype(int)

print(f"[+] Training model from {dataset_source} data with {len(dataset_X)} samples...")

try:
    import xgboost as xgb

    X_train, X_test, y_train, y_test = _train_test_split(dataset_X, dataset_y)
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)

    params = {
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'max_depth': 6,
        'eta': 0.05,
        'subsample': 0.85,
        'colsample_bytree': 0.85,
        'seed': 42,
    }
    bst = xgb.train(params, dtrain, num_boost_round=120)
    probabilities = bst.predict(dtest)
    predictions = (probabilities >= 0.5).astype(int)

    accuracy = float(np.mean(predictions == y_test))
    precision, recall, f1 = _precision_recall_f1(y_test, predictions)
    roc_auc = _roc_auc_score(y_test, probabilities)
    confusion_matrix = _confusion_matrix(y_test, predictions)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    bst.save_model(str(MODEL_PATH))
    metrics = {
        "dataset_source": dataset_source,
        "sample_count": int(len(dataset_X)),
        "train_count": int(len(X_train)),
        "test_count": int(len(X_test)),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": confusion_matrix,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"[+] Saved trained model to {MODEL_PATH}")
    print(f"[+] Saved evaluation metrics to {METRICS_PATH}")
    print(f"[+] Accuracy={accuracy:.4f} Precision={precision:.4f} Recall={recall:.4f} F1={f1:.4f} ROC-AUC={roc_auc:.4f}")
except Exception as e:
    print(f"[-] Training failed: {e}")
    print("[i] Falling back to lightweight numpy trainer (no xgboost required)")

    # Simple logistic regression trained with gradient descent as a fallback
    def _sigmoid(z):
        return 1.0 / (1.0 + np.exp(-z))

    X_train, X_test, y_train, y_test = _train_test_split(dataset_X, dataset_y)

    # initialize weights
    n_features = X_train.shape[1]
    rng = np.random.default_rng(42)
    weights = rng.normal(scale=0.01, size=(n_features,))
    bias = 0.0

    # gradient descent
    lr = 0.1
    epochs = 200
    for epoch in range(epochs):
        logits = X_train.dot(weights) + bias
        probs = _sigmoid(logits)
        error = probs - y_train
        grad_w = X_train.T.dot(error) / len(X_train)
        grad_b = float(np.mean(error))
        weights -= lr * grad_w
        bias -= lr * grad_b

    # evaluate
    test_logits = X_test.dot(weights) + bias
    probabilities = _sigmoid(test_logits)
    predictions = (probabilities >= 0.5).astype(int)

    accuracy = float(np.mean(predictions == y_test))
    precision, recall, f1 = _precision_recall_f1(y_test, predictions)
    roc_auc = _roc_auc_score(y_test, probabilities)
    confusion_matrix = _confusion_matrix(y_test, predictions)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    # save lightweight model weights as JSON
    model_data = {
        "type": "numpy_logistic",
        "weights": [float(w) for w in weights.tolist()],
        "bias": float(bias),
    }
    METRICS_PATH.write_text(json.dumps({
        "dataset_source": dataset_source,
        "sample_count": int(len(dataset_X)),
        "train_count": int(len(X_train)),
        "test_count": int(len(X_test)),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": confusion_matrix,
    }, indent=2), encoding="utf-8")

    MODEL_PATH.write_text(json.dumps(model_data, indent=2), encoding="utf-8")
    print(f"[+] Saved lightweight model to {MODEL_PATH}")
    print(f"[+] Saved evaluation metrics to {METRICS_PATH}")
    print(f"[+] Accuracy={accuracy:.4f} Precision={precision:.4f} Recall={recall:.4f} F1={f1:.4f} ROC-AUC={roc_auc:.4f}")
