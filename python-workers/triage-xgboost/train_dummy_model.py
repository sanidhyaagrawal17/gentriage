import numpy as np
import xgboost as xgb
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / "model" / "xgboost_weights.json"
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

# Create a simple synthetic training set
N = 2000
X = np.random.rand(N, 100)
# Create a label skewed: 10% positive
y = (np.random.rand(N) < 0.1).astype(int)

dtrain = xgb.DMatrix(X, label=y)
params = {
    'objective': 'binary:logistic',
    'eval_metric': 'logloss',
    'max_depth': 4,
    'eta': 0.1,
}

bst = xgb.train(params, dtrain, num_boost_round=50)
# Save model
bst.save_model(str(MODEL_PATH))
print(f"Saved dummy XGBoost model to {MODEL_PATH}")
