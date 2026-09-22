from __future__ import annotations

import os
from typing import Any, Dict, List

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from src.feature_engineering import feature_vector_from_df
from src.utils import safe_float

MODEL_PATH = os.path.join("models", "anomaly_model.joblib")


def train_anomaly_model(dataframes: List[Any]) -> Dict[str, Any]:
    if not dataframes:
        return {"status": "insufficient_data", "message": "Insufficient traffic data for anomaly analysis."}

    features = []
    for df in dataframes:
        if df is None or df.empty:
            continue
        vector = feature_vector_from_df(df)
        if len(vector) == 13:
            features.append(vector)

    if len(features) < 3:
        return {"status": "insufficient_data", "message": "Insufficient variation in traffic features to train the anomaly model."}

    arr = np.asarray(features, dtype=float)
    if np.allclose(arr, arr[0]):
        return {"status": "insufficient_variation", "message": "Traffic does not provide enough variation for model training."}

    try:
        model = IsolationForest(contamination=0.1, random_state=42, n_estimators=200)
        model.fit(arr)
        joblib.dump(model, MODEL_PATH)
        return {"status": "ok", "model": model, "message": "Anomaly model trained successfully."}
    except Exception as exc:
        return {"status": "training_failed", "message": f"Unable to train anomaly model: {exc}"}


def load_anomaly_model() -> Any:
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


def predict_anomaly(model: Any, feature_vector: List[float]) -> bool:
    if model is None:
        return False
    try:
        arr = np.asarray([feature_vector], dtype=float)
        prediction = model.predict(arr)
        return bool(prediction[0] == -1)
    except Exception:
        return False


def calculate_anomaly_score(model: Any, feature_vector: List[float]) -> float:
    if model is None:
        return 0.0
    try:
        arr = np.asarray([feature_vector], dtype=float)
        score = -model.score_samples(arr)[0]
        return float(np.clip(score, 0.0, 10.0))
    except Exception:
        return 0.0
