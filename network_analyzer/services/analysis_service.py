# services/analysis_service.py

from typing import List, Dict, Any

from algorithms import algos
from models.manager import model_manager, FEATURE_ORDER
from schemas.schemas import (
    TrainRequest,
    TrainReport,
    PredictRequest,
    PredictResponse,
    AnalyzeResponse,
    TrafficWindow,
)
from clients.sniffer_client import SnifferClient
from config.config import settings


def _flatten_samples(samples: List[TrafficWindow]) -> (List[float], int, int):

    n_samples = len(samples)
    if n_samples == 0:
        raise ValueError("No samples provided")

    n_features = len(FEATURE_ORDER)
    x_flat: List[float] = []

    for s in samples:
        s_dict = s.model_dump()
        for feat in FEATURE_ORDER:
            x_flat.append(float(s_dict[feat]))

    return x_flat, n_samples, n_features


def train_model(req: TrainRequest) -> TrainReport:
    # Prepare params
    params: Dict[str, Any] = {}
    if req.model_type == "knn":
        if req.k is None:
            raise ValueError("k must be provided for KNN model")
        params["k"] = req.k
    else:
        if req.kernel is not None:
            params["kernel"] = req.kernel
        if req.gamma is not None:
            params["gamma"] = req.gamma
        if req.nu is not None:
            params["nu"] = req.nu
        if req.coef0 is not None:
            params["coef0"] = req.coef0
        if req.degree is not None:
            params["degree"] = req.degree

    # Create or replace model
    wrapper = model_manager.create_or_replace_model(req.model_id, req.model_type, params)

    # Flatten data
    x_flat, n_samples, n_features = _flatten_samples(req.x)
    if len(req.y) != n_samples:
        raise ValueError("Number of labels (y) must match number of samples (x)")

    y = [float(v) for v in req.y]

    # Train
    wrapper.train(x_flat, y, n_features)

    # Get scores on training data for metrics
    scores = wrapper.predict(x_flat, n_samples)

    # Metrics via C++ benchmarks
    roc_auc_val = algos.roc_auc(scores, y)
    recall_val = algos.recall(scores, y, settings.DEFAULT_RECALL_THRESHOLD)

    metrics = {
        "roc_auc": float(roc_auc_val),
        "recall_at_threshold": float(recall_val),
        "threshold": float(settings.DEFAULT_RECALL_THRESHOLD),
    }

    return TrainReport(
        model_id=req.model_id,
        model_type=req.model_type,
        n_samples=n_samples,
        n_features=n_features,
        params=wrapper.get_params(),
        metrics=metrics,
    )


def predict_with_model(model_id: str, req: PredictRequest) -> PredictResponse:
    wrapper = model_manager.get_model(model_id)

    x_flat, n_samples, n_features = _flatten_samples(req.samples)

    if wrapper.n_features is not None and wrapper.n_features != n_features:
        raise ValueError(
            f"Model expects {wrapper.n_features} features, but got {n_features}"
        )

    scores = wrapper.predict(x_flat, n_samples)

    # Simple rule: score > 0 => DDoS (1), else normal (0).
    preds = [1 if s > 0.0 else 0 for s in scores]

    return PredictResponse(
        model_id=model_id,
        model_type=wrapper.model_type,
        predictions=preds,
        raw_scores=[float(s) for s in scores],
        params=wrapper.get_params(),
    )


async def analyze_ip(ip: str, model_id: str) -> AnalyzeResponse:

    wrapper = model_manager.get_model(model_id)
    sniffer = SnifferClient()
    packets = await sniffer.get_packets(ip)

    data = packets.get("data", [])
    if not data:
        raise ValueError(f"No traffic windows available for IP {ip}")

    # Last up to 5 windows
    last_windows_raw = data[-5:]
    windows = [TrafficWindow(**w) for w in last_windows_raw]

    x_flat, n_samples, n_features = _flatten_samples(windows)

    if wrapper.n_features is not None and wrapper.n_features != n_features:
        raise ValueError(
            f"Model expects {wrapper.n_features} features, but got {n_features}"
        )

    scores = wrapper.predict(x_flat, n_samples)
    preds = [1 if s > 0.0 else 0 for s in scores]

    ongoing_ddos = n_samples > 0 and all(p == 1 for p in preds)

    return AnalyzeResponse(
        ip=ip,
        model_id=model_id,
        model_type=wrapper.model_type,
        windows_analyzed=n_samples,
        window_predictions=preds,
        ongoing_ddos=ongoing_ddos,
        params=wrapper.get_params(),
    )
