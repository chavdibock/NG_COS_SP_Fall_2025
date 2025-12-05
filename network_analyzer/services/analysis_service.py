# services/analysis_service.py

from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
import json


from algorithms import algos
from models.manager import model_manager, FEATURE_ORDER
from schemas.schemas import (
    TrainRequest,
    TrainReport,
    PredictRequest,
    PredictResponse,
    AnalyzeResponse,
    AnalyzeMultiResponse,
    AnalyzeModelsRequest, 
    TrafficWindow,
    TestRequest,
    TestReport,
)
from clients.sniffer_client import SnifferClient
from config.config import settings

def _apply_preprocessing(
    x_flat: List[float],
    n_samples: int,
    n_features: int,
    params: Dict[str, Any],
) -> Tuple[List[float], int]:
    use_scaling = bool(params.get("use_scaling", False))
    use_pca = bool(params.get("use_pca", False))
    n_pca_components = int(params.get("n_pca_components", 0) or 0)

    if not (use_scaling or use_pca):
        return x_flat, n_features

    x_proc = algos.pca_scaling(
        x_flat,
        n_samples,
        n_features,
        use_scaling,
        use_pca,
        n_pca_components,
    )

    new_n_features = (
        n_pca_components if use_pca and n_pca_components > 0 else n_features
    )
    return x_proc, new_n_features
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

async def _prepare_ip_traffic(ip: str) -> (List[TrafficWindow], List[float], int, int):
    sniffer = SnifferClient()
    packets = await sniffer.get_packets(ip)

    data = packets.get("data", [])
    if not data:
        raise ValueError(f"No traffic windows available for IP {ip}")

    
    last_windows_raw = data[-5:]
    windows = [TrafficWindow(**w) for w in last_windows_raw]

    x_flat, n_samples, n_features = _flatten_samples(windows)
    return windows, x_flat, n_samples, n_features

def train_model(req: TrainRequest) -> TrainReport:
     
    wrapper = model_manager.create_or_replace_model(
        req.model_id,
        req.model_type,
        dict(req.params or {}),
    )

    
    x_flat, n_samples, n_features = _flatten_samples(req.x)
    if len(req.y) != n_samples:
        raise ValueError("Number of labels (y) must match number of samples (x)")

    y = [float(v) for v in req.y]

   
    x_flat, n_features = _apply_preprocessing(
        x_flat,
        n_samples,
        n_features,
        wrapper.params,
    )


    wrapper.train(x_flat, y, n_features)

   
    scores = wrapper.predict(x_flat, n_samples)
    roc_auc_val = algos.roc_auc(scores, y)
    recall_val = algos.recall(scores, y, float(settings.DEFAULT_RECALL_THRESHOLD))

    metrics = {
        "roc_auc": float(roc_auc_val),
        "recall": float(recall_val),
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


def test_model(model_id: str, req: TestRequest) -> TestReport:

    wrapper = model_manager.get_model(model_id)

    
    x_flat, n_samples, n_features = _flatten_samples(req.x)

    if len(req.y) != n_samples:
        raise ValueError("Number of labels (y) must match number of samples (x)")

    y = [int(v) for v in req.y]

    
    if wrapper.n_features is not None and wrapper.n_features != n_features:
        raise ValueError(
            f"Model expects {wrapper.n_features} features, but got {n_features}"
        )

   
    scores = wrapper.predict(x_flat, n_samples)
    preds = [1 if s > 0.0 else 0 for s in scores]

    
    roc_auc_val = algos.roc_auc(scores, y)
    recall_val = algos.recall(scores, y, settings.DEFAULT_RECALL_THRESHOLD)

    metrics = {
        "roc_auc": float(roc_auc_val),
        "recall_at_threshold": float(recall_val),
        "threshold": float(settings.DEFAULT_RECALL_THRESHOLD),
    }

    return TestReport(
        model_id=model_id,
        model_type=wrapper.model_type,
        n_samples=n_samples,
        n_features=n_features,
        metrics=metrics,
        predictions=preds,
        raw_scores=[float(s) for s in scores],
    )


def predict_with_model(model_id: str, req: PredictRequest) -> PredictResponse:
   wrapper = model_manager.get_model(model_id)

   x_flat, n_samples, n_features = _flatten_samples(req.samples)

 
   x_flat, n_features = _apply_preprocessing(
        x_flat,
        n_samples,
        n_features,
        wrapper.params,
    )

   if wrapper.n_features is not None and wrapper.n_features != n_features:
        raise ValueError(
            f"Model expects {wrapper.n_features} features, but got {n_features}"
        )

   scores = wrapper.predict(x_flat, n_samples)
   preds = [1 if s > 0.0 else 0 for s in scores]

   return PredictResponse(
       model_id=model_id,
       scores=scores,
       predictions=preds,
   )

async def analyze_ip(ip: str, model_id: str) -> AnalyzeResponse:
    wrapper = model_manager.get_model(model_id)

    x_flat, n_samples, n_features = _flatten_samples(last_windows)

    x_flat, n_features = _apply_preprocessing(
        x_flat,
        n_samples,
        n_features,
        wrapper.params,
    )

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


async def analyze_ip_multiple(
    ip: str, model_ids: Optional[List[str]] = None
) -> AnalyzeMultiResponse:
 
    _, x_flat, n_samples, n_features = await _prepare_ip_traffic(ip)

    
    if model_ids is None:
        all_models = model_manager.list_models()
        if not all_models:
            raise ValueError("No models are loaded")
        model_ids_to_use = list(all_models.keys())
    else:
        if not model_ids:
            raise ValueError("No model_ids specified")
        model_ids_to_use = model_ids

    results: List[AnalyzeResponse] = []

    for mid in model_ids_to_use:
        wrapper = model_manager.get_model(mid)

        if wrapper.n_features is not None and wrapper.n_features != n_features:
            raise ValueError(
                f"Model '{mid}' expects {wrapper.n_features} features, but got {n_features}"
            )

        scores = wrapper.predict(x_flat, n_samples)
        preds = [1 if s > 0.0 else 0 for s in scores]
        ongoing_ddos = n_samples > 0 and all(p == 1 for p in preds)

        results.append(
            AnalyzeResponse(
                ip=ip,
                model_id=mid,
                model_type=wrapper.model_type,
                windows_analyzed=n_samples,
                window_predictions=preds,
                ongoing_ddos=ongoing_ddos,
                params=wrapper.get_params(),
            )
        )

    return AnalyzeMultiResponse(ip=ip, results=results)

async def _load_training_data_from_json() -> Tuple[List[TrafficWindow], Optional[List[int]]]:
 
    base_dir = Path(__file__).resolve().parent.parent
    json_path = base_dir / "training_data.json"

    if not json_path.exists():
        raise FileNotFoundError(f"training_data.json not found at {json_path}")

    with json_path.open() as f:
        raw = json.load(f)

    if isinstance(raw, dict):
        x_raw = raw.get("x", [])
        y_raw = raw.get("y")
    elif isinstance(raw, list):
        x_raw = raw
        y_raw = None
    else:
        raise ValueError("training_data.json has unsupported structure")

    if not x_raw:
        raise ValueError("training_data.json: no samples found")

   
    windows: List[TrafficWindow] = [TrafficWindow(**item) for item in x_raw]

    labels: Optional[List[int]] = None
    if y_raw is not None:
        if len(y_raw) != len(windows):
            raise ValueError(
                f"training_data.json: len(y)={len(y_raw)} does not match len(x)={len(windows)}"
            )
        labels = [int(v) for v in y_raw]

    return windows, labels


async def train_all_models_on_startup() -> None:
    models_info = model_manager.list_models()
    if not models_info:
        print("[startup] No models registered; skipping auto-training.")
        return

    try:
        windows, labels = await _load_training_data_from_json()
    except Exception as e:
        print(f"[startup] Failed to load training data: {e}")
        return

    x_flat, n_samples, n_features = _flatten_samples(windows)

    for model_id, info in models_info.items():
        wrapper = model_manager.get_model(model_id)

        if wrapper.model_type == "knn":
            if labels is None:
                print(
                    "no labels available in training_data.json"
                )
                continue

            print(
                f"on {n_samples} samples with labels..."
            )
            try:
                wrapper.train(x_flat, labels, n_features)
                print(
                    f"n_features={wrapper.n_features}"
                )
            except Exception as e:
                print(f"[startup] Failed to train KNN model '{model_id}': {e}")

        elif wrapper.model_type == "ocsvm":
            dummy_labels = [1] * n_samples

            try:
                wrapper.train(x_flat, dummy_labels, n_features)
            except Exception as e:
                print(e)

        else:
            print(model_type)
