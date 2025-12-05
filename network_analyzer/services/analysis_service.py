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
     
    params: Dict[str, Any] = {}

    if req.model_type == "knn":
        if req.k is None:
            raise ValueError("k must be provided for KNN models")
        params["k"] = int(req.k)
    elif req.model_type == "ocsvm":
        if req.kernel is not None:
            params["kernel"] = req.kernel

        if req.gamma is not None:
            params["gamma"] = float(req.gamma)
        if req.nu is not None:
            params["nu"] = float(req.nu)
        if req.coef0 is not None:
            params["coef0"] = float(req.coef0)
        if req.degree is not None:
            params["degree"] = int(req.degree)
    else:
        raise ValueError(f"Unsupported model_type: {req.model_type}")

    if req.use_scaling is not None:
        params["use_scaling"] = bool(req.use_scaling)
    if req.use_pca is not None:
        params["use_pca"] = bool(req.use_pca)
    if req.n_pca_components is not None:
        params["n_pca_components"] = int(req.n_pca_components)

    wrapper = model_manager.create_or_replace_model(
        req.model_id,
        req.model_type,
        params,
    )

    x_flat, n_samples, n_features = _flatten_samples(req.x)
    if len(req.y) != n_samples:
        raise ValueError("Number of labels (y) must match number of samples (x)")

    y = [int(v) for v in req.y]

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
        # IMPORTANT: use wrapper.params so CSV and API behave the same
        params=wrapper.params,
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

async def _load_training_data_from_json(
    filename: str,
    require_labels: bool,
) -> Tuple[List[TrafficWindow], Optional[List[int]]]:

    base_dir = Path(__file__).resolve().parent.parent
    json_path = base_dir / filename

    if not json_path.exists():
        raise FileNotFoundError(f"{filename} not found at {json_path}")

    with json_path.open() as f:
        raw = json.load(f)

    if isinstance(raw, dict):
        x_raw = raw.get("x", [])
        y_raw = raw.get("y")
    elif isinstance(raw, list):
        x_raw = raw
        y_raw = None
    else:
        raise ValueError(f"{filename}: expected dict or list at top level")

    if not isinstance(x_raw, list):
        raise ValueError(f"{filename}: 'x' must be a list")

    windows: List[TrafficWindow] = [TrafficWindow(**item) for item in x_raw]

    labels: Optional[List[int]] = None
    if y_raw is not None:
        if not isinstance(y_raw, list):
            raise ValueError(f"{filename}: 'y' must be a list when present")
        if len(y_raw) != len(windows):
            raise ValueError(
                f"{filename}: len(y)={len(y_raw)} does not match len(x)={len(windows)}"
            )
        labels = [int(v) for v in y_raw]
    elif require_labels:
        raise ValueError(f"{filename}: labels (y) missing")

    return windows, labels



async def train_all_models_on_startup() -> None:
    models_info = model_manager.list_models()
    if not models_info:
        print("[startup] No models registered; skipping auto-training.")
        return

    knn_windows: Optional[List[TrafficWindow]] = None
    knn_labels: Optional[List[int]] = None
    knn_x_flat: Optional[List[float]] = None
    knn_n_samples: Optional[int] = None
    knn_n_features: Optional[int] = None

    try:
        knn_windows, knn_labels = await _load_training_data_from_json(
            "training_data_knn.json",
            require_labels=True, 
        )
        knn_x_flat, knn_n_samples, knn_n_features = _flatten_samples(knn_windows)
        print(
            f"[startup] Loaded KNN training data: {knn_n_samples} samples, {knn_n_features} features."
        )
    except FileNotFoundError:
        print(
            "[startup] training_data_knn.json not found; KNN models will not be auto-trained."
        )
    except Exception as e:
        print(f"[startup] Failed to load KNN training data: {e}")

    ocsvm_windows: Optional[List[TrafficWindow]] = None
    ocsvm_x_flat: Optional[List[float]] = None
    ocsvm_n_samples: Optional[int] = None
    ocsvm_n_features: Optional[int] = None

    try:
        ocsvm_windows, _ = await _load_training_data_from_json(
            "training_data_oc_svm.json",
            require_labels=False, 
        )
        ocsvm_x_flat, ocsvm_n_samples, ocsvm_n_features = _flatten_samples(
            ocsvm_windows
        )
       
    except FileNotFoundError:
        print(
            "training_data_ocsvm.json not found"
        )
    except Exception as e:
        print(f"Failed to load OC-SVM training data: {e}")

    for model_id, info in models_info.items():
        wrapper = model_manager.get_model(model_id)

        if wrapper.model_type == "knn":
            if (
                knn_x_flat is None
                or knn_labels is None
                or knn_n_samples is None
                or knn_n_features is None
            ):
                print("skipping model")
                continue

            #if wrapper.n_features is not None and wrapper.n_features != knn_n_features:
            #    print(
            #        f" KNN model '{model_id}' expects "
            #        f"{wrapper.n_features} training data has "
            #        f"{knn_n_features}"
            #    )

            try:
                wrapper.train(knn_x_flat, knn_labels, knn_n_features)
               
            except Exception as e:
                print(f"Failed to train KNN model '{model_id}': {e}")

        elif wrapper.model_type == "ocsvm":
            if (
                ocsvm_x_flat is None
                or ocsvm_n_samples is None
                or ocsvm_n_features is None
            ):
                print("No valid Oc-SVM data")
                continue

            dummy_labels = [1] * ocsvm_n_samples

            # if wrapper.n_features is not None and wrapper.n_features != ocsvm_n_features:
               # print(
               #     f"[startup] Warning: OC-SVM model '{model_id}' expects "
               #     f"{wrapper.n_features} features but training data has "
               #     f"{ocsvm_n_features}; using training data feature count."
               # )

            try:
                wrapper.train(ocsvm_x_flat, dummy_labels, ocsvm_n_features)
                #print(
                #    f"[startup] Trained OC-SVM model '{model_id}' on "
                #    f"{ocsvm_n_samples} samples (n_features={wrapper.n_features})."
                #)
            except Exception as e:
                print(f"[startup] Failed to train OC-SVM model '{model_id}': {e}")

        else:
            print(f"[startup] Unknown model_type '{wrapper.model_type}' for '{model_id}'")
