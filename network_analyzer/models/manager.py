# models/manager.py

from typing import Dict, Any, Literal, List
from dataclasses import dataclass, field
import threading
from algorithms import algos

from pathlib import Path
import csv


FEATURE_ORDER: List[str] = [
    "bytes_ps",
    "pkts_ps",
    "tcp_fraction",
    "mean_pkt_size",
    "syn_rate",
    "syn_ack_ratio",
    "half_open_conn_count",
    "avg_bytes_per_flow",
    "new_conn_rate",
    "peak_to_avg_rate",
]




@dataclass
class BaseModelWrapper:
    model_id: str
    model_type: Literal["knn", "ocsvm"]
    n_features: int | None = None
    params: Dict[str, Any] = field(default_factory=dict)

    def train(self, x_flat: List[float], y: List[float], n_features: int) -> None:
        raise NotImplementedError

    def predict(self, x_flat: List[float], n_samples: int) -> List[float]:
        raise NotImplementedError

    def get_params(self) -> Dict[str, Any]:
        raw = self._model.get_params() 
        if self.model_type == "ocsvm":
            allowed = {"kernel", "gamma", "nu", "coef0", "degree"}
            print("########")
            print({k: raw[k] for k in allowed if k in raw})
            print("########")
            return {k: raw[k] for k in allowed if k in raw}
        return raw


@dataclass
class KNNWrapper(BaseModelWrapper):
    model: Any = None  

    def __post_init__(self) -> None:
        print("Inside MOdel Creation")
        print(self.params)
        print("Inside MOdel Creation")
        k = int(self.params.get("k", 5))
        self.model = algos.KNN(k)
        self.params["k"] = k

    def train(self, x_flat: List[float], y: List[float], n_features: int) -> None:
        self.n_features = n_features
        self.model.train(x_flat, y, n_features)

    def predict(self, x_flat: List[float], n_samples: int) -> List[float]:
        return self.model.predict(x_flat, n_samples)


@dataclass
class OcSvmWrapper(BaseModelWrapper):
    model: Any = None  

    def __post_init__(self) -> None:

        print("Inside MOdel Creation")
        print(self.params)
        print("Inside MOdel Creation")
        kernel_str = self.params.get("kernel", "RBF")
        kernel_enum = getattr(algos.KernelType, kernel_str)
        gamma = float(self.params.get("gamma", 0.1))
        nu = float(self.params.get("nu", 0.1))
        coef0 = float(self.params.get("coef0", 0.0))
        degree = int(self.params.get("degree", 3))

        self.model = algos.OcSvm(
            int(kernel_enum),
            gamma,
            nu,
            coef0,
            degree,
        )
        self.params.update(
            {
                "kernel": kernel_str,
                "gamma": gamma,
                "nu": nu,
                "coef0": coef0,
                "degree": degree,
            }
        )

    def train(self, x_flat: List[float], y: List[float], n_features: int) -> None:
        self.n_features = n_features
        self.model.train(x_flat, y, n_features)

        try:
            cpp_params = self.model.get_params()
            if isinstance(cpp_params, dict):
                self.params.update(cpp_params)
        except Exception:
            pass

    def predict(self, x_flat: List[float], n_samples: int) -> List[float]:
        return self.model.predict(x_flat, n_samples)


class ModelManager:
    def __init__(self) -> None:
        self._models: Dict[str, BaseModelWrapper] = {}
        self._lock = threading.RLock()

    def create_or_replace_model(
        self,
        model_id: str,
        model_type: Literal["knn", "ocsvm"],
        params: Dict[str, Any],
    ) -> BaseModelWrapper:
        with self._lock:
            if model_type == "knn":
                wrapper = KNNWrapper(model_id=model_id, model_type="knn", params=params)
            else:
                wrapper = OcSvmWrapper(model_id=model_id, model_type="ocsvm", params=params)

            self._models[model_id] = wrapper
            return wrapper

    def get_model(self, model_id: str) -> BaseModelWrapper:
        with self._lock:
            if model_id not in self._models:
                raise KeyError(f"Model '{model_id}' not found")
            return self._models[model_id]

    def delete_model(self, model_id: str) -> None:
        """Remove a model from memory."""
        with self._lock:
            if model_id not in self._models:
                raise KeyError(f"Model '{model_id}' not found")
            del self._models[model_id]

    def list_models(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {
                mid: {
                    "model_type": m.model_type,
                    "n_features": m.n_features,
                    "params": {k: m.params[k] for k in {"kernel", "gamma", "nu", "coef0", "degree"} if k in m.params},
                }
                for mid, m in self._models.items()
            }

    def load_from_csv_files(self, base_dir: str | Path | None = None) -> None:
        base_path = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent
        knn_path = base_path / "KNN_MODELS.csv"
        ocsvm_path = base_path / "Oc_SVM_MODELS.csv"

        with self._lock:
            # KNN
            if knn_path.exists():
                with knn_path.open(newline="") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        model_id = row.get("model_id") or row.get("id")
                        if not model_id:
                            continue

                        params: Dict[str, Any] = {}

                        
                        k_val = row.get("k")
                        if not k_val:
                            continue
                        try:
                            params["k"] = int(k_val)
                        except ValueError:
                            continue

                        # PCA 
                        for key in ("use_scaling", "use_pca", "n_pca_components"):
                            val = row.get(key)
                            if val in (None, ""):
                                continue
                            if key == "n_pca_components":
                                try:
                                    params[key] = int(val)
                                except ValueError:
                                    continue
                            else:
                                # bool from 0/1
                                params[key] = bool(int(val))

                        self.create_or_replace_model(model_id, "knn", params)

            #  Oc-SVM
            if ocsvm_path.exists():
                with ocsvm_path.open(newline="") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        model_id = row.get("model_id") or row.get("id")
                        if not model_id:
                            continue

                        params: Dict[str, Any] = {}

                        kernel = row.get("kernel")
                        if kernel:
                            params["kernel"] = kernel

                        for key, cast in [("gamma", float), ("nu", float), ("coef0", float)]:
                            val = row.get(key)
                            if val not in (None, ""):
                                try:
                                    params[key] = cast(val)
                                except ValueError:
                                    pass

                        degree = row.get("degree")
                        if degree not in (None, ""):
                            try:
                                params["degree"] = int(degree)
                            except ValueError:
                                pass

                        # scaling / PCA 
                        for key in ("use_scaling", "use_pca", "n_pca_components"):
                            val = row.get(key)
                            if val in (None, ""):
                                continue
                            if key == "n_pca_components":
                                try:
                                    params[key] = int(val)
                                except ValueError:
                                    continue
                            else:
                                params[key] = bool(int(val))

                        self.create_or_replace_model(model_id, "ocsvm", params)

model_manager = ModelManager()
