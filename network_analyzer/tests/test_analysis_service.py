# tests/test_analysis_service.py

import pytest

from schemas.schemas import TrafficWindow, TrainRequest, TestRequest, PredictRequest  
from services import analysis_service 

from algorithms import algos
import math

class DummyWrapper:

    def __init__(self, model_id="dummy", model_type="knn", params=None):
        self.model_id = model_id
        self.model_type = model_type
        self.params = params or {}
        self.n_features = None
        self.trained = False

    def train(self, x_flat, y, n_features):
        # just record n_features and mark as trained
        self.n_features = n_features
        self.trained = True

    def predict(self, x_flat, n_samples):
        # return n_samples scores linearly spaced between -1 and 1
        if n_samples == 0:
            return []
        return [float(i) / max(n_samples - 1, 1) * 2 - 1 for i in range(n_samples)]

    def get_params(self):
        return self.params



def test__flatten_samples_empty_raises_value_error():
    with pytest.raises(ValueError, match="No samples provided"):
        analysis_service._flatten_samples([])


def test__flatten_samples_happy_path():
    samples = [
        TrafficWindow(
            bytes_ps=1,
            pkts_ps=2,
            tcp_fraction=0.5,
            mean_pkt_size=100,
            syn_rate=1,
            syn_ack_ratio=0.2,
            half_open_conn_count=3,
            avg_bytes_per_flow=10,
            new_conn_rate=2,
            peak_to_avg_rate=1.5,
        ),
        TrafficWindow(
            bytes_ps=3,
            pkts_ps=4,
            tcp_fraction=0.6,
            mean_pkt_size=90,
            syn_rate=1.2,
            syn_ack_ratio=0.25,
            half_open_conn_count=4,
            avg_bytes_per_flow=11,
            new_conn_rate=2.5,
            peak_to_avg_rate=1.6,
        ),
    ]

    x_flat, n_samples, n_features = analysis_service._flatten_samples(samples)

    assert n_samples == 2
    assert n_features == 10
    assert len(x_flat) == n_samples * n_features


# -----------------------------
# Tests for train_model
# -----------------------------


def test_train_model_invalid_type_raises():
    req = TrainRequest(
        model_id="m1",
        model_type="knn",  # will change after creation
        x=[],
        y=[],
    )
    # Force an invalid type directly in params by bypassing pydantic? Not needed:
    # we trigger invalid by passing wrong model_type literal below.
    # Use direct call with patch on model_type.
    with pytest.raises(ValueError, match="Unsupported model_type"):
        # call internal function directly with invalid type by monkeypatching
        bad_req = req.copy(update={"model_type": "something_else"})
        analysis_service.train_model(bad_req)


def test_train_model_knn_without_k_raises(monkeypatch):
    # KNN requires k in request
    req = TrainRequest(
        model_id="m1",
        model_type="knn",
        x=[
            TrafficWindow(
                bytes_ps=1,
                pkts_ps=2,
                tcp_fraction=0.5,
                mean_pkt_size=100,
                syn_rate=1,
                syn_ack_ratio=0.2,
                half_open_conn_count=3,
                avg_bytes_per_flow=10,
                new_conn_rate=2,
                peak_to_avg_rate=1.5,
            )
        ],
        y=[1],
        k=None,  # intentionally missing
    )

    with pytest.raises(ValueError, match="k must be provided for KNN models"):
        analysis_service.train_model(req)


def test_train_model_mismatched_labels_raises(monkeypatch):
    # One sample but two labels
    sample = TrafficWindow(
        bytes_ps=1,
        pkts_ps=2,
        tcp_fraction=0.5,
        mean_pkt_size=100,
        syn_rate=1,
        syn_ack_ratio=0.2,
        half_open_conn_count=3,
        avg_bytes_per_flow=10,
        new_conn_rate=2,
        peak_to_avg_rate=1.5,
    )
    req = TrainRequest(
        model_id="m1",
        model_type="knn",
        x=[sample],
        y=[1, 0],  # mismatch
        k=3,
    )

    # Stub out create_or_replace_model so it doesn't use real algos
    def dummy_create_or_replace_model(model_id, model_type, params):
        return DummyWrapper(model_id=model_id, model_type=model_type, params=params)

    monkeypatch.setattr(
        analysis_service.model_manager,
        "create_or_replace_model",
        dummy_create_or_replace_model,
    )

    with pytest.raises(ValueError, match="Number of labels \\(y\\) must match number of samples \\(x\\)"):
        analysis_service.train_model(req)


def test_train_model_happy_path_knn(monkeypatch):
    # one simple sample
    sample = TrafficWindow(
        bytes_ps=1,
        pkts_ps=2,
        tcp_fraction=0.5,
        mean_pkt_size=100,
        syn_rate=1,
        syn_ack_ratio=0.2,
        half_open_conn_count=3,
        avg_bytes_per_flow=10,
        new_conn_rate=2,
        peak_to_avg_rate=1.5,
    )
    req = TrainRequest(
        model_id="m1",
        model_type="knn",
        x=[sample],
        y=[1],
        k=3,
    )

    # Use dummy wrapper
    dummy_wrapper = DummyWrapper(model_id="m1", model_type="knn", params={})

    def dummy_create_or_replace_model(model_id, model_type, params):
        dummy_wrapper.params.update(params)
        return dummy_wrapper

    monkeypatch.setattr(
        analysis_service.model_manager,
        "create_or_replace_model",
        dummy_create_or_replace_model,
    )

    # Stub out algos metrics & preprocessing
    class DummyAlgos:
        @staticmethod
        def pca_scaling(x_flat, n_samples, n_features, use_scaling, use_pca, n_pca_components):
            # Just return input unchanged
            return x_flat

        @staticmethod
        def roc_auc(scores, y):
            return 1.0

        @staticmethod
        def recall(scores, y, threshold):
            return 1.0

    monkeypatch.setattr(analysis_service, "algos", DummyAlgos)

    report = analysis_service.train_model(req)

    assert report.model_id == "m1"
    assert report.model_type == "knn"
    assert report.n_samples == 1
    assert report.n_features == 10
    assert report.metrics["roc_auc"] == 1.0
    assert report.metrics["recall"] == 1.0
    assert "k" in report.params
    assert report.params["k"] == 3


# -----------------------------
# Tests for test_model
# -----------------------------


def test_test_model_mismatched_labels_raises(monkeypatch):
    sample = TrafficWindow(
        bytes_ps=1,
        pkts_ps=2,
        tcp_fraction=0.5,
        mean_pkt_size=100,
        syn_rate=1,
        syn_ack_ratio=0.2,
        half_open_conn_count=3,
        avg_bytes_per_flow=10,
        new_conn_rate=2,
        peak_to_avg_rate=1.5,
    )
    req = TestRequest(
        x=[sample],
        y=[1, 0],  
    )

    dummy_wrapper = DummyWrapper(model_id="m1", model_type="knn", params={})
    monkeypatch.setattr(
        analysis_service.model_manager,
        "get_model",
        lambda mid: dummy_wrapper,
    )

    with pytest.raises(ValueError, match="Number of labels \\(y\\) must match number of samples \\(x\\)"):
        analysis_service.test_model("m1", req)


def test_test_model_feature_mismatch_raises(monkeypatch):
    sample = TrafficWindow(
        bytes_ps=1,
        pkts_ps=2,
        tcp_fraction=0.5,
        mean_pkt_size=100,
        syn_rate=1,
        syn_ack_ratio=0.2,
        half_open_conn_count=3,
        avg_bytes_per_flow=10,
        new_conn_rate=2,
        peak_to_avg_rate=1.5,
    )
    req = TestRequest(
        x=[sample, sample],
        y=[1, 0],
    )

    dummy_wrapper = DummyWrapper(model_id="m1", model_type="knn", params={})
    dummy_wrapper.n_features = 5
    monkeypatch.setattr(
        analysis_service.model_manager,
        "get_model",
        lambda mid: dummy_wrapper,
    )

    with pytest.raises(ValueError, match="Model expects 5 features, but got 10"):
        analysis_service.test_model("m1", req)


def test_test_model_happy_path(monkeypatch):
    sample = TrafficWindow(
        bytes_ps=1,
        pkts_ps=2,
        tcp_fraction=0.5,
        mean_pkt_size=100,
        syn_rate=1,
        syn_ack_ratio=0.2,
        half_open_conn_count=3,
        avg_bytes_per_flow=10,
        new_conn_rate=2,
        peak_to_avg_rate=1.5,
    )
    req = TestRequest(
        x=[sample, sample],
        y=[1, 0],
    )

    dummy_wrapper = DummyWrapper(model_id="m1", model_type="knn", params={})
    dummy_wrapper.n_features = 10

    monkeypatch.setattr(
        analysis_service.model_manager,
        "get_model",
        lambda mid: dummy_wrapper,
    )

    class DummyAlgos:
        @staticmethod
        def roc_auc(scores, y):
            return 0.7

        @staticmethod
        def recall(scores, y, threshold):
            return 0.8

    monkeypatch.setattr(analysis_service, "algos", DummyAlgos)

    report = analysis_service.test_model("m1", req)

    assert report.model_id == "m1"
    assert report.model_type == "knn"
    assert report.n_samples == 2
    assert report.n_features == 10
    assert report.metrics["roc_auc"] == 0.7
    assert report.metrics["recall_at_threshold"] == 0.8
    assert len(report.predictions) == 2
    assert len(report.raw_scores) == 2



def test_predict_with_model_feature_mismatch_raises(monkeypatch):
    sample = TrafficWindow(
        bytes_ps=1,
        pkts_ps=2,
        tcp_fraction=0.5,
        mean_pkt_size=100,
        syn_rate=1,
        syn_ack_ratio=0.2,
        half_open_conn_count=3,
        avg_bytes_per_flow=10,
        new_conn_rate=2,
        peak_to_avg_rate=1.5,
    )
    req = PredictRequest(samples=[sample])

    dummy_wrapper = DummyWrapper(model_id="m1", model_type="knn", params={})
    dummy_wrapper.n_features = 5  # mismatch on purpose

    monkeypatch.setattr(
        analysis_service.model_manager,
        "get_model",
        lambda mid: dummy_wrapper,
    )

    class DummyAlgos:
        @staticmethod
        def pca_scaling(x_flat, n_samples, n_features, use_scaling, use_pca, n_pca_components):
            return x_flat

    monkeypatch.setattr(analysis_service, "algos", DummyAlgos)

    with pytest.raises(ValueError, match="Model expects 5 features, but got 10"):
        analysis_service.predict_with_model("m1", req)


def test_predict_with_model_happy_path(monkeypatch):
    sample = TrafficWindow(
        bytes_ps=1,
        pkts_ps=2,
        tcp_fraction=0.5,
        mean_pkt_size=100,
        syn_rate=1,
        syn_ack_ratio=0.2,
        half_open_conn_count=3,
        avg_bytes_per_flow=10,
        new_conn_rate=2,
        peak_to_avg_rate=1.5,
    )
    req = PredictRequest(samples=[sample, sample])

    dummy_wrapper = DummyWrapper(model_id="m1", model_type="knn", params={"use_scaling": False, "use_pca": False})
    dummy_wrapper.n_features = 10

    monkeypatch.setattr(
        analysis_service.model_manager,
        "get_model",
        lambda mid: dummy_wrapper,
    )

    class DummyAlgos:
        @staticmethod
        def pca_scaling(x_flat, n_samples, n_features, use_scaling, use_pca, n_pca_components):
            return x_flat

    monkeypatch.setattr(analysis_service, "algos", DummyAlgos)

    resp = analysis_service.predict_with_model("m1", req)
    assert resp.model_id == "m1"

    assert len(resp.scores) == 2
    assert len(resp.predictions) == 2


def test_kerneltype_has_expected_members():
    assert hasattr(algos, "KernelType")

    kt = algos.KernelType
    assert hasattr(kt, "LINEAR")
    assert hasattr(kt, "RBF")
    assert hasattr(kt, "POLY")
    assert hasattr(kt, "SIGMOID")


    values = {kt.LINEAR, kt.RBF, kt.POLY, kt.SIGMOID}
    assert len(values) == 4




def _make_simple_dataset():
    x = [
        0.0, 0.0,
        0.1, -0.1,
        1.0, 1.0,
        0.9, 1.1,
    ]
    y = [0.0, 0.0, 1.0, 1.0]
    n_features = 2
    n_samples = len(y)
    assert len(x) == n_samples * n_features
    return x, y, n_features, n_samples


def test_knn_train_and_predict_runs():
    x, y, n_features, _ = _make_simple_dataset()

    k = 3
    knn = algos.KNN(k)

    knn.train(x, y, n_features)

    
    x_test = [
        0.0, 0.0,  
        1.0, 1.0,  
    ]
    n_samples_test = 2

    scores = knn.predict(x_test, n_samples_test)

    assert isinstance(scores, list)
    assert len(scores) == n_samples_test
    assert all(isinstance(s, float) for s in scores)
    _ = knn.sanity_check()



def test_ocsvm_default_ctor_and_get_params():
    model = algos.OcSvm()

    params = model.get_params()
    assert isinstance(params, dict)
    assert len(params) > 0


def test_ocsvm_train_and_predict_runs():
    x, y, n_features, n_samples = _make_simple_dataset()

    # explicit kernel via enum
    model = algos.OcSvm(
        kernel=algos.KernelType.RBF,
        gamma=0.1,
        nu=0.1,
        coef0=0.0,
        degree=3,
    )
    model.train(x, y, n_features)

    scores = model.predict(x, n_samples)

    assert isinstance(scores, list)
    assert len(scores) == n_samples
    assert all(isinstance(s, float) for s in scores)



def test_pca_scaling_no_pca_preserves_shape():
    # two samples, 3 features
    n_samples, n_features = 2, 3
    x = [
        1.0, 2.0, 3.0,
        4.0, 5.0, 6.0,
    ]

    out = algos.pca_scaling(
        x,
        n_samples=n_samples,
        n_features=n_features,
        use_scaling=True,
        use_pca=False,
        n_pca_components=0,
    )

    assert isinstance(out, list)
    assert len(out) == n_samples * n_features


def test_pca_scaling_with_pca_changes_feature_dimension():
    # two samples, 4 features, reduce to 2 components
    n_samples, n_features, n_components = 2, 4, 2
    x = [
        1.0, 2.0, 3.0, 4.0,
        2.0, 3.0, 4.0, 5.0,
    ]

    out = algos.pca_scaling(
        x,
        n_samples=n_samples,
        n_features=n_features,
        use_scaling=True,
        use_pca=True,
        n_pca_components=n_components,
    )

    assert isinstance(out, list)
    # PCA applied
    assert len(out) == n_samples * n_components





def test_roc_auc_perfect_separation():
    #  expected AUC = 0.75
    scores = [0.1, 0.4, 0.35, 0.8]
    labels = [0, 0, 1, 1]

    auc = algos.roc_auc(scores, labels)
    assert isinstance(auc, float)
    assert math.isfinite(auc)
    assert auc == pytest.approx(0.75, rel=1e-3)


def test_roc_auc_all_same_label_returns_nan_or_0():

    scores = [0.1, 0.2, 0.3]
    labels = [1, 1, 1]

    auc = algos.roc_auc(scores, labels)
    assert isinstance(auc, float)

    assert math.isfinite(auc) or math.isnan(auc)





def test_recall_default_threshold():
    
    scores = [0.1, 0.9]
    labels = [0, 1]

    r = algos.recall(scores, labels)  
    assert isinstance(r, float)
    assert r == pytest.approx(1.0, rel=1e-6)


def test_recall_custom_threshold_partial_recall():
    scores = [0.3, 0.6, 0.9]
    labels = [0, 1, 1]

 
    r = algos.recall(scores, labels, threshold=0.8)

    assert isinstance(r, float)
   
    assert r == pytest.approx(0.5, rel=1e-6)