# schemas.py

from typing import List, Literal, Dict, Optional, Union
from pydantic import BaseModel, Field



class TrafficWindow(BaseModel):
    bytes_ps: float
    pkts_ps: float
    tcp_fraction: float
    mean_pkt_size: float
    syn_rate: float
    syn_ack_ratio: float
    half_open_conn_count: int
    avg_bytes_per_flow: float
    new_conn_rate: float
    peak_to_avg_rate: float
        

class TestRequest(BaseModel):

    x: List[TrafficWindow]
    y: List[int] 


class TestReport(BaseModel):

    model_id: str
    model_type: str
    n_samples: int
    n_features: int
    metrics: Dict[str, float]
    predictions: List[int]
    raw_scores: List[float]


class TrainRequest(BaseModel):
    model_id: str = Field(..., description="Unique identifier for the model instance")
    model_type: Literal["knn", "ocsvm"]

    x: List[TrafficWindow] = Field(..., description="Training samples")
    y: List[int] = Field(..., description="Labels: 1 = DDoS, 0 = normal")

    # Optional hyperparameters
    k: Optional[int] = Field(None, description="K for KNN (required if model_type = 'knn')")
    kernel: Optional[Literal["LINEAR", "RBF", "POLY", "SIGMOID"]] = None
    gamma: Optional[float] = None
    nu: Optional[float] = None
    coef0: Optional[float] = None
    degree: Optional[int] = None


class TrainReport(BaseModel):
    model_id: str
    model_type: str
    n_samples: int
    n_features: int
    params: Dict[str, Union[float, int, str]]
    metrics: Dict[str, float]


class PredictRequest(BaseModel):
    samples: List[TrafficWindow]


class PredictResponse(BaseModel):
    model_id: str
    model_type: str
    predictions: List[int]
    raw_scores: Optional[List[float]] = None
    params: Dict[str, Union[float, int, str]]


class AnalyzeResponse(BaseModel):
    ip: str
    model_id: str
    model_type: str
    windows_analyzed: int
    window_predictions: List[int]
    ongoing_ddos: bool
    params: Dict[str, Union[float, int, str]]


class AnalyzeMultiResponse(BaseModel):
    ip: str
    results: List[AnalyzeResponse]


class AnalyzeModelsRequest(BaseModel):
    model_ids: List[str]