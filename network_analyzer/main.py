# main.py

from fastapi import FastAPI, HTTPException

from schemas.schemas import (
    TrainRequest,
    TrainReport,
    PredictRequest,
    PredictResponse,
    AnalyzeResponse,
)
from models.manager import model_manager
from services.analysis_service import train_model, predict_with_model, analyze_ip

app = FastAPI()


@app.get("/models")
async def list_models():
    """
    List all models currently stored in memory.
    """
    return model_manager.list_models()


@app.post("/train", response_model=TrainReport)
async def train(req: TrainRequest):
    """
    Train (or retrain) a model with the given ID.
    Returns model params and benchmark metrics (ROC-AUC, recall, etc.).
    """
    try:
        report = train_model(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return report


@app.post("/predict/{model_id}", response_model=PredictResponse)
async def predict(model_id: str, req: PredictRequest):
    """
    Run predictions for the given model on provided traffic windows.
    Returns predictions, raw scores, and model params.
    """
    try:
        resp = predict_with_model(model_id, req)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return resp


@app.get("/analyze/{ip}/{model_id}", response_model=AnalyzeResponse)
async def analyze(ip: str, model_id: str):
    """
    Fetch the latest up to 5 traffic windows from network_sniffer for the IP
    and classify them with the specified model.

    If ALL of those windows are classified as DDoS (prediction == 1),
    we consider there to be an ongoing attack.
    """
    try:
        result = await analyze_ip(ip, model_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@app.delete("/delete/{model_name}")
async def delete_model(model_name: str):
    """
    Delete a model from memory by its name (model_id).
    """
    try:
        model_manager.delete_model(model_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Model '{model_name}' not found")

    return {"status": "deleted", "model_name": model_name}
