# main.py

from fastapi import FastAPI, HTTPException

from schemas.schemas import (
    TrainRequest,
    TrainReport,
    PredictRequest,
    PredictResponse,
    AnalyzeResponse,
    AnalyzeMultiResponse,
    AnalyzeModelsRequest,
    TestRequest,
    TestReport,
)
from models.manager import model_manager

from services.analysis_service import (
    train_model,
    predict_with_model,
    analyze_ip,
    analyze_ip_multiple,
    train_all_models_on_startup,
    test_model,

)


app = FastAPI()


@app.on_event("startup")
async def load_models_on_startup():
    model_manager.load_from_csv_files()
    await train_all_models_on_startup()


@app.get("/models")
async def list_models():
    return model_manager.list_models()


@app.post("/train", response_model=TrainReport)
async def train(req: TrainRequest):

    try:
        report = train_model(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return report


@app.post("/predict/{model_id}", response_model=PredictResponse)
async def predict(model_id: str, req: PredictRequest):

    try:
        resp = predict_with_model(model_id, req)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return resp


@app.post("/test/{model_id}", response_model=TestReport)
async def test(model_id: str, req: TestRequest):
    try:
        result = test_model(model_id, req)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


@app.get("/analyze/{ip}/{model_id}", response_model=AnalyzeResponse)
async def analyze(ip: str, model_id: str):

    try:
        result = await analyze_ip(ip, model_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@app.get("/analyze_all/{ip}", response_model=AnalyzeMultiResponse)
async def analyze_all_models(ip: str):
    try:
        result = await analyze_ip_multiple(ip)
    except KeyError as e:
        # Unknown model id somewhere in the list
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@app.post("/analyze/{ip}/models", response_model=AnalyzeMultiResponse)
async def analyze_specific_models(ip: str, req: AnalyzeModelsRequest):
    try:
        result = await analyze_ip_multiple(ip, req.model_ids)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result
@app.delete("/delete/{model_name}")
async def delete_model(model_name: str):

    try:
        model_manager.delete_model(model_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Model '{model_name}' not found")

    return {"status": "deleted", "model_name": model_name}
