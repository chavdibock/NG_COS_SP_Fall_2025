# config/config.py

from pydantic import  AnyHttpUrl
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Base URL of the network_sniffer service
    SNIFFER_BASE_URL: AnyHttpUrl = "http://localhost:8001"

    # Threshold used for recall metric (applied to raw scores)
    DEFAULT_RECALL_THRESHOLD: float = 0.5

    class Config:
        env_file = ".env"


settings = Settings()
