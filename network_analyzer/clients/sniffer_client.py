# clients/sniffer_client.py

from typing import Dict, Any
import httpx
from fastapi import HTTPException

from config.config import settings


class SnifferClient:
    def __init__(self, base_url: str = None):
        self.base_url = base_url or str(settings.SNIFFER_BASE_URL)

    async def get_packets(self, ip: str) -> Dict[str, Any]:
        url = f"{self.base_url}/packets/{ip}"
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(url, timeout=10.0)
            except httpx.RequestError as exc:
                raise HTTPException(
                    status_code=503,
                    detail=f"Failed to reach network_sniffer: {exc}"
                )

        if resp.status_code != 200:
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"network_sniffer error: {resp.text}"
            )

        return resp.json()
