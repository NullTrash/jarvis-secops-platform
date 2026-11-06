"""Ollama GPU Compute REST API client manager.

Connects to the local Ollama instance on the GPU compute node to monitor
installed models, active VRAM allocations, and manage model downloads/offloading.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
load_dotenv()


class OllamaClientManager:
    """Manages asynchronous communication with the Ollama REST API."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: float = 30.0,
    ):
        self.host = host or os.getenv("OLLAMA_HOST", os.getenv("ELASTIC_HOST", "10.0.0.20"))
        self.port = port or int(os.getenv("OLLAMA_PORT", "11434"))
        self.base_url = f"http://{self.host}:{self.port}"
        self.timeout = timeout

    async def get_version(self) -> str:
        """Retrieve Ollama daemon version."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/api/version")
            resp.raise_for_status()
            return resp.json().get("version", "unknown")

    async def get_installed_models(self) -> List[Dict[str, Any]]:
        """Retrieve list of all models downloaded locally in Ollama."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/api/tags")
            resp.raise_for_status()
            models = resp.json().get("models", [])
            parsed = []
            for m in models:
                details = m.get("details", {})
                size_bytes = m.get("size", 0)
                parsed.append({
                    "name": m.get("name"),
                    "size_mb": round(size_bytes / (1024**2), 1),
                    "size_gb": round(size_bytes / (1024**3), 2),
                    "parameter_size": details.get("parameter_size"),
                    "quantization_level": details.get("quantization_level"),
                    "format": details.get("format"),
                    "family": details.get("family"),
                    "capabilities": m.get("capabilities", []),
                    "modified_at": m.get("modified_at"),
                })
            return parsed

    async def get_running_models(self) -> List[Dict[str, Any]]:
        """Retrieve models currently loaded in GPU VRAM or system RAM."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/api/ps")
            resp.raise_for_status()
            models = resp.json().get("models", [])
            parsed = []
            for m in models:
                size_bytes = m.get("size", 0)
                size_vram = m.get("size_vram", 0)
                parsed.append({
                    "name": m.get("name"),
                    "size_mb": round(size_bytes / (1024**2), 1),
                    "size_vram_mb": round(size_vram / (1024**2), 1),
                    "vram_percentage": round((size_vram / size_bytes * 100), 1) if size_bytes > 0 else 0,
                    "expires_at": m.get("expires_at"),
                    "details": m.get("details", {}),
                })
            return parsed

    async def pull_model(self, model_name: str) -> Dict[str, Any]:
        """Trigger pulling a model from the Ollama library."""
        # Use an extended timeout for downloading large models
        async with httpx.AsyncClient(timeout=600.0) as client:
            resp = await client.post(
                f"{self.base_url}/api/pull",
                json={"name": model_name, "stream": False},
            )
            resp.raise_for_status()
            return resp.json()

    async def generate(
        self,
        model: str,
        prompt: str,
        system: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        keep_alive: Optional[str] = "10m",
        timeout: float = 180.0,
    ) -> Dict[str, Any]:
        """Execute a text completion generation request against an Ollama model."""
        payload: Dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system
        if options:
            payload["options"] = options
        if keep_alive:
            payload["keep_alive"] = keep_alive

        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{self.base_url}/api/generate", json=payload)
            resp.raise_for_status()
            return resp.json()

    async def unload_model(self, model_name: str) -> Dict[str, Any]:
        """Unload a model from VRAM by setting keep_alive to 0."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/generate",
                json={"model": model_name, "keep_alive": 0},
            )
            resp.raise_for_status()
            return {"status": "unloaded", "model": model_name}
