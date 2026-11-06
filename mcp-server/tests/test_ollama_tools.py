import pytest
from unittest.mock import AsyncMock, patch
from src.server import (
    get_ollama_status,
    get_ollama_running_models,
    pull_ollama_model,
    unload_ollama_model,
)


@pytest.mark.asyncio
async def test_get_ollama_status_success():
    mock_models = [
        {
            "name": "qwen3.5:2b",
            "size_mb": 2559.1,
            "size_gb": 2.5,
            "parameter_size": "1.9B",
            "quantization_level": "Q8_0",
            "format": "gguf",
            "family": "qwen35",
            "capabilities": ["completion", "vision"],
            "modified_at": "2026-10-17T19:54:24Z",
        },
        {
            "name": "nomic-embed-text:latest",
            "size_mb": 261.6,
            "size_gb": 0.26,
            "parameter_size": "137M",
            "quantization_level": "F16",
            "format": "gguf",
            "family": "nomic-bert",
            "capabilities": ["embedding"],
            "modified_at": "2026-10-17T19:54:31Z",
        },
    ]

    with patch("src.server.ollama_manager.get_version", new_callable=AsyncMock, return_value="0.40.6"), \
         patch("src.server.ollama_manager.get_installed_models", new_callable=AsyncMock, return_value=mock_models):
        res = await get_ollama_status()
        assert res["status"] == "online"
        assert res["version"] == "0.40.6"
        assert res["total_models"] == 2
        assert res["total_storage_gb"] == 2.76
        assert res["models"][0]["name"] == "qwen3.5:2b"


@pytest.mark.asyncio
async def test_get_ollama_running_models_success():
    mock_running = [
        {
            "name": "qwen3.5:2b",
            "size_mb": 2559.1,
            "size_vram_mb": 2559.1,
            "vram_percentage": 100.0,
            "expires_at": "2026-10-25T14:00:00Z",
            "details": {"family": "qwen35"},
        }
    ]

    with patch("src.server.ollama_manager.get_running_models", new_callable=AsyncMock, return_value=mock_running):
        res = await get_ollama_running_models()
        assert res["loaded_models_count"] == 1
        assert res["total_vram_used_mb"] == 2559.1
        assert res["running_models"][0]["name"] == "qwen3.5:2b"


@pytest.mark.asyncio
async def test_pull_ollama_model_success():
    with patch("src.server.ollama_manager.pull_model", new_callable=AsyncMock, return_value={"status": "success"}):
        res = await pull_ollama_model(model_name="qwen3.5:9b")
        assert res["status"] == "success"
        assert res["model"] == "qwen3.5:9b"


@pytest.mark.asyncio
async def test_unload_ollama_model_success():
    with patch("src.server.ollama_manager.unload_model", new_callable=AsyncMock, return_value={"status": "unloaded", "model": "qwen3.5:2b"}):
        res = await unload_ollama_model(model_name="qwen3.5:2b")
        assert res["status"] == "unloaded"
        assert res["model"] == "qwen3.5:2b"
