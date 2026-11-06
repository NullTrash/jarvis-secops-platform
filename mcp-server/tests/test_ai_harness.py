import pytest
from unittest.mock import AsyncMock, patch
from src.ai_harness import extract_thinking_and_completion
from src.server import (
    execute_ai_task,
    query_ai_task_audits,
    get_ai_observability_summary,
    record_system_health,
)


def test_extract_thinking_with_tags():
    raw = "<think>\nAnalyzing firewall rule drop.\nPort 22 is SSH.\n</think>\nAction is benign scanner."
    thinking, completion = extract_thinking_and_completion(raw)
    assert thinking == "Analyzing firewall rule drop.\nPort 22 is SSH."
    assert completion == "Action is benign scanner."


def test_extract_thinking_without_tags():
    raw = "The destination IP is safe."
    thinking, completion = extract_thinking_and_completion(raw)
    assert thinking is None
    assert completion == "The destination IP is safe."


def test_extract_native_ollama_thinking_with_response():
    raw = "Yes, SSH exposure on WAN is risky."
    thinking, completion = extract_thinking_and_completion(
        raw_response=raw,
        ollama_thinking="Evaluating WAN exposure of port 22...",
        done_reason="stop",
        completion_tokens=50,
    )
    assert thinking == "Evaluating WAN exposure of port 22..."
    assert completion == "Yes, SSH exposure on WAN is risky."


def test_extract_native_ollama_thinking_token_limit_exhausted():
    raw = ""
    thinking, completion = extract_thinking_and_completion(
        raw_response=raw,
        ollama_thinking="Here is a multi-step thinking process that runs out of tokens...",
        done_reason="length",
        completion_tokens=250,
    )
    assert thinking == "Here is a multi-step thinking process that runs out of tokens..."
    assert "[Incomplete: Reached max token limit (250 tokens) during reasoning phase" in completion


@pytest.mark.asyncio
async def test_execute_ai_task_success():
    mock_ollama_response = {
        "model": "qwen3.5:9b",
        "response": "<think>Checking IP reputation.</think>IP 198.51.100.1 is known research scanner.",
        "total_duration": 1_200_000_000,
        "load_duration": 100_000_000,
        "prompt_eval_count": 15,
        "prompt_eval_duration": 200_000_000,
        "eval_count": 30,
        "eval_duration": 900_000_000,
        "done_reason": "stop",
    }
    mock_es_index_response = {"_id": "audit_abc123", "result": "created"}

    mock_es_client = AsyncMock()
    mock_es_client.index = AsyncMock(return_value=mock_es_index_response)

    with patch("src.server.ollama_manager.generate", new_callable=AsyncMock, return_value=mock_ollama_response) as mock_gen, \
         patch("src.server.ai_harness.sample_infrastructure", new_callable=AsyncMock, return_value={"running_models_count": 0}), \
         patch("src.server.es_manager.get_client", return_value=mock_es_client):
        res = await execute_ai_task(
            prompt="Analyze this IP: 198.51.100.1",
            task_type="threat-analysis",
            model="qwen3.5:9b",
            session_id="session-test-01",
            agent_id="subagent-triage",
        )

        assert res["status"] == "success"
        assert res["model"] == "qwen3.5:9b"
        assert res["task_type"] == "threat-analysis"
        assert res["session_id"] == "session-test-01"
        assert res["agent_id"] == "subagent-triage"
        assert res["thinking"] == "Checking IP reputation."
        assert res["completion"] == "IP 198.51.100.1 is known research scanner."
        assert res["has_thinking"] is True
        assert res["tokens"]["prompt"] == 15
        assert res["tokens"]["completion"] == 30
        assert res["tokens"]["total"] == 45
        assert res["tokens_per_second"] == 33.33
        assert res["latency_ms"] == 1200.0
        assert res["audit_id"] == "audit_abc123"
        assert res["es_ingested"] is True

        # Verify ES document structure
        mock_es_client.index.assert_called_once()
        call_kwargs = mock_es_client.index.call_args.kwargs
        assert call_kwargs["index"] == "logs-ai.agent_tasks-default"
        assert call_kwargs["op_type"] == "create"
        doc = call_kwargs["document"]
        assert doc["event"]["outcome"] == "success"
        assert doc["ai"]["task_type"] == "threat-analysis"
        assert doc["ai"]["thinking"] == "Checking IP reputation."
        assert doc["ai"]["tokens"]["total"] == 45


@pytest.mark.asyncio
async def test_execute_ai_task_ollama_error():
    mock_es_client = AsyncMock()
    mock_es_client.index = AsyncMock(return_value={"_id": "audit_err_456"})

    with patch("src.server.ollama_manager.generate", new_callable=AsyncMock, side_effect=RuntimeError("Ollama CUDA Out Of Memory")), \
         patch("src.server.ai_harness.sample_infrastructure", new_callable=AsyncMock, return_value={"running_models_count": 0}), \
         patch("src.server.es_manager.get_client", return_value=mock_es_client):
        res = await execute_ai_task(
            prompt="Analyze this huge payload",
            task_type="secops-triage",
        )

        assert res["status"] == "error"
        assert "Ollama CUDA Out Of Memory" in res["error"]
        assert res["es_ingested"] is True

        # Verify ES captured the failure
        mock_es_client.index.assert_called_once()
        doc = mock_es_client.index.call_args.kwargs["document"]
        assert doc["event"]["outcome"] == "failure"
        assert doc["error"]["message"] == "Ollama CUDA Out Of Memory"


@pytest.mark.asyncio
async def test_query_ai_task_audits():
    mock_search_res = {
        "hits": {
            "total": {"value": 2},
            "hits": [
                {
                    "_source": {
                        "@timestamp": "2026-11-04T21:00:00Z",
                        "ai": {
                            "task_id": "t-1",
                            "model": "qwen3.5:9b",
                            "task_type": "secops-triage",
                            "completion": "Drop rule is active.",
                        },
                    }
                },
                {
                    "_source": {
                        "@timestamp": "2026-11-04T21:05:00Z",
                        "ai": {
                            "task_id": "t-2",
                            "model": "qwen3.5:9b",
                            "task_type": "secops-triage",
                            "completion": "No lateral movement.",
                        },
                    }
                },
            ],
        }
    }
    mock_es_client = AsyncMock()
    mock_es_client.search = AsyncMock(return_value=mock_search_res)

    with patch("src.server.es_manager.get_client", return_value=mock_es_client):
        res = await query_ai_task_audits(task_type="secops-triage", hours_back=12)
        assert res["total_matches"] == 2
        assert len(res["tasks"]) == 2
        assert res["tasks"][0]["ai"]["task_id"] == "t-1"


@pytest.mark.asyncio
async def test_get_ai_observability_summary():
    mock_agg_res = {
        "hits": {
            "total": {"value": 15},
            "hits": [
                {
                    "_source": {
                        "@timestamp": "2026-11-04T21:00:00Z",
                        "ai": {
                            "task_id": "t-recent",
                            "model": "qwen3.5:9b",
                            "task_type": "threat-analysis",
                            "tokens": {"total": 120},
                            "tokens_per_second": 45.2,
                            "latency_ms": 1150.0,
                            "has_thinking": True,
                        },
                    }
                }
            ],
        },
        "aggregations": {
            "total_prompt_tokens": {"value": 1500.0},
            "total_completion_tokens": {"value": 3500.0},
            "total_tokens": {"value": 5000.0},
            "avg_latency_ms": {"value": 980.5},
            "avg_tokens_per_second": {"value": 48.7},
            "outcomes": {"buckets": [{"key": "success", "doc_count": 14}, {"key": "failure", "doc_count": 1}]},
            "models": {"buckets": [{"key": "qwen3.5:9b", "doc_count": 12}, {"key": "qwen3.5:2b", "doc_count": 3}]},
            "task_types": {"buckets": [{"key": "threat-analysis", "doc_count": 10}, {"key": "secops-triage", "doc_count": 5}]},
        },
    }
    mock_es_client = AsyncMock()
    mock_es_client.search = AsyncMock(return_value=mock_agg_res)

    with patch("src.server.es_manager.get_client", return_value=mock_es_client):
        summary = await get_ai_observability_summary(hours_back=24)
        assert summary["total_tasks_executed"] == 15
        assert summary["token_usage"]["total_tokens"] == 5000
        assert summary["token_usage"]["total_completion_tokens"] == 3500
        assert summary["performance"]["avg_latency_ms"] == 980.5
        assert summary["performance"]["avg_tokens_per_second"] == 48.7
        assert len(summary["breakdown"]["by_model"]) == 2
        assert summary["breakdown"]["by_model"][0]["model"] == "qwen3.5:9b"
        assert len(summary["recent_tasks"]) == 1


@pytest.mark.asyncio
async def test_record_system_health():
    mock_running = [
        {"name": "qwen3.5:9b", "size_vram_mb": 3900.0}
    ]
    mock_es_client = AsyncMock()
    mock_es_client.index = AsyncMock(return_value={"_id": "health_snap_1"})

    with patch("src.server.ollama_manager.get_running_models", new_callable=AsyncMock, return_value=mock_running), \
         patch("src.server.proxmox_manager.is_configured", return_value=False), \
         patch("src.server.es_manager.get_client", return_value=mock_es_client):
        res = await record_system_health()
        assert res["status"] == "success"
        assert res["audit_id"] == "health_snap_1"
        assert res["telemetry"]["gpu_vram_used_mb"] == 3900.0


