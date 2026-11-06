"""AI Task Observability & Audit Harness.

Execution harness and middleware to trace, measure, and audit local Ollama AI tasks.
Captures reasoning chains (thinking tokens from reasoning models like qwen3.5:9b),
token consumption metrics, generation throughput (tokens/sec), and latency,
streaming full Elastic Common Schema (ECS) compliant audit logs to Elasticsearch.
"""

import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.client import ElasticClientManager
from src.ollama import OllamaClientManager
from src.proxmox import ProxmoxClientManager


def extract_thinking_and_completion(
    raw_response: str,
    ollama_thinking: Optional[str] = None,
    done_reason: Optional[str] = None,
    completion_tokens: int = 0,
) -> Tuple[Optional[str], str]:
    """Extract reasoning thought trace and final completion from model output.

    Handles both:
    1. Ollama's native top-level 'thinking' field (used by Ollama for reasoning models like qwen3.5:9b).
    2. Embedded <think>...</think> tags inside raw_response.
    3. Truncation handling: If generation stopped due to token limit while still inside the reasoning phase.
    """
    thinking: Optional[str] = ollama_thinking.strip() if (ollama_thinking and ollama_thinking.strip()) else None
    completion: str = raw_response or ""

    if not thinking and "<think>" in completion:
        think_match = re.search(r"<think>(.*?)</think>", completion, re.DOTALL)
        if think_match:
            thinking = think_match.group(1).strip()
            completion = re.sub(r"<think>.*?</think>", "", completion, flags=re.DOTALL)
        else:
            partial_match = re.search(r"<think>(.*)", completion, re.DOTALL)
            if partial_match:
                thinking = partial_match.group(1).strip()
                completion = ""

    completion = completion.strip()

    # If the response is empty because the model spent its entire token limit in the thinking phase
    if not completion and thinking and done_reason == "length":
        completion = (
            f"[Incomplete: Reached max token limit ({completion_tokens} tokens) during reasoning phase. "
            "Increase max_tokens to allow model to emit final answer.]"
        )

    return thinking, completion


class AITaskHarness:
    """Execution and audit harness for local Ollama AI tasks and workflows."""

    DEFAULT_DATA_STREAM = "logs-ai.agent_tasks-default"
    DEFAULT_HEALTH_STREAM = "logs-ai.health-default"

    def __init__(
        self,
        ollama_manager: Optional[OllamaClientManager] = None,
        es_manager: Optional[ElasticClientManager] = None,
        proxmox_manager: Optional[ProxmoxClientManager] = None,
        data_stream: Optional[str] = None,
    ):
        self.ollama = ollama_manager or OllamaClientManager()
        self.es = es_manager or ElasticClientManager()
        self.proxmox = proxmox_manager or ProxmoxClientManager()
        self.data_stream = data_stream or os.getenv("AI_AUDIT_DATA_STREAM", self.DEFAULT_DATA_STREAM)
        self.health_stream = os.getenv("AI_HEALTH_DATA_STREAM", self.DEFAULT_HEALTH_STREAM)

    async def sample_infrastructure(self) -> Dict[str, Any]:
        """Sample current GPU VRAM allocation, active Ollama models, and Proxmox node telemetry."""
        infra: Dict[str, Any] = {
            "ollama_host": self.ollama.host,
            "ollama_port": self.ollama.port,
            "gpu_vram_used_mb": 0.0,
            "running_models_count": 0,
            "active_models": [],
        }
        try:
            running = await self.ollama.get_running_models()
            infra["running_models_count"] = len(running)
            infra["active_models"] = [m.get("name") for m in running]
            infra["gpu_vram_used_mb"] = round(sum(m.get("size_vram_mb", 0.0) for m in running), 1)
        except Exception:
            pass

        if self.proxmox and self.proxmox.is_configured():
            try:
                nodes = await self.proxmox.get_nodes()
                if nodes:
                    first_node = nodes[0]
                    node_name = first_node.get("node", "pve")
                    infra["proxmox_node"] = node_name
                    infra["proxmox_status"] = first_node.get("status", "unknown")
                    detailed = await self.proxmox.get_node_status(node_name)
                    cpu_pct = round((detailed.get("cpu", first_node.get("cpu", 0)) or 0) * 100, 2)
                    mem = detailed.get("memory", {})
                    mem_total = mem.get("total", first_node.get("maxmem", 1)) or 1
                    mem_used = mem.get("used", first_node.get("mem", 0))
                    mem_pct = round((mem_used / mem_total) * 100, 2)
                    infra["proxmox_cpu_pct"] = cpu_pct
                    infra["proxmox_ram_pct"] = mem_pct
            except Exception:
                pass

        return infra

    async def record_infrastructure_snapshot(self) -> Dict[str, Any]:
        """Capture and index a dedicated system health and GPU metric snapshot into Elasticsearch."""
        timestamp = datetime.now(timezone.utc).isoformat()
        infra = await self.sample_infrastructure()
        doc = {
            "@timestamp": timestamp,
            "event": {
                "kind": "metric",
                "category": ["host", "infrastructure", "ai"],
                "type": ["info"],
                "action": "infrastructure_health_snapshot",
                "outcome": "success",
            },
            "infrastructure": infra,
            "host": {
                "name": self.ollama.host,
            },
        }
        try:
            client = self.es.get_client()
            res = await client.index(
                index=self.health_stream,
                document=doc,
                op_type="create",
            )
            return {"status": "success", "audit_id": res.get("_id"), "telemetry": infra}
        except Exception as e:
            return {"status": "error", "error": str(e), "telemetry": infra}

    async def execute_and_audit(
        self,
        prompt: str,
        task_type: str = "general",
        model: str = "llama3.2:3b",
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = "jarvis-agent",
        temperature: Optional[float] = 0.7,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute a prompt via Ollama, record full telemetry, and ingest audit log to Elasticsearch."""
        session_id = session_id or str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        start_wall = datetime.now(timezone.utc).isoformat()
        start_perf = time.perf_counter()

        options: Dict[str, Any] = {}
        if temperature is not None:
            options["temperature"] = temperature
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        generation_result: Optional[Dict[str, Any]] = None
        error_info: Optional[Dict[str, Any]] = None
        thinking: Optional[str] = None
        completion: str = ""
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        tokens_per_second = 0.0
        total_duration_nanos = 0
        latency_ms = 0.0

        try:
            generation_result = await self.ollama.generate(
                model=model,
                prompt=prompt,
                system=system_prompt,
                options=options if options else None,
            )
            elapsed_perf = time.perf_counter() - start_perf
            total_duration_nanos = generation_result.get("total_duration") or int(elapsed_perf * 1_000_000_000)
            latency_ms = round(total_duration_nanos / 1_000_000, 2)

            prompt_tokens = generation_result.get("prompt_eval_count", 0)
            completion_tokens = generation_result.get("eval_count", 0)
            total_tokens = prompt_tokens + completion_tokens
            done_reason = generation_result.get("done_reason")

            raw_response = generation_result.get("response", "")
            ollama_thinking = generation_result.get("thinking")
            thinking, completion = extract_thinking_and_completion(
                raw_response=raw_response,
                ollama_thinking=ollama_thinking,
                done_reason=done_reason,
                completion_tokens=completion_tokens,
            )

            eval_duration_nanos = generation_result.get("eval_duration", 0)
            if eval_duration_nanos > 0 and completion_tokens > 0:
                tokens_per_second = round(completion_tokens / (eval_duration_nanos / 1_000_000_000), 2)
            elif elapsed_perf > 0 and completion_tokens > 0:
                tokens_per_second = round(completion_tokens / elapsed_perf, 2)

        except Exception as e:
            elapsed_perf = time.perf_counter() - start_perf
            latency_ms = round(elapsed_perf * 1000, 2)
            total_duration_nanos = int(elapsed_perf * 1_000_000_000)
            error_info = {
                "message": str(e),
                "type": type(e).__name__,
            }

        # Build ECS-aligned audit document
        infra_telemetry = await self.sample_infrastructure()
        audit_record: Dict[str, Any] = {
            "@timestamp": start_wall,
            "event": {
                "kind": "event",
                "category": ["process", "ai"],
                "type": ["audit", "info"],
                "action": "ai_task_execution",
                "duration": total_duration_nanos,
                "outcome": "failure" if error_info else "success",
            },
            "infrastructure": infra_telemetry,
            "ai": {
                "task_id": task_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "task_type": task_type,
                "model": model,
                "prompt": prompt,
                "system_prompt": system_prompt,
                "completion": completion,
                "thinking": thinking,
                "has_thinking": bool(thinking),
                "tokens": {
                    "prompt": prompt_tokens,
                    "completion": completion_tokens,
                    "total": total_tokens,
                },
                "latency_ms": latency_ms,
                "tokens_per_second": tokens_per_second,
                "done_reason": generation_result.get("done_reason", "unknown") if generation_result else "error",
            },
            "host": {
                "name": self.ollama.host,
            },
        }

        if error_info:
            audit_record["error"] = error_info

        # Ingest into Elasticsearch Data Stream
        es_doc_id = None
        es_ingested = False
        es_error = None
        try:
            client = self.es.get_client()
            index_res = await client.index(
                index=self.data_stream,
                document=audit_record,
                op_type="create",
            )
            es_doc_id = index_res.get("_id")
            es_ingested = True
        except Exception as es_e:
            es_error = str(es_e)

        if error_info:
            return {
                "status": "error",
                "error": error_info["message"],
                "task_id": task_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "model": model,
                "latency_ms": latency_ms,
                "es_ingested": es_ingested,
                "es_error": es_error,
            }

        return {
            "status": "success",
            "task_id": task_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "task_type": task_type,
            "model": model,
            "completion": completion,
            "thinking": thinking,
            "has_thinking": bool(thinking),
            "tokens": {
                "prompt": prompt_tokens,
                "completion": completion_tokens,
                "total": total_tokens,
            },
            "tokens_per_second": tokens_per_second,
            "latency_ms": latency_ms,
            "audit_id": es_doc_id,
            "es_ingested": es_ingested,
            "es_error": es_error,
        }

    async def query_audits(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        task_type: Optional[str] = None,
        hours_back: int = 24,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Query historical AI task execution audit traces from Elasticsearch."""
        client = self.es.get_client()
        must_clauses: List[Dict[str, Any]] = [
            {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{hours_back}h",
                        "lte": "now",
                    }
                }
            }
        ]

        if session_id:
            must_clauses.append({"term": {"ai.session_id": session_id}})
        if agent_id:
            must_clauses.append({"term": {"ai.agent_id": agent_id}})
        if task_type:
            must_clauses.append({"term": {"ai.task_type": task_type}})

        query = {"bool": {"must": must_clauses}}

        try:
            response = await client.search(
                index="logs-ai.agent_tasks-*",
                query=query,
                size=min(limit, 100),
                sort=[{"@timestamp": {"order": "desc"}}],
            )
            hits = response["hits"]["hits"]
            return {
                "total_matches": response["hits"]["total"]["value"],
                "returned_count": len(hits),
                "tasks": [hit["_source"] for hit in hits],
            }
        except Exception as e:
            return {"error": f"Failed to query AI task audits: {str(e)}"}

    async def get_observability_summary(self, hours_back: int = 24) -> Dict[str, Any]:
        """Calculate aggregated throughput, latency, and token consumption statistics."""
        client = self.es.get_client()
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{hours_back}h",
                    "lte": "now",
                }
            }
        }

        aggs = {
            "total_prompt_tokens": {"sum": {"field": "ai.tokens.prompt"}},
            "total_completion_tokens": {"sum": {"field": "ai.tokens.completion"}},
            "total_tokens": {"sum": {"field": "ai.tokens.total"}},
            "avg_latency_ms": {"avg": {"field": "ai.latency_ms"}},
            "avg_tokens_per_second": {"avg": {"field": "ai.tokens_per_second"}},
            "outcomes": {"terms": {"field": "event.outcome", "size": 5}},
            "models": {"terms": {"field": "ai.model", "size": 10}},
            "task_types": {"terms": {"field": "ai.task_type", "size": 10}},
        }

        try:
            response = await client.search(
                index="logs-ai.agent_tasks-*",
                query=time_filter,
                size=5,
                sort=[{"@timestamp": {"order": "desc"}}],
                aggs=aggs,
            )
            aggregations = response.get("aggregations", {})
            total_tasks = response["hits"]["total"]["value"]

            return {
                "time_window_hours": hours_back,
                "total_tasks_executed": total_tasks,
                "token_usage": {
                    "total_prompt_tokens": int(aggregations.get("total_prompt_tokens", {}).get("value") or 0),
                    "total_completion_tokens": int(aggregations.get("total_completion_tokens", {}).get("value") or 0),
                    "total_tokens": int(aggregations.get("total_tokens", {}).get("value") or 0),
                },
                "performance": {
                    "avg_latency_ms": round(aggregations.get("avg_latency_ms", {}).get("value") or 0.0, 2),
                    "avg_tokens_per_second": round(aggregations.get("avg_tokens_per_second", {}).get("value") or 0.0, 2),
                },
                "breakdown": {
                    "by_outcome": [
                        {"status": b["key"], "count": b["doc_count"]}
                        for b in aggregations.get("outcomes", {}).get("buckets", [])
                    ],
                    "by_model": [
                        {"model": b["key"], "count": b["doc_count"]}
                        for b in aggregations.get("models", {}).get("buckets", [])
                    ],
                    "by_task_type": [
                        {"task_type": b["key"], "count": b["doc_count"]}
                        for b in aggregations.get("task_types", {}).get("buckets", [])
                    ],
                },
                "recent_tasks": [
                    {
                        "task_id": h["_source"].get("ai", {}).get("task_id"),
                        "timestamp": h["_source"].get("@timestamp"),
                        "model": h["_source"].get("ai", {}).get("model"),
                        "task_type": h["_source"].get("ai", {}).get("task_type"),
                        "tokens_total": h["_source"].get("ai", {}).get("tokens", {}).get("total"),
                        "tokens_per_second": h["_source"].get("ai", {}).get("tokens_per_second"),
                        "latency_ms": h["_source"].get("ai", {}).get("latency_ms"),
                        "has_thinking": h["_source"].get("ai", {}).get("has_thinking"),
                    }
                    for h in response["hits"]["hits"]
                ],
            }
        except Exception as e:
            return {"error": f"Failed to retrieve observability summary: {str(e)}"}
