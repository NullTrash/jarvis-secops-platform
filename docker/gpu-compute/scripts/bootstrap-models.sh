#!/usr/bin/env bash
# ==============================================================================
# Jarvis GPU Worker Model Bootstrapper
# Pulls worker subagent models into the 24/7 Ollama GPU instance
# ==============================================================================

set -e

OLLAMA_HOST="${1:-http://localhost:11434}"

echo "[*] Connecting to Ollama at ${OLLAMA_HOST}..."

MODELS=(
    "qwen3.5:9b"       # Primary high-speed local worker for SecOps & log parsing
    "qwen3.5:2b"       # Ultra-lightweight JSON extractor & router
    "nomic-embed-text" # Local embedding model for semantic log / document search
)

for model in "${MODELS[@]}"; do
    echo "[+] Pulling model: ${model}..."
    curl -s "${OLLAMA_HOST}/api/pull" -d "{\"name\": \"${model}\"}" | while read -r line; do
        status=$(echo "$line" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$status" ]; then
            printf "\r\033[K[~] %s: %s" "$model" "$status"
        fi
    done
    echo ""
    echo "[✓] Successfully downloaded ${model}"
done

echo "[★] All worker subagent models are ready on Ollama GPU compute node!"
