# LLM Provider Runtime Configuration

The project supports multiple LLM providers through environment variables.

## Local mode

No API call. Uses local deterministic agent heuristics.

```bash
export LLM_PROVIDER=local
```

## DeepSeek

```bash
export LLM_PROVIDER=deepseek
export DEEPSEEK_API_KEY="sk-xxx"
export DEEPSEEK_MODEL="deepseek-chat"
uvicorn backend.main:app --reload
```

## Zhipu GLM

```bash
export LLM_PROVIDER=zhipu
export ZHIPU_API_KEY="xxx"
export ZHIPU_MODEL="glm-4-flash"
uvicorn backend.main:app --reload
```

## OpenAI / GPT

```bash
export LLM_PROVIDER=openai
export OPENAI_API_KEY="sk-xxx"
export OPENAI_MODEL="gpt-4o-mini"
uvicorn backend.main:app --reload
```

## OpenAI-compatible gateway

Use this for SiliconFlow, one-api, local vLLM, proxy gateways, or other OpenAI-compatible endpoints.

```bash
export LLM_PROVIDER=openai-compatible
export LLM_API_KEY="xxx"
export LLM_BASE_URL="https://your-endpoint/v1"
export LLM_MODEL="your-model-name"
uvicorn backend.main:app --reload
```

## Ollama local model

```bash
ollama run qwen2.5-coder:7b
export LLM_PROVIDER=ollama
export OLLAMA_BASE_URL="http://127.0.0.1:11434/v1"
export OLLAMA_MODEL="qwen2.5-coder:7b"
uvicorn backend.main:app --reload
```

The API key is never written to disk by the application. It is only read from the process environment.
