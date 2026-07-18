from functools import lru_cache
import json
import re

from llama_cpp import Llama

MODEL_PATH = "./models/Qwen3-4B-Q5_K_M.gguf"

N_CTX = 8192
MAX_TOTAL_TOKENS = 6144

_ALLOWED_GEN_KWARGS = {
    "do_sample", "temperature", "top_p", "top_k",
    "repetition_penalty", "no_repeat_ngram_size",
}


@lru_cache(maxsize=1)
def _get_model():
    llm = Llama(
        model_path=MODEL_PATH,
        n_ctx=N_CTX,
        n_gpu_layers=-1,
        n_batch=512,
        verbose=False,
    )
    return llm


def _build_sampling(gen_kwargs):
    src = {k: v for k, v in gen_kwargs.items() if k in _ALLOWED_GEN_KWARGS}

    params = {}
    if src.get("do_sample", False):
        if "temperature" in src:
            params["temperature"] = src["temperature"]
        if "top_p" in src:
            params["top_p"] = src["top_p"]
        if "top_k" in src:
            params["top_k"] = src["top_k"]
    else:
        params["temperature"] = 0.0

    if "repetition_penalty" in src:
        params["repeat_penalty"] = src["repetition_penalty"]

    return params


def request_llm(prompt, system, max_new_tokens=1024, enable_thinking=True,
                schema=None, **gen_kwargs):
    llm = _get_model()

    user_content = (
        prompt
        + "First, write your reasoning inside <thought> tags.\n"
        + "Then, output the required JSON inside <json> tags."
    )
    if not enable_thinking:
        user_content += " /no_think"

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]

    max_tokens = min(max_new_tokens, MAX_TOTAL_TOKENS)

    out = llm.create_chat_completion(
        messages=messages,
        max_tokens=max_tokens,
        **_build_sampling(gen_kwargs),
    )

    result = out["choices"][0]["message"]["content"].strip()

    close = result.rfind("</think>")
    if close != -1:
        result = result[close + len("</think>"):].strip()

    return result


def extract_json(text):
    print(f"[*] Extracting JSON from LLM output: {text}")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON object in: {text!r}")
    return json.loads(text[start:end + 1])

if __name__ == "__main__":
    prompt = "What is the capital of France?"
    system = "You are a helpful assistant."
    response = request_llm(prompt, system)
    print(f"LLM Response: {response}")