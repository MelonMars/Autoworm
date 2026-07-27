# llm.py
from functools import lru_cache
import json
import re
import logging

from llama_cpp import Llama
from pydantic import BaseModel
import inspect

def _to_json_schema(schema):
    if schema is None:
        return None
    if inspect.isclass(schema) and issubclass(schema, BaseModel):
        return schema.model_json_schema()
    return schema

logger = logging.getLogger(__name__)

MODEL_PATHS = {
    1: "./models/Qwen3.6-27B-Fable-Fus-711-UnHeretic-NM-DAU-NEO-MAX-NEO-MTP-Q5_K_M.gguf",
    0: "./models/Qwen3-4B-Q5_K_M.gguf",
}

MODEL_OPTS = {
    0: {"n_ctx": 16384,  "n_gpu_layers": -1, "n_batch": 512},
    1: {"n_ctx": 16384, "n_gpu_layers": -1, "n_batch": 512},
}

_MODELS = {}

_ALLOWED_GEN_KWARGS = {
    "temperature",
    "top_p",
    "top_k",
    "repetition_penalty",
    "do_sample",
}

def _get_model(level=0):
    if level not in MODEL_PATHS:
        raise ValueError(f"Unknown level {level!r}; expected one of {sorted(MODEL_PATHS)}")
    if level not in _MODELS:
        logger.info("Loading level %s: %s", level, MODEL_PATHS[level])
        _MODELS[level] = Llama(
            model_path=MODEL_PATHS[level],
            verbose=False,
            **MODEL_OPTS[level],
        )
    return _MODELS[level]

def unload_model(level):
    llm = _MODELS.pop(level, None)
    if llm is not None:
        llm.close()

def _build_sampling(gen_kwargs):
    src = {k: v for k, v in gen_kwargs.items() if k in _ALLOWED_GEN_KWARGS}
    params = {}
    if src.get("do_sample", False):
        if "temperature" in src: params["temperature"] = src["temperature"]
        if "top_p" in src: params["top_p"] = src["top_p"]
        if "top_k" in src: params["top_k"] = src["top_k"]
    else:
        params["temperature"] = 0.0
    if "repetition_penalty" in src:
        params["repeat_penalty"] = src["repetition_penalty"]
    return params

def request_llm(prompt, system, max_new_tokens=1024, enable_thinking=True, schema=None, level=0, **gen_kwargs):
    llm = _get_model(level=level)
    
    user_content = (
        prompt
        + "\n\nOutput your final answer as a single JSON object. You may wrap it in <json> tags if helpful."
    )
    if not enable_thinking:
        user_content += " /no_think"

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]

    out = llm.create_chat_completion(
        messages=messages,
        max_tokens=max_new_tokens,
        response_format={"type": "json_object", "schema": _to_json_schema(schema)} if schema else None,
        stop=["</json>"],
        **_build_sampling(gen_kwargs),
    )

    result = out["choices"][0]["message"]["content"].strip()
    close = result.rfind("<tool_call>")
    if close != -1:
        result = result[close + len("<tool_call>"):].strip()

    return result

def extract_json(text):
    json_match = re.search(r'<json>\s*(.*?)\s*</json>', text, re.DOTALL)
    if json_match:
        text = json_match.group(1)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    if start == -1:
        logger.error(f"Failed to extract JSON. No '{{' found. Raw output:\n{text[:500]}")
        raise ValueError(f"No JSON object found in LLM output.")

    stack = []
    in_string = False
    escape = False
    
    for i, char in enumerate(text[start:]):
        if in_string:
            if char == '\\' and not escape:
                escape = True
            elif escape:
                escape = False
            elif char == '"':
                in_string = False
        else:
            if char == '{':
                stack.append(i)
            elif char == '}':
                if stack:
                    start_idx = stack.pop()
                    if not stack:
                        json_str = text[start + start_idx : start + i + 1]
                        try:
                            return json.loads(json_str)
                        except json.JSONDecodeError as e:
                            logger.error(f"JSON decode error: {e}")
                            logger.debug(f"Failed raw text:\n{json_str}")
                            raise ValueError(f"JSON decode error: {e}")

    logger.error(f"Failed to extract JSON. Unbalanced braces. Raw output:\n{text[:500]}")
    raise ValueError(f"No JSON object found in LLM output.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    prompt = "What is the capital of France?"
    system = "You are a helpful assistant."
    response = request_llm(prompt, system)
    print(f"LLM Response: {response}")