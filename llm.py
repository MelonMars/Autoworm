from functools import lru_cache
from transformers import AutoTokenizer, AutoModelForCausalLM
import json
from pydantic import BaseModel, Field
from typing import Optional
import torch
from transformers import BitsAndBytesConfig

hf_token = "" # Only for downloading the model from HF hub. Ideally, we would just ship the model w/ the entire thing, and not require a token, but for bootstrapping it, the token is the only way to download it in a reasonable (<2h) timeframe.
MODEL_ID = "Qwen/Qwen3-8B"
LOCAL_DIR = "./Qwen3-8B"

@lru_cache(maxsize=1)
def _get_model():
    tokenizer = AutoTokenizer.from_pretrained(LOCAL_DIR)
    model = AutoModelForCausalLM.from_pretrained(
        LOCAL_DIR,
        device_map="auto",
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
        ),
    )
    return tokenizer, model

def request_llm(prompt, system, max_new_tokens=1024, enable_thinking=True, schema=None, **gen_kwargs):
    tokenizer, model = _get_model()
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]
    inputs = tokenizer.apply_chat_template(
        messages,

        add_generation_prompt=True,
        enable_thinking=enable_thinking,
        return_tensors="pt",
        return_dict=True,
    ).to(model.device)

    gen = dict(gen_kwargs)
    if schema is not None:
            # parser = JsonSchemaParser(schema.model_json_schema())
            # gen["prefix_allowed_tokens_fn"] = (
            #     build_transformers_prefix_allowed_tokens_fn(tokenizer, parser)
            # )
        pass
    
    outputs = model.generate(**inputs, max_new_tokens=max_new_tokens, **gen)
    new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]

    close_id = tokenizer.convert_tokens_to_ids("</think>")
    idx = (new_tokens == close_id).nonzero().flatten()
    if len(idx):
        new_tokens = new_tokens[idx[-1] + 1:]
    return tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

def extract_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON object in: {text!r}")
    return json.loads(text[start:end + 1])
