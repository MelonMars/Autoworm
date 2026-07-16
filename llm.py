from functools import lru_cache
from transformers import AutoTokenizer, AutoModelForCausalLM
import json
from pydantic import BaseModel, Field
from typing import Optional
import torch
from transformers import BitsAndBytesConfig
import warnings
import re

warnings.filterwarnings("ignore", category=FutureWarning, module="bitsandbytes")
warnings.filterwarnings("ignore", message=".*_check_is_size.*")

hf_token = "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"
MODEL_ID = "Qwen/Qwen3-4B"
LOCAL_DIR = "./Qwen3-4B"

MAX_INPUT_TOKENS = 4096
MAX_TOTAL_TOKENS = 6144

@lru_cache(maxsize=1)
def _get_model():
    tokenizer = AutoTokenizer.from_pretrained(LOCAL_DIR)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token_id = tokenizer.eos_token_id

    model = AutoModelForCausalLM.from_pretrained(
        LOCAL_DIR,
        device_map="auto",
        torch_dtype=torch.float16,
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4", 
            bnb_4bit_use_double_quant=True,
        ),
    )
    model.eval()
    return tokenizer, model


def request_llm(prompt, system, max_new_tokens=1024, enable_thinking=True,
                schema=None, **gen_kwargs):
    tokenizer, model = _get_model()

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt +
            "First, write your reasoning inside <thought> tags.\n"
            "Then, output the required JSON inside <json> tags."},
    ]

    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        enable_thinking=enable_thinking,
        return_tensors="pt",
        return_dict=True,
        truncation=True,
        max_length=MAX_INPUT_TOKENS,
    )

    device = next(model.parameters()).device
    inputs = {k: v.to(device) for k, v in inputs.items()}

    ALLOWED_GEN_KWARGS = {
        "do_sample", "temperature", "top_p", "top_k",
        "repetition_penalty", "no_repeat_ngram_size",
    }
    gen = {k: v for k, v in gen_kwargs.items() if k in ALLOWED_GEN_KWARGS}
    gen.setdefault("do_sample", False)
    gen["pad_token_id"] = tokenizer.pad_token_id

    input_len = inputs["input_ids"].shape[-1]
    max_new = min(max_new_tokens, MAX_TOTAL_TOKENS - input_len)
    if max_new <= 0:
        raise ValueError(f"Input ({input_len} tokens) exceeds MAX_TOTAL_TOKENS ({MAX_TOTAL_TOKENS})")

    torch.cuda.empty_cache()

    with torch.inference_mode():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new,
            use_cache=True,
            **gen,
        )

    new_tokens = outputs[0][input_len:]

    close_id = tokenizer.convert_tokens_to_ids("</think>")
    if close_id is not None and close_id != tokenizer.unk_token_id:
        idx = (new_tokens == close_id).nonzero().flatten()
        if len(idx):
            new_tokens = new_tokens[idx[-1] + 1:]

    result = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

    del outputs, new_tokens
    torch.cuda.empty_cache()

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