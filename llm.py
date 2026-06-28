from functools import lru_cache
from transformers import AutoTokenizer, AutoModelForCausalLM
import json

MODEL_ID = "Qwen/Qwen3-4B"

@lru_cache(maxsize=1)
def _get_model():
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, dtype="auto", device_map="auto")
    return tokenizer, model

def request_llm(prompt, system, max_new_tokens=1024, enable_thinking=True, **gen_kwargs):
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

    outputs = model.generate(**inputs, max_new_tokens=max_new_tokens, **gen_kwargs)
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
