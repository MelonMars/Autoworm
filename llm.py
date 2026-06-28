from functools import lru_cache
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_ID = "Qwen/Qwen3-4B"

@lru_cache(maxsize=1)
def _get_model():
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, dtype="auto", device_map="auto")
    return tokenizer, model

def request_llm(prompt: str, system: str, max_new_tokens: int = 1024) -> str:
    tokenizer, model = _get_model()
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]
    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        enable_thinking=True,
        return_tensors="pt",
        return_dict=True,
    ).to(model.device)

    outputs = model.generate(**inputs, max_new_tokens=max_new_tokens)
    new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]

    think_close = tokenizer.convert_tokens_to_ids(tokenizer.thinking_close_token)
    idx = (new_tokens == think_close).nonzero().flatten()
    if len(idx): new_tokens = new_tokens[idx[-1] + 1:]
    return tokenizer.decode(new_tokens, skip_special_tokens=True).strip()