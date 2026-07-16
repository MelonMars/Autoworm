from huggingface_hub import snapshot_download
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch, os

MODEL_ID = "google/gemma-4-E4B"
LOCAL_DIR = "./gemma-4-E4B"
hf_token = "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"

snapshot_download(
    repo_id=MODEL_ID,
    local_dir=LOCAL_DIR,
    token=hf_token,

    # ignore_patterns=["*.pth", "*.gguf", "original/*"],
)

tokenizer = AutoTokenizer.from_pretrained(LOCAL_DIR)
model = AutoModelForCausalLM.from_pretrained(
    LOCAL_DIR,
    device_map="auto",
    quantization_config=BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.float16,
    ),
)

print("loaded from", LOCAL_DIR)