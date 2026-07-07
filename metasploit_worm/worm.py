import json
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from pymetasploit3.msfrpc import MsfRpcClient


MODEL_ID = "Qwen/Qwen3.5-2B" 

MSF_PASSWORD = "msf"
MSF_SERVER = "127.0.0.1"
MSF_PORT = 55553

print("Loading LLM...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID, 
    torch_dtype=torch.float16, 
    device_map="auto"
)

print("Connecting to Metasploit RPC...")
msf_client = MsfRpcClient(MSF_PASSWORD, server=MSF_SERVER, port=MSF_PORT)

def get_module_info(module_name):
    try:
        mod = msf_client.modules.get('auxiliary', module_name)
        info = {
            "name": mod.name,
            "description": mod.description,
            "options": mod.options
        }

        return json.dumps(info, indent=2)[:1500] 
    except Exception as e:
        return f"Error retrieving module: {str(e)}"

def run_agent_loop(initial_prompt):
    system_prompt = """You are a penetration testing assistant. 
You have access to a tool called `get_module_info(module_name)`.
To use a tool, respond ONLY with a JSON object in this format:
{"action": "get_module_info", "module_name": "scanner/http/http_version"}
Once you have the information you need, respond with a summary and include {"action": "finish"} in your JSON."""

    conversation = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": initial_prompt}
    ]

    max_iterations = 5

    for i in range(max_iterations):
        print(f"\n--- Iteration {i+1} ---")
        
        input_ids = tokenizer.apply_chat_template(
            conversation, 
            add_generation_prompt=True, 
            return_tensors="pt"
        ).to(model.device)

        outputs = model.generate(
            input_ids, 
            max_new_tokens=512, 
            do_sample=False,
            temperature=0.0
        )
        
        response = tokenizer.decode(outputs[0][input_ids.shape[1]:], skip_special_tokens=True)
        print(f"LLM Output:\n{response}")

        try:
            clean_response = response.strip().replace("```json", "").replace("```", "").strip()
            action_json = json.loads(clean_response)
            
            action = action_json.get("action")
            
            if action == "get_module_info":
                module_name = action_json.get("module_name")
                print(f"Executing tool: get_module_info({module_name})")
                tool_result = get_module_info(module_name)
                
                conversation.append({"role": "assistant", "content": response})
                conversation.append({"role": "user", "content": f"Tool Result: {tool_result}"})
                
            elif action == "finish":
                print("Agent decided to finish.")
                break
                
        except json.JSONDecodeError:
            print("LLM did not return valid JSON. Asking for correction.")
            conversation.append({"role": "assistant", "content": response})
            conversation.append({"role": "user", "content": "Error: Invalid JSON. Please respond with the correct JSON format."})

if __name__ == "__main__":
    run_agent_loop("Please get the information for the auxiliary scanner 'scanner/http/http_version'.")