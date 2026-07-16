import pickle
import os
import json
from pprint import pprint

CHECKPOINT_PATH = "campaign_checkpoint.pkl"

def load_checkpoint():
    if not os.path.exists(CHECKPOINT_PATH):
        print(f"[-] Checkpoint file not found at {CHECKPOINT_PATH}")
        return None
    with open(CHECKPOINT_PATH, "rb") as f:
        return pickle.load(f)

def save_checkpoint(state):
    tmp = CHECKPOINT_PATH + ".tmp"
    with open(tmp, "wb") as f:
        pickle.dump(state, f)
    os.replace(tmp, CHECKPOINT_PATH)
    print(f"\n[+] Checkpoint saved successfully to {CHECKPOINT_PATH}")

def main():
    state = load_checkpoint()
    if not state:
        return

    host = state.get("host")
    if not host:
        print("[-] No host found in checkpoint.")
        return

    while True:
        print("\n" + "="*50)
        print(" MEMORY & HYPOTHESIS EDITOR ")
        print("="*50)
        print(f"1. Show Host Overview (IP, OS, Foothold)")
        print(f"2. Show Facts")
        print(f"3. Show Vulnerabilities")
        print(f"4. List Hypotheses")
        print(f"5. Add Hypothesis")
        print(f"6. Remove Hypothesis by Index")
        print(f"7. Clear All Hypotheses")
        print(f"8. Force Set Foothold (For testing post-exploitation)")
        print(f"9. Clear Facts")
        print(f"10. Save & Exit")
        print(f"11. Exit without saving")
        
        choice = input("\nSelect an option (1-11): ").strip()

        if choice == '1':
            print(f"\nIP: {host.ip}")
            print(f"OS: {host.os}")
            print(f"Hostname: {host.hostname}")
            print(f"State: {host.state}")
            print(f"Foothold: {host.foothold}")
            print(f"Services: {host.services}")

        elif choice == '2':
            print("\n--- Facts ---")
            pprint(host.facts)

        elif choice == '3':
            print("\n--- Vulnerabilities ---")
            pprint(host.vulnerabilities)

        elif choice == '4':
            print("\n--- Hypotheses ---")
            if not host.hypotheses:
                print("No hypotheses found.")
            for i, h in enumerate(host.hypotheses):
                print(f"[{i}] Confidence: {h.get('confidence', 'N/A')}")
                print(f"    Desc: {h.get('description', 'N/A')}")
                print(f"    CWE: {h.get('cwe', 'N/A')}")
                print(f"    Approach: {h.get('exploit_approach', 'N/A')}")

        elif choice == '5':
            print("\n--- Add New Hypothesis ---")
            desc = input("Description: ").strip()
            conf = float(input("Confidence (0.0 - 1.0): ").strip() or "0.8")
            cwe = input("CWE (e.g. CWE-798, leave blank if none): ").strip()
            approach = input("Exploit approach (e.g. http_request, exploit_exec): ").strip()
            
            new_hyp = {
                "description": desc,
                "evidence": ["Manually added by user"],
                "confidence": conf,
                "cwe": [cwe] if cwe else [],
                "chain": None,
                "exploit_approach": approach,
                "failed_attempts": []
            }
            host.hypotheses.append(new_hyp)
            print("[+] Hypothesis added (remember to save)!")

        elif choice == '6':
            if not host.hypotheses:
                print("No hypotheses to remove.")
                continue
            idx_str = input("Enter index to remove: ").strip()
            try:
                idx = int(idx_str)
                if 0 <= idx < len(host.hypotheses):
                    removed = host.hypotheses.pop(idx)
                    print(f"[+] Removed: {removed.get('description')}")
                else:
                    print("[-] Invalid index.")
            except ValueError:
                print("[-] Invalid number.")

        elif choice == '7':
            host.hypotheses = []
            print("[+] All hypotheses cleared.")

        elif choice == '8':
            print("\n--- Force Set Foothold ---")
            print("This skips validation and pretends you have access.")
            ftype = input("Foothold type (e.g. ssh_key, meterpreter, msf_shell): ").strip()
            user = input("User (e.g. root): ").strip()
            key_path = input("Local Key Path (if ssh_key, else leave blank): ").strip()
            
            host.foothold = {
                "type": ftype,
                "details": {
                    "user": user,
                    "local_key_path": key_path
                }
            }
            print("[+] Foothold forced (remember to save)!")

        elif choice == '9':
            host.facts = {}
            print("[+] Facts cleared.")

        elif choice == '10':
            state["host"] = host
            save_checkpoint(state)
            break

        elif choice == '11':
            print("[*] Exiting without saving.")
            break
        else:
            print("[-] Invalid choice.")

if __name__ == "__main__":
    main()