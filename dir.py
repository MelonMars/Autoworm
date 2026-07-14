import subprocess
import sys

def get_py_files():
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.py"],
        capture_output=True, text=True, check=True,
    )
    return sorted(f for f in out.stdout.splitlines() if f)

def copy_to_clipboard(text):
    if sys.platform == "darwin":
        subprocess.run(["pbcopy"], input=text, text=True,
                       encoding="utf-8", check=True)
    elif sys.platform == "win32":
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Set-Clipboard -Value ([Console]::In.ReadToEnd())"],
            input=text, text=True, encoding="utf-8", check=True,
        )
    else:
        subprocess.run(["xclip", "-selection", "clipboard"],
                       input=text, text=True, encoding="utf-8", check=True)
def main():
    blocks = []
    for path in get_py_files():
        try:
            with open(path, encoding="utf-8") as f:
                blocks.append(f"{path}\n{f.read()}")
        except (UnicodeDecodeError, OSError) as e:
            print(f"skipped {path}: {e}", file=sys.stderr)
    output = "\n\n".join(blocks)
    copy_to_clipboard(output)
    print(f"Copied {len(blocks)} files to clipboard.")

if __name__ == "__main__":
    main()