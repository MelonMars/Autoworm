#!/bin/sh
command -v python3 >/dev/null 2>&1 || {
  if command -v brew >/dev/null 2>&1; then brew install python
  else
    DIR="$HOME/.localpython"
    case "$(uname -m)" in x86_64|amd64) A=x86_64;; aarch64|arm64) A=aarch64;; esac
    case "$(uname -s)" in Darwin) O=apple-darwin;; *) O=unknown-linux-gnu;; esac
    U="https://github.com/astral-sh/python-build-standalone/releases/download/20250612/cpython-3.12.11+20250612-${A}-${O}-install_only.tar.gz"
    mkdir -p "$DIR" && curl -L "$U" | tar xz -C "$DIR"
    export PATH="$DIR/python/bin:$PATH"
  fi
}
python3 -m pip install --user -r requirements.txt
python3 orchestrator.py