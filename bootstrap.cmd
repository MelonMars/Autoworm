@echo off
where python >nul 2>nul || winget install -e --id Python.Python.3.12 --scope user
python -m pip install --user -r requirements.txt
python orchestrator.py