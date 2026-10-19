@echo off
cd /d "%~dp0"
python -c "import fastapi, uvicorn, psutil" >nul 2>&1
if errorlevel 1 (
  echo Installing PacketParent dependencies...
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    pause
    exit /b 1
  )
)
echo Open http://127.0.0.1:8765 in your browser.
python app.py
pause
