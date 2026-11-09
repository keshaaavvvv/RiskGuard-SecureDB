@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  py -m venv .venv
)
call ".venv\Scripts\activate.bat"
python -m pip install -r requirements.txt
if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo Created .env. Edit FLASK_SECRET_KEY, ADMIN_EMAIL and ADMIN_PASSWORD before first admin login.
  notepad ".env"
)
python app.py
pause
