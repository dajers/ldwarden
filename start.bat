@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 (
  echo Нужен Python 3.10+. Установите его с https://python.org и повторите.
  pause
  exit /b 1
)

if not exist "venv\Scripts\python.exe" (
  echo [1/3] Создаю виртуальное окружение...
  %PY% -m venv venv
  if errorlevel 1 goto :error
) else (
  echo [1/3] Виртуальное окружение уже есть
)

echo [2/3] Устанавливаю зависимости...
venv\Scripts\python.exe -m pip install --upgrade pip
venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo [3/3] Сервер: http://127.0.0.1:8000
echo Остановить — Ctrl+C
echo.
start "" /min cmd /c "timeout /t 5 >nul & start http://127.0.0.1:8000"
venv\Scripts\python.exe -m app.main serve --host 127.0.0.1 --port 8000
goto :eof

:error
echo.
echo Не удалось установить зависимости. Проверьте интернет и Python 3.10+.
pause
exit /b 1
