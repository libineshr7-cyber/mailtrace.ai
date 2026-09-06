@echo off
title Mailtrace AI — Enterprise Forensic Launch Console
echo ======================================================================
echo           MAILTRACE AI — REAL-TIME FORENSIC EMAIL PLATFORM
echo ======================================================================
echo.
echo Starting Backend (FastAPI on http://localhost:8000)...
start "Mailtrace AI - Backend (Port 8000)" cmd /k "python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 2 /nobreak >nul

echo Starting Frontend (Vite on http://localhost:3000)...
start "Mailtrace AI - Frontend (Port 3000)" cmd /k "cd frontend && npm run dev"

echo.
echo ======================================================================
echo Both services launched!
echo - Web Dashboard:  http://localhost:3000
echo - REST API Docs:  http://localhost:8000/docs
echo - Live Health:    http://localhost:8000/api/system/health
echo ======================================================================
echo.
pause
