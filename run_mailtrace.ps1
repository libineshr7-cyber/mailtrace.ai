# ======================================================================
# MAILTRACE AI — Enterprise Forensic Email Platform Launcher
# ======================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "          MAILTRACE AI — REAL-TIME FORENSIC EMAIL PLATFORM            " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$RootPath = $PSScriptRoot

Write-Host "[*] Launching FastAPI Backend on http://localhost:8000..." -ForegroundColor Yellow
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd /d `"$RootPath`" && python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload" -WindowStyle Normal

Start-Sleep -Seconds 2

Write-Host "[*] Launching Vite Frontend on http://localhost:3000..." -ForegroundColor Yellow
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd /d `"$RootPath\frontend`" && npm run dev" -WindowStyle Normal

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " Both services running in background windows:" -ForegroundColor Green
Write-Host "  -> Frontend App:       http://localhost:3000" -ForegroundColor White
Write-Host "  -> Interactive API:    http://localhost:8000/docs" -ForegroundColor White
Write-Host "  -> System Health:      http://localhost:8000/api/system/health" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""
