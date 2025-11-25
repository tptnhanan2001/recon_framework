@echo off
echo ======================================================================
echo Recon Tool Web Dashboard
echo ======================================================================
echo Starting API server...
echo.
cd /d "%~dp0\.."
python web\api_server.py
pause

