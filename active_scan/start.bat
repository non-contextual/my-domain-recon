@echo off
chcp 65001 >nul
title FTP 树状图代理服务器
cd /d "%~dp0"

REM 后台 3 秒后自动开浏览器
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:8765/"

echo.
echo  ========================================
echo   FTP 树状图代理服务器
echo  ========================================
echo.
echo  代理地址: http://localhost:8765/
echo  浏览器会自动打开 (3 秒内)
echo  Ctrl+C 退出
echo.

python serve.py
pause
