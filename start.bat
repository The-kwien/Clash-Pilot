@echo off
chcp 65001 >nul
setlocal
title Clash Pilot
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo [Clash Pilot] 未检测到 Python。
  echo 请先安装 Python 3.10 或更高版本：https://www.python.org/downloads/
  echo.
  pause
  exit /b 1
)

python -c "import yaml" >nul 2>nul
if errorlevel 1 (
  echo.
  echo [Clash Pilot] 缺少依赖 PyYAML，正在尝试安装...
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo.
    echo [Clash Pilot] 依赖安装失败，请手动执行：
    echo     python -m pip install -r requirements.txt
    echo.
    pause
    exit /b 1
  )
)

python app.py %*
if errorlevel 1 (
  echo.
  echo [Clash Pilot] 控制台异常退出，请查看上方错误信息。
  pause
)
