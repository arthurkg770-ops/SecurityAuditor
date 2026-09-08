@echo off
title Security Auditor V5.1 - Build EXE
where py >nul 2>nul || (echo Python nao encontrado.&pause&exit /b 1)
py -m pip install --upgrade pyinstaller
if errorlevel 1 (pause&exit /b 1)
py -m py_compile security_auditor_v5_1.py
if errorlevel 1 (echo Erro de sintaxe.&pause&exit /b 1)
py -m PyInstaller --onefile --windowed --name SecurityAuditorV5_1 security_auditor_v5_1.py
echo.
echo EXE criado em dist\SecurityAuditorV5_1.exe
pause
