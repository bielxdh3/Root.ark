@echo off
setlocal EnableExtensions
rem LAB-only build using the installed MSVC and Windows SDK; no production build integration.
if "%~1"=="" (
  echo ERROR: Supply output EXE path in a disposable directory. 1>&2
  exit /b 2
)
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo ERROR: MSVC vcvars64.bat not present. 1>&2
  exit /b 3
)
call "%VCVARS%" >nul
if errorlevel 1 exit /b 4
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /D_WIN32_WINNT=0x0A00 /Fo:"%~dp1held-link-win.obj" /Fe:"%~1" "%~dp0held-link-win.cpp" /link /SUBSYSTEM:CONSOLE
if errorlevel 1 exit /b 5
exit /b 0
