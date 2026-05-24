@echo off
setlocal
call "D:\Installations\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=x86 -no_logo
if errorlevel 1 (
    echo VsDevCmd failed.
    exit /b 1
)
cd /d "%~dp0"
echo === building probe.dll (32-bit) ===
cl /nologo /EHsc /W3 /MD /LD probe.cpp /link /OUT:probe.dll
if errorlevel 1 exit /b 1
echo === building inject.exe (32-bit) ===
cl /nologo /EHsc /W3 /MD inject.cpp /link /OUT:inject.exe
if errorlevel 1 exit /b 1
echo === done ===
dir /b probe.dll inject.exe
