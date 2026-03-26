@echo off
setlocal

if not exist src\go.mod (
    echo [ERROR] run from the open-filerep root directory
    exit /b 1
)

cd src

go mod tidy
if errorlevel 1 exit /b 1

go build -o ..\open-filerep.exe .
if errorlevel 1 exit /b 1

cd ..
echo [OK] open-filerep.exe built
