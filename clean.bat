@echo off
setlocal

set ROOT=%~dp0

echo This will stop dev servers (node.exe) and remove local build/cache folders.
set /p CONFIRM=Continue? (y/N):
if /I not "%CONFIRM%"=="Y" (
  echo Aborted.
  exit /b 1
)

echo Stopping dev servers...
taskkill /F /IM node.exe /T >nul 2>&1

echo Cleaning safe-to-delete folders...
for %%P in (
  "node_modules"
  "apps\api\.wrangler"
  "apps\api\node_modules"
  "apps\api\dist"
  "apps\web\node_modules"
  "apps\web\dist"
  "apps\web\node_modules\.vite"
  "apps\api\node_modules\.cache"
  "node_modules\.mf"
  "apps\api\node_modules\.mf"
) do (
  if exist "%ROOT%%%~P" (
    echo Removing %ROOT%%%~P
    rmdir /S /Q "%ROOT%%%~P"
  )
)

echo Done.
endlocal
