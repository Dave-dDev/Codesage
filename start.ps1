$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Python environment not found. Create it with: py -3.13 -m venv .venv"
}

if (-not (Test-Path (Join-Path $root "frontend\dist\index.html"))) {
    Write-Host "Build the frontend first: cd frontend; pnpm install; pnpm build"
}

Push-Location (Join-Path $root "backend")
try {
    & $python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
}
finally {
    Pop-Location
}
