# PowerShell One-Click Startup Script for Qwen3Guard Enterprise Suite
$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Qwen3Guard Enterprise Security & TC260 Compliance Suite       " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Ensure Docker volume qwenguard_models exists and models are synced
$vols = docker volume ls --format "{{.Name}}"
if ($vols -notcontains "qwenguard_models") {
    Write-Host "[1/3] Creating Linux ext4 volume qwenguard_models and syncing models..." -ForegroundColor Yellow
    docker volume create qwenguard_models | Out-Null
    docker run --rm --entrypoint bash -v "D:\aiAgent\agy\qwenguard\models:/src:ro" -v "qwenguard_models:/models" vllm/vllm-openai:qwen38-x86_64-cu130 -c "cp -r /src/* /models/"
}

Write-Host "[2/3] Starting qwenguard-server container on GPU (0.0.0.0:8092)..." -ForegroundColor Green
docker compose up -d --force-recreate

Write-Host "[3/3] Waiting for Qwen3Guard-Gen-0.6B, Qwen3Guard-Stream-0.6B, and Qwen3-0.6B to load..." -ForegroundColor Yellow
for ($i = 1; $i -le 30; $i++) {
    Start-Sleep -Seconds 2
    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8092/health" -TimeoutSec 2
        if ($resp.models_loaded -eq $true) {
            Write-Host "✅ All 3 Models Loaded on $($resp.gpu_name)!" -ForegroundColor Green
            Write-Host "   Local Web Console : http://127.0.0.1:8092" -ForegroundColor Cyan
            Write-Host "   LAN Web Console   : http://192.168.9.120:8092" -ForegroundColor Cyan
            Write-Host "   OpenAPI Docs      : http://127.0.0.1:8092/docs" -ForegroundColor Cyan
            break
        }
    } catch {
        Write-Host "   Loading models... ($i/30)" -ForegroundColor DarkGray
    }
}
