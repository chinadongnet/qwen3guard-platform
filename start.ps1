<#
.SYNOPSIS
    One-Click Startup Script for Qwen3Guard Enterprise Suite.
.DESCRIPTION
    Supports both Native Windows GPU Acceleration (RTX 3090 / CUDA) and Docker Compose deployment.
    Automatically detects local LAN IPv4 addresses to provide clickable access links across the local network.
.PARAMETER Mode
    Deployment mode: "Auto" (default), "Native" (Windows host Python/CUDA), or "Docker".
.PARAMETER HostAddress
    Bind address for HTTP server. Defaults to "0.0.0.0" for LAN access.
.PARAMETER Port
    Bind port for HTTP server. Defaults to 8092.
#>
[CmdletBinding()]
param(
    [ValidateSet("Auto", "Native", "Docker")]
    [string]$Mode = "Auto",

    [string]$HostAddress = "0.0.0.0",

    [int]$Port = 8092
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Qwen3Guard Enterprise Security & TC260 Compliance Suite       " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Detect LAN IPv4 addresses for remote console access
$lanIps = @()
try {
    $lanIps = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -ne "127.0.0.1" -and
            $_.IPAddress -notlike "169.254*" -and
            $_.InterfaceAlias -notlike "*Loopback*"
        } |
        Select-Object -ExpandProperty IPAddress
} catch {
    # Fallback if Get-NetIPAddress is restricted
}

# 2. Determine Deployment Mode
$dockerAvailable = $false
try {
    $null = Get-Command docker -ErrorAction Stop
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        $dockerAvailable = $true
    }
} catch {
    $dockerAvailable = $false
}

$hasNvidiaGpu = $false
$gpuName = "CPU"
$gpuMem = "N/A"
$gpuDriver = "N/A"
try {
    $smiOut = nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader,nounits 2>&1
    if ($LASTEXITCODE -eq 0 -and $smiOut) {
        $hasNvidiaGpu = $true
        $gpuParts = ($smiOut -split ", ")
        $gpuName = $gpuParts[0]
        $gpuMem = "$($gpuParts[1]) MB"
        $gpuDriver = $gpuParts[2]
    }
} catch {
    $hasNvidiaGpu = $false
}

if ($Mode -eq "Auto") {
    if ($hasNvidiaGpu -and (-not $dockerAvailable)) {
        $Mode = "Native"
    } elseif ($hasNvidiaGpu) {
        # Native mode provides direct direct hardware PCIe access without VM / container overhead
        $Mode = "Native"
    } elseif ($dockerAvailable) {
        $Mode = "Docker"
    } else {
        $Mode = "Native"
    }
}

Write-Host "Deployment Mode    : $Mode" -ForegroundColor Yellow
if ($hasNvidiaGpu) {
    Write-Host "Detected GPU       : $gpuName ($gpuMem, Driver: $gpuDriver)" -ForegroundColor Green
} else {
    Write-Host "Detected Hardware  : CPU (No NVIDIA GPU detected)" -ForegroundColor Gray
}

# 3. Native Mode Startup
if ($Mode -eq "Native") {
    # Locate Python interpreter (.venv preferred)
    $pythonExe = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $pythonExe)) {
        $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
        if ($pythonCmd) {
            $pythonExe = $pythonCmd.Source
        } else {
            throw "Python interpreter not found. Please create virtual environment in .venv or install Python."
        }
    }
    Write-Host "Python Interpreter : $pythonExe" -ForegroundColor Gray

    # Initialize platform credentials if needed
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot ".env"))) {
        Write-Host "Initializing deployment secrets..." -ForegroundColor Yellow
        & $pythonExe (Join-Path $PSScriptRoot "scripts/setup_platform.py")
        if ($LASTEXITCODE -ne 0) { throw "Platform initialization failed." }
    }

    Write-Host ""
    Write-Host "🚀 Launching Qwen3Guard Platform on host (0.0.0.0:$Port)..." -ForegroundColor Green
    Write-Host "   Local Web Console : http://127.0.0.1:$Port" -ForegroundColor Cyan
    foreach ($ip in $lanIps) {
        Write-Host "   LAN Web Console   : http://$($ip):$Port" -ForegroundColor Cyan
    }
    Write-Host "   OpenAPI Docs      : http://127.0.0.1:$Port/docs" -ForegroundColor Cyan
    Write-Host "   Admin Credentials : data/bootstrap-credentials.txt (local, gitignored)" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    # Start FastAPI / Uvicorn server natively
    & $pythonExe -m uvicorn app.main:app --host $HostAddress --port $Port
}
# 4. Docker Mode Startup
else {
    # Ensure Docker volume qwenguard_models exists and models are synced
    $vols = docker volume ls --format "{{.Name}}"
    if ($vols -notcontains "qwenguard_models") {
        Write-Host "[1/3] Creating Linux ext4 volume qwenguard_models..." -ForegroundColor Yellow
        docker volume create qwenguard_models | Out-Null
        $modelSrc = Join-Path $PSScriptRoot "models"
        if (Test-Path -LiteralPath $modelSrc) {
            docker run --rm -v "${modelSrc}:/src:ro" -v "qwenguard_models:/models" alpine sh -c "cp -r /src/* /models/"
        }
    }

    Write-Host "[2/3] Starting qwenguard-server container on 0.0.0.0:$Port..." -ForegroundColor Green
    docker compose up -d --build
    if ($LASTEXITCODE -ne 0) { throw "Platform container startup failed." }

    Write-Host "[3/3] Waiting for service and models to load..." -ForegroundColor Yellow
    for ($i = 1; $i -le 30; $i++) {
        Start-Sleep -Seconds 2
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2
            if ($resp.models_loaded -eq $true) {
                Write-Host "✅ Platform $($resp.version) and all 3 models are ready." -ForegroundColor Green
                Write-Host "   Local Web Console : http://127.0.0.1:$Port" -ForegroundColor Cyan
                foreach ($ip in $lanIps) {
                    Write-Host "   LAN Web Console   : http://$($ip):$Port" -ForegroundColor Cyan
                }
                Write-Host "   OpenAPI Docs      : http://127.0.0.1:$Port/docs" -ForegroundColor Cyan
                Write-Host "   Admin credentials : data/bootstrap-credentials.txt (local, gitignored)" -ForegroundColor Yellow
                break
            }
        } catch {
            Write-Host "   Loading models... ($i/30)" -ForegroundColor DarkGray
        }
    }
}
