$ErrorActionPreference = "Stop"

$backendEnvPath = Join-Path $PSScriptRoot "backend\.env"
$frontendEnvPath = Join-Path $PSScriptRoot "frontend\.env.local"
$generatedAdminPassword = $null

function New-RandomUrlSafeValue([int]$byteCount) {
    $bytes = New-Object byte[] $byteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }

    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Import-EnvFile([string]$path) {
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $path) {
        if ($line -match '^\s*([^#=]+?)\s*=\s*(.*?)\s*$') {
            $name = $matches[1].Trim()
            $values[$name] = $matches[2]
            [Environment]::SetEnvironmentVariable($name, $matches[2], "Process")
        }
    }
    return $values
}

Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath $backendEnvPath)) {
        $secretKey = New-RandomUrlSafeValue 48
        $generatedAdminPassword = New-RandomUrlSafeValue 32
        $backendConfig = @"
SECRET_KEY=$secretKey
ADMIN_INITIAL_PASSWORD=$generatedAdminPassword
DATABASE_URL=sqlite:///./securevision_dev.db
CORS_ORIGINS=http://localhost:3000
"@
        [System.IO.File]::WriteAllText(
            $backendEnvPath,
            $backendConfig + [Environment]::NewLine,
            [System.Text.UTF8Encoding]::new($false)
        )
    }

    if (-not (Test-Path -LiteralPath $frontendEnvPath)) {
        [System.IO.File]::WriteAllText(
            $frontendEnvPath,
            "NEXT_PUBLIC_API_BASE=http://localhost:8000$([Environment]::NewLine)",
            [System.Text.UTF8Encoding]::new($false)
        )
    }

    $backendSettings = Import-EnvFile $backendEnvPath
    if ($backendSettings["DATABASE_URL"] -ne "sqlite:///./securevision_dev.db") {
        throw "backend\.env must set DATABASE_URL=sqlite:///./securevision_dev.db; it was not changed."
    }
    if ($backendSettings["CORS_ORIGINS"] -ne "http://localhost:3000") {
        throw "backend\.env must set CORS_ORIGINS=http://localhost:3000; it was not changed."
    }
    if (-not $backendSettings["SECRET_KEY"] -or $backendSettings["SECRET_KEY"].Length -lt 48) {
        throw "backend\.env must contain a SECRET_KEY of at least 48 characters."
    }
    if (-not $backendSettings["ADMIN_INITIAL_PASSWORD"] -or $backendSettings["ADMIN_INITIAL_PASSWORD"].Length -lt 32) {
        throw "backend\.env must contain an ADMIN_INITIAL_PASSWORD of at least 32 characters."
    }

    $frontendConfig = Get-Content -LiteralPath $frontendEnvPath
    if (-not ($frontendConfig -contains "NEXT_PUBLIC_API_BASE=http://localhost:8000")) {
        throw "frontend\.env.local must set NEXT_PUBLIC_API_BASE=http://localhost:8000; it was not changed."
    }

    if ($generatedAdminPassword) {
        Write-Host "Initial administrator credentials: username=admin password=$generatedAdminPassword"
    }

    python .\init_db.py
    if ($LASTEXITCODE -ne 0) {
        throw "Database initialization failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
