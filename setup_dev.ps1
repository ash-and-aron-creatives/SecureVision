param(
    [switch]$UpdateExisting
)

$ErrorActionPreference = "Stop"

$backendEnvPath = Join-Path $PSScriptRoot "backend\.env"
$frontendEnvPath = Join-Path $PSScriptRoot "frontend\.env.local"
$generatedAdminPassword = $null

if ((Test-Path -LiteralPath $backendEnvPath) -and -not $UpdateExisting) {
    throw "backend\.env already exists and was not changed. Review it, then rerun with -UpdateExisting to refresh the local PostgreSQL settings."
}

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
        }
    }
    return $values
}

function Write-BackendEnv($settings) {
    $lines = @(
        "SECRET_KEY=$($settings["SECRET_KEY"])",
        "ADMIN_INITIAL_PASSWORD=$($settings["ADMIN_INITIAL_PASSWORD"])",
        "POSTGRES_DB=$($settings["POSTGRES_DB"])",
        "POSTGRES_USER=$($settings["POSTGRES_USER"])",
        "POSTGRES_PASSWORD=$($settings["POSTGRES_PASSWORD"])",
        "DATABASE_URL=$($settings["DATABASE_URL"])",
        "CORS_ORIGINS=$($settings["CORS_ORIGINS"])"
    )
    [System.IO.File]::WriteAllText(
        $backendEnvPath,
        ($lines -join [Environment]::NewLine) + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
}

Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath $backendEnvPath)) {
        $generatedAdminPassword = New-RandomUrlSafeValue 32
        $settings = @{
            SECRET_KEY = New-RandomUrlSafeValue 48
            ADMIN_INITIAL_PASSWORD = $generatedAdminPassword
            POSTGRES_DB = "securevision_dev"
            POSTGRES_USER = "securevision"
            POSTGRES_PASSWORD = New-RandomUrlSafeValue 32
            CORS_ORIGINS = "http://localhost:3000"
        }
    }
    else {
        $settings = Import-EnvFile $backendEnvPath
        if (-not $settings["SECRET_KEY"]) {
            $settings["SECRET_KEY"] = New-RandomUrlSafeValue 48
        }
        if (-not $settings["ADMIN_INITIAL_PASSWORD"]) {
            $generatedAdminPassword = New-RandomUrlSafeValue 32
            $settings["ADMIN_INITIAL_PASSWORD"] = $generatedAdminPassword
        }
        if (-not $settings["POSTGRES_DB"]) {
            $settings["POSTGRES_DB"] = "securevision_dev"
        }
        if (-not $settings["POSTGRES_USER"]) {
            $settings["POSTGRES_USER"] = "securevision"
        }
        if (-not $settings["POSTGRES_PASSWORD"]) {
            $settings["POSTGRES_PASSWORD"] = New-RandomUrlSafeValue 32
        }
        if (-not $settings["CORS_ORIGINS"]) {
            $settings["CORS_ORIGINS"] = "http://localhost:3000"
        }
    }

    $settings["DATABASE_URL"] = "postgresql+psycopg2://$($settings["POSTGRES_USER"]):$($settings["POSTGRES_PASSWORD"])@localhost:5432/$($settings["POSTGRES_DB"])"
    Write-BackendEnv $settings

    if (-not (Test-Path -LiteralPath $frontendEnvPath)) {
        [System.IO.File]::WriteAllText(
            $frontendEnvPath,
            "NEXT_PUBLIC_API_BASE=http://localhost:8000$([Environment]::NewLine)",
            [System.Text.UTF8Encoding]::new($false)
        )
    }

    $backendSettings = Import-EnvFile $backendEnvPath
    if ($backendSettings["CORS_ORIGINS"] -ne "http://localhost:3000") {
        throw "backend\.env must set CORS_ORIGINS=http://localhost:3000."
    }
    if (-not $backendSettings["SECRET_KEY"] -or $backendSettings["SECRET_KEY"].Length -lt 48) {
        throw "backend\.env must contain a SECRET_KEY of at least 48 characters."
    }
    if (-not $backendSettings["ADMIN_INITIAL_PASSWORD"] -or $backendSettings["ADMIN_INITIAL_PASSWORD"].Length -lt 32) {
        throw "backend\.env must contain an ADMIN_INITIAL_PASSWORD of at least 32 characters."
    }

    foreach ($name in $backendSettings.Keys) {
        [Environment]::SetEnvironmentVariable($name, $backendSettings[$name], "Process")
    }

    $frontendConfig = Get-Content -LiteralPath $frontendEnvPath
    if (-not ($frontendConfig -contains "NEXT_PUBLIC_API_BASE=http://localhost:8000")) {
        throw "frontend\.env.local must set NEXT_PUBLIC_API_BASE=http://localhost:8000."
    }

    if ($generatedAdminPassword) {
        Write-Host "Initial administrator credentials: username=admin ******"
    }

    & docker compose --env-file $backendEnvPath -f docker-compose.yml -f docker-compose.local.yml up -d --wait postgres
    if ($LASTEXITCODE -ne 0) {
        throw "PostgreSQL container startup failed with exit code $LASTEXITCODE."
    }

    python .\init_db.py
    if ($LASTEXITCODE -ne 0) {
        throw "Database initialization failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
