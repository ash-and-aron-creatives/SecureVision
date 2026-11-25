param(
    [string]$ComposeProjectName = "securevision-dev"
)

$ErrorActionPreference = "Stop"

$backendEnvPath = Join-Path $PSScriptRoot "backend\.env"
$frontendEnvPath = Join-Path $PSScriptRoot "frontend\.env.local"
$generatedAdminPassword = $null

if (Test-Path -LiteralPath $backendEnvPath) {
    throw "backend\.env already exists and was not changed. Move it aside manually before creating fresh local settings."
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
        "POSTGRES_APP_USER=$($settings["POSTGRES_APP_USER"])",
        "POSTGRES_APP_PASSWORD=$($settings["POSTGRES_APP_PASSWORD"])",
        "PRIORITY_MODE=$($settings["PRIORITY_MODE"])",
        "DATABASE_URL=$($settings["DATABASE_URL"])",
        "MIGRATION_DATABASE_URL=$($settings["MIGRATION_DATABASE_URL"])",
        "CVE_DATASET_FILENAME=$($settings["CVE_DATASET_FILENAME"])",
        "CVE_DATASET_HOST_PATH=$($settings["CVE_DATASET_HOST_PATH"])",
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
    $generatedAdminPassword = New-RandomUrlSafeValue 32
    $settings = @{
        SECRET_KEY = New-RandomUrlSafeValue 48
        ADMIN_INITIAL_PASSWORD = $generatedAdminPassword
        POSTGRES_DB = "securevision_dev"
        POSTGRES_USER = "securevision_owner"
        POSTGRES_PASSWORD = New-RandomUrlSafeValue 32
        POSTGRES_APP_USER = "securevision_app"
        POSTGRES_APP_PASSWORD = New-RandomUrlSafeValue 32
        PRIORITY_MODE = "ml_asset"
        CVE_DATASET_FILENAME = "master_cves_2026-10-08.csv"
        CVE_DATASET_HOST_PATH = ".\data\processed\master_cves_2026-10-08.csv"
        CORS_ORIGINS = "http://localhost:3000"
    }

    $settings["DATABASE_URL"] = "postgresql+psycopg2://$($settings["POSTGRES_APP_USER"]):$($settings["POSTGRES_APP_PASSWORD"])@localhost:5432/$($settings["POSTGRES_DB"])"
    $settings["MIGRATION_DATABASE_URL"] = "postgresql+psycopg2://$($settings["POSTGRES_USER"]):$($settings["POSTGRES_PASSWORD"])@localhost:5432/$($settings["POSTGRES_DB"])"
    Write-BackendEnv $settings

    if (-not (Test-Path -LiteralPath $frontendEnvPath)) {
        [System.IO.File]::WriteAllText(
            $frontendEnvPath,
            "NEXT_PUBLIC_API_BASE=http://localhost:8000$([Environment]::NewLine)",
            [System.Text.UTF8Encoding]::new($false)
        )
    }

    $backendSettings = Import-EnvFile $backendEnvPath
    if (-not $backendSettings["SECRET_KEY"] -or $backendSettings["SECRET_KEY"].Length -lt 48) {
        throw "backend\.env must contain a SECRET_KEY of at least 48 characters."
    }
    if (-not $backendSettings["ADMIN_INITIAL_PASSWORD"] -or $backendSettings["ADMIN_INITIAL_PASSWORD"].Length -lt 32) {
        throw "backend\.env must contain an ADMIN_INITIAL_PASSWORD of at least 32 characters."
    }

    foreach ($name in $backendSettings.Keys) {
        if ($name -notin @(
            "POSTGRES_DB",
            "POSTGRES_USER",
            "POSTGRES_PASSWORD",
            "POSTGRES_APP_USER",
            "POSTGRES_APP_PASSWORD",
            "MIGRATION_DATABASE_URL"
        )) {
            [Environment]::SetEnvironmentVariable($name, $backendSettings[$name], "Process")
        }
    }

    $frontendConfig = Get-Content -LiteralPath $frontendEnvPath
    if (-not ($frontendConfig -contains "NEXT_PUBLIC_API_BASE=http://localhost:8000")) {
        throw "frontend\.env.local must set NEXT_PUBLIC_API_BASE=http://localhost:8000."
    }

    Write-Host "Initial administrator password (copy now): $generatedAdminPassword"

    $composeArgs = @(
        "-p", $ComposeProjectName,
        "--env-file", $backendEnvPath,
        "-f", "docker-compose.yml",
        "-f", "docker-compose.local.yml",
        "up", "-d", "--wait", "postgres"
    )
    & docker compose @composeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PostgreSQL container startup failed with exit code $LASTEXITCODE."
    }

    $provisionArgs = @(
        "-p", $ComposeProjectName,
        "--env-file", $backendEnvPath,
        "-f", "docker-compose.yml",
        "-f", "docker-compose.local.yml",
        "exec", "-T", "postgres",
        "sh", "/docker-entrypoint-initdb.d/10-create-app-role.sh"
    )
    $roleProvisioned = $false
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        & docker compose @provisionArgs
        if ($LASTEXITCODE -eq 0) {
            $roleProvisioned = $true
            break
        }
        if ($attempt -lt 10) {
            Start-Sleep -Seconds 2
        }
    }
    if (-not $roleProvisioned) {
        throw "Application database role provisioning failed with exit code $LASTEXITCODE."
    }

    $migrationArgs = @(
        "-p", $ComposeProjectName,
        "--env-file", $backendEnvPath,
        "-f", "docker-compose.yml",
        "-f", "docker-compose.local.yml",
        "run", "--rm", "migrate"
    )
    & docker compose @migrationArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Database migration failed with exit code $LASTEXITCODE."
    }

    python -m backend.init_db
    if ($LASTEXITCODE -ne 0) {
        throw "Database initialization failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
