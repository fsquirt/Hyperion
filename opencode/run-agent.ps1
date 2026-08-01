# Hyperion analysis-machine helper script
# 1) Read WorkDir from appsettings.json
# 2) Call server connect to fetch cluster LLM API (llm_apis)
# 3) Generate WorkDir\.opencode\config\opencode.json (register cluster provider + default model)
# Called by run-agent.bat (which sets env vars and redirects opencode data dirs to WorkDir).
param(
    [string]$AppSettingsPath,
    [switch]$PrintWorkDir
)

$ErrorActionPreference = "SilentlyContinue"

# If no valid path given, search upward from this script for appsettings.json
if (-not $AppSettingsPath -or -not (Test-Path $AppSettingsPath)) {
    $dir = $PSScriptRoot
    while ($dir -and -not (Test-Path (Join-Path $dir "appsettings.json"))) {
        $dir = [System.IO.Path]::GetDirectoryName($dir)
    }
    if ($dir) { $AppSettingsPath = Join-Path $dir "appsettings.json" }
}
if (-not $AppSettingsPath -or -not (Test-Path $AppSettingsPath)) {
    Write-Host "[config] appsettings.json not found."
    exit 1
}

$j = Get-Content $AppSettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
$workDir = [string]$j.WorkDir

# bat calls -PrintWorkDir to capture WorkDir (plain text output)
if ($PrintWorkDir) {
    Write-Output $workDir
    exit 0
}
$server = ([string]$j.ServerUrl).TrimEnd('/')
$token = [string]$j.CredentialToken

if (-not $workDir) {
    Write-Host "[config] WorkDir missing in appsettings.json"
    exit 1
}

$configDir = Join-Path $workDir ".opencode\config"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
$opencodeJson = Join-Path $configDir "opencode.json"

# Only try to fetch cluster model if ServerUrl + token are present
if ($server -and $token) {
    try {
        $body = @{ } | ConvertTo-Json
        $headers = @{ Authorization = "Bearer $token" }
        $r = Invoke-RestMethod -Method Post -Uri ($server + "/api/reverse-agent/connect") `
            -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 30

        if ($r.llm_apis -and @($r.llm_apis).Count -gt 0) {
            $apis = @($r.llm_apis) | Where-Object { $_.base_url -and $_.api_key -and $_.model_name } |
                Sort-Object @{ Expression = { [int]$_.priority } } |
                Select-Object -First 1
            if ($apis) {
                $pidx = "hyperion-cluster"
                $modelName = [string]$apis.model_name
                $providers = @{
                    $pidx = @{
                        name    = "Hyperion Cluster"
                        npm     = "@ai-sdk/openai-compatible"
                        options = @{
                            baseURL = [string]$apis.base_url
                            apiKey  = [string]$apis.api_key
                        }
                        models  = @{
                            $modelName = @{ id = $modelName; name = $modelName }
                        }
                    }
                }
                $cfg = @{
                    model    = "$pidx/$modelName"
                    provider = $providers
                }
                $cfg | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $opencodeJson
                Write-Host "[config] cluster model registered: $pidx/$modelName"
                exit 0
            }
        }
        Write-Host "[config] server returned no usable llm_apis, keep opencode default model."
    }
    catch {
        Write-Host "[config] fetch cluster LLM failed: $($_.Exception.Message)"
    }
} else {
    Write-Host "[config] ServerUrl/CredentialToken not set, keep opencode default model."
}

# On failure do not overwrite existing config; if absent keep opencode default
if (-not (Test-Path $opencodeJson)) {
    Write-Host "[config] opencode.json not generated (will use opencode built-in default)."
}
exit 0
