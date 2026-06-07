# Run setup_test_misconfigs.ps1 using ADMIN credentials from .env.admin
# Keeps .env (scanner read-only) untouched for scanning afterward.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$AdminEnvFile = Join-Path $ProjectRoot ".env.admin"

if (-not (Test-Path $AdminEnvFile)) {
    Write-Host "ERROR: .env.admin not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "Steps:" -ForegroundColor Yellow
    Write-Host "  1. copy .env.admin.example .env.admin"
    Write-Host "  2. Create IAM user 'aivar-admin' with AdministratorAccess (see README)"
    Write-Host "  3. Paste admin access keys into .env.admin"
    Write-Host "  4. Re-run: .\scripts\run_setup_as_admin.ps1"
    exit 1
}

# Save current scanner env vars (from .env loaded by shell or parent)
$SavedKey = $env:AWS_ACCESS_KEY_ID
$SavedSecret = $env:AWS_SECRET_ACCESS_KEY
$SavedRegion = $env:AWS_DEFAULT_REGION

# Load admin creds from .env.admin
Get-Content $AdminEnvFile | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
        $name = $matches[1].Trim()
        $value = $matches[2].Trim()
        if (-not [string]::IsNullOrEmpty($value)) {
            Set-Item -Path "env:$name" -Value $value
        }
    }
}

Write-Host "=== Running setup with ADMIN credentials ===" -ForegroundColor Cyan

# Verify admin identity
try {
    $identity = aws sts get-caller-identity --output json 2>&1 | ConvertFrom-Json
    Write-Host "Admin identity: $($identity.Arn)" -ForegroundColor Green
    Write-Host "Account:      $($identity.Account)"
} catch {
    Write-Host "ERROR: AWS CLI failed. Install AWS CLI v2 and check .env.admin keys." -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

& (Join-Path $PSScriptRoot "setup_test_misconfigs.ps1")
$setupExit = $LASTEXITCODE

# Restore scanner env vars if they were set
if ($SavedKey) { $env:AWS_ACCESS_KEY_ID = $SavedKey } else { Remove-Item Env:AWS_ACCESS_KEY_ID -ErrorAction SilentlyContinue }
if ($SavedSecret) { $env:AWS_SECRET_ACCESS_KEY = $SavedSecret } else { Remove-Item Env:AWS_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue }
if ($SavedRegion) { $env:AWS_DEFAULT_REGION = $SavedRegion }

Write-Host ""
Write-Host "Admin session ended. Scanner .env unchanged." -ForegroundColor Cyan
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  .\scripts\verify_test_misconfigs.ps1   # uses scanner creds from .env"
Write-Host "  python main.py --config checklist.yaml --verbose"

exit $setupExit
