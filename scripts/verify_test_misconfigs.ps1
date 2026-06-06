# Verify test misconfigurations are visible to the read-only scanner user.
# Uses credentials from .env (aivar-scanner) — no admin keys required.

$ErrorActionPreference = "Continue"
$Region = if ($env:AWS_DEFAULT_REGION) { $env:AWS_DEFAULT_REGION } else { "ap-south-1" }

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $ProjectRoot ".env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            if (-not [string]::IsNullOrEmpty($value)) {
                Set-Item -Path "env:$name" -Value $value
            }
        }
    }
}

Write-Host "=== Verifying test misconfigurations (scanner read-only creds) ===" -ForegroundColor Cyan
Write-Host "Region: $Region"
Write-Host ""

$results = @()

function Add-Result {
    param([string]$Name, [bool]$Pass, [string]$Detail)
    $script:results += [PSCustomObject]@{ Name = $Name; Pass = $Pass; Detail = $Detail }
}

# 1. Public S3 bucket ACL
$publicBuckets = @()
try {
    $buckets = aws s3api list-buckets --query "Buckets[?starts_with(Name, 'aivar-test-public')].Name" --output json 2>&1 | ConvertFrom-Json
    if ($buckets) { $publicBuckets = @($buckets) }
} catch { }

$publicAclOk = $false
$publicDetail = "No aivar-test-public-* bucket found"
foreach ($bucket in $publicBuckets) {
    try {
        $acl = aws s3api get-bucket-acl --bucket $bucket 2>&1 | ConvertFrom-Json
        $publicGrant = $acl.Grants | Where-Object {
            $_.Grantee.URI -match "AllUsers|AuthenticatedUsers"
        }
        if ($publicGrant) {
            $publicAclOk = $true
            $publicDetail = "Bucket $bucket has public ACL grant"
            break
        }
    } catch {
        $publicDetail = "Bucket $bucket exists but ACL check failed: $_"
    }
}
Add-Result "s3_public_acl (public S3 bucket)" $publicAclOk $publicDetail

# 2. Unencrypted S3 bucket
$noEncOk = $false
$noEncDetail = "No aivar-test-noenc-* bucket found"
try {
    $noEncBuckets = aws s3api list-buckets --query "Buckets[?starts_with(Name, 'aivar-test-noenc')].Name" --output json 2>&1 | ConvertFrom-Json
    if ($noEncBuckets) {
        foreach ($bucket in @($noEncBuckets)) {
            try {
                aws s3api get-bucket-encryption --bucket $bucket 2>&1 | Out-Null
            } catch {
                if ($_.ToString() -match "ServerSideEncryptionConfigurationNotFoundError") {
                    $noEncOk = $true
                    $noEncDetail = "Bucket $bucket has no encryption configured"
                    break
                }
            }
        }
        if (-not $noEncOk -and $noEncBuckets) {
            $noEncDetail = "Bucket(s) exist but encryption may be enabled"
        }
    }
} catch { }
Add-Result "s3_encryption_disabled (unencrypted S3)" $noEncOk $noEncDetail

# 3. IAM user without MFA
$iamOk = $false
$iamDetail = "test-no-mfa-user not found or no console access"
try {
    aws iam get-login-profile --user-name test-no-mfa-user 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $mfa = aws iam list-mfa-devices --user-name test-no-mfa-user --query "MFADevices" --output json 2>&1 | ConvertFrom-Json
        if (-not $mfa -or $mfa.Count -eq 0) {
            $iamOk = $true
            $iamDetail = "test-no-mfa-user has console access, no MFA"
        } else {
            $iamDetail = "test-no-mfa-user exists but has MFA attached"
        }
    }
} catch { }
Add-Result "iam_user_mfa (console user, no MFA)" $iamOk $iamDetail

# 4. Open SSH security group
$sshOk = $false
$sshDetail = "open-ssh-sg not found or no port 22 rule"
try {
    $sgs = aws ec2 describe-security-groups --region $Region `
        --filters "Name=group-name,Values=open-ssh-sg" --output json 2>&1 | ConvertFrom-Json
    foreach ($sg in $sgs.SecurityGroups) {
        foreach ($rule in $sg.IpPermissions) {
            $from = if ($rule.FromPort) { $rule.FromPort } else { 0 }
            $to = if ($rule.ToPort) { $rule.ToPort } else { 65535 }
            if ($from -le 22 -and $to -ge 22 -and $rule.IpProtocol -in @("tcp", "-1")) {
                $open = $rule.IpRanges | Where-Object { $_.CidrIp -eq "0.0.0.0/0" }
                if ($open) {
                    $sshOk = $true
                    $sshDetail = "open-ssh-sg allows SSH from 0.0.0.0/0 ($($sg.GroupId))"
                    break
                }
            }
        }
        if ($sshOk) { break }
    }
} catch { }
Add-Result "sg_open_ssh (port 22 open to world)" $sshOk $sshDetail

# 5. Open RDP security group
$rdpOk = $false
$rdpDetail = "open-rdp-sg not found or no port 3389 rule"
try {
    $sgs = aws ec2 describe-security-groups --region $Region `
        --filters "Name=group-name,Values=open-rdp-sg" --output json 2>&1 | ConvertFrom-Json
    foreach ($sg in $sgs.SecurityGroups) {
        foreach ($rule in $sg.IpPermissions) {
            $from = if ($rule.FromPort) { $rule.FromPort } else { 0 }
            $to = if ($rule.ToPort) { $rule.ToPort } else { 65535 }
            if ($from -le 3389 -and $to -ge 3389 -and $rule.IpProtocol -in @("tcp", "-1")) {
                $open = $rule.IpRanges | Where-Object { $_.CidrIp -eq "0.0.0.0/0" }
                if ($open) {
                    $rdpOk = $true
                    $rdpDetail = "open-rdp-sg allows RDP from 0.0.0.0/0 ($($sg.GroupId))"
                    break
                }
            }
        }
        if ($rdpOk) { break }
    }
} catch { }
Add-Result "sg_open_rdp (port 3389 open to world)" $rdpOk $rdpDetail

# Summary
Write-Host ""
$passCount = ($results | Where-Object { $_.Pass }).Count
$failCount = ($results | Where-Object { -not $_.Pass }).Count

foreach ($r in $results) {
    $status = if ($r.Pass) { "PASS" } else { "FAIL" }
    $color = if ($r.Pass) { "Green" } else { "Red" }
    Write-Host "  [$status] $($r.Name)" -ForegroundColor $color
    Write-Host "         $($r.Detail)"
}

Write-Host ""
Write-Host "Result: $passCount passed, $failCount failed (of $($results.Count) test resources)" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })

if ($failCount -gt 0) {
    Write-Host ""
    Write-Host "Missing resources? Create them via AWS Console (see README) or run:" -ForegroundColor Yellow
    Write-Host "  .\scripts\setup_test_misconfigs.ps1   (requires admin credentials)"
}

Write-Host ""
if ($failCount -eq 0) {
    exit 0
} else {
    exit 1
}
