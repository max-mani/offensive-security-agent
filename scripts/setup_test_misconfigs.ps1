# AWS Test Environment Setup — intentional misconfigurations
# Run with ADMIN credentials (not the scanner user). Region: ap-south-1

$ErrorActionPreference = "Continue"
$Region = "ap-south-1"
$Timestamp = [int][double]::Parse((Get-Date -UFormat %s))

$results = @()

function Add-Result {
    param([string]$Name, [bool]$Pass, [string]$Detail)
    $script:results += [PSCustomObject]@{ Name = $Name; Pass = $Pass; Detail = $Detail }
    $status = if ($Pass) { "PASS" } else { "FAIL" }
    $color = if ($Pass) { "Green" } else { "Red" }
    Write-Host "  [$status] $Name - $Detail" -ForegroundColor $color
}

function Ensure-SecurityGroupRule {
    param(
        [string]$GroupName,
        [string]$Description,
        [string]$VpcId,
        [int]$Port,
        [string]$Protocol = "tcp"
    )
    $sgId = $null
    try {
        $existing = aws ec2 describe-security-groups --region $Region `
            --filters "Name=group-name,Values=$GroupName" "Name=vpc-id,Values=$VpcId" `
            --query "SecurityGroups[0].GroupId" --output text 2>&1
        if ($existing -and $existing -ne "None") {
            $sgId = $existing.Trim()
        }
    } catch { }

    if (-not $sgId) {
        try {
            $sgId = aws ec2 create-security-group --group-name $GroupName `
                --description $Description --vpc-id $VpcId --region $Region `
                --query "GroupId" --output text 2>&1
            $sgId = $sgId.Trim()
        } catch {
            Add-Result $GroupName $false "Failed to create security group: $_"
            return
        }
    }

    $hasRule = $false
    try {
        $sgJson = aws ec2 describe-security-groups --group-ids $sgId --region $Region --output json 2>&1 | ConvertFrom-Json
        foreach ($rule in $sgJson.SecurityGroups[0].IpPermissions) {
            $from = if ($rule.FromPort) { [int]$rule.FromPort } else { 0 }
            $to = if ($rule.ToPort) { [int]$rule.ToPort } else { 65535 }
            if ($from -le $Port -and $to -ge $Port) {
                $open = $rule.IpRanges | Where-Object { $_.CidrIp -eq "0.0.0.0/0" }
                if ($open) { $hasRule = $true; break }
            }
        }
    } catch { }

    if (-not $hasRule) {
        try {
            aws ec2 authorize-security-group-ingress --group-id $sgId --region $Region `
                --protocol $Protocol --port $Port --cidr 0.0.0.0/0 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Add-Result $GroupName $false "Failed to add ingress rule on port $Port"
                return
            }
        } catch {
            Add-Result $GroupName $false "Failed to authorize ingress: $_"
            return
        }
    }

    Add-Result $GroupName $true "SG $sgId allows port $Port from 0.0.0.0/0"
}

Write-Host "=== Creating intentional misconfigurations in $Region ===" -ForegroundColor Cyan
Write-Host ""

# 1. S3 bucket with public ACL (CRITICAL)
$PublicBucket = "aivar-test-public-$Timestamp"
Write-Host "Creating public ACL bucket: $PublicBucket"
try {
    aws s3api create-bucket --bucket $PublicBucket --region $Region `
        --create-bucket-configuration LocationConstraint=$Region 2>&1 | Out-Null
    aws s3api put-public-access-block --bucket $PublicBucket `
        --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" 2>&1 | Out-Null
    aws s3api put-bucket-ownership-controls --bucket $PublicBucket `
        --ownership-controls Rules=[{ObjectOwnership=ObjectWriter}] 2>&1 | Out-Null
    aws s3api put-bucket-acl --bucket $PublicBucket --acl public-read 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Add-Result "s3_public_acl" $true "Bucket $PublicBucket with public-read ACL"
    } else {
        Add-Result "s3_public_acl" $false "put-bucket-acl failed (check Block Public Access)"
    }
} catch {
    Add-Result "s3_public_acl" $false $_.Exception.Message
}

# 2. S3 bucket with public read policy (CRITICAL)
# Note: account-level S3 default encryption prevents unencrypted-bucket demos on newer accounts.
$PolicyBucket = "aivar-test-policy-$Timestamp"
Write-Host "Creating public-policy bucket: $PolicyBucket"
try {
    aws s3api create-bucket --bucket $PolicyBucket --region $Region `
        --create-bucket-configuration LocationConstraint=$Region 2>&1 | Out-Null
    aws s3api put-public-access-block --bucket $PolicyBucket `
        --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" 2>&1 | Out-Null
    $policy = @"
{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::$PolicyBucket/*"}]}
"@
    aws s3api put-bucket-policy --bucket $PolicyBucket --policy $policy 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Add-Result "s3_public_policy" $true "Bucket $PolicyBucket with public read policy"
    } else {
        Add-Result "s3_public_policy" $false "put-bucket-policy failed"
    }
} catch {
    Add-Result "s3_public_policy" $false $_.Exception.Message
}

# 3. IAM user without MFA (HIGH)
Write-Host "Creating IAM user test-no-mfa-user"
try {
    aws iam create-user --user-name test-no-mfa-user 2>&1 | Out-Null
    aws iam create-login-profile --user-name test-no-mfa-user `
        --password "TestPass@123!" --no-password-reset-required 2>&1 | Out-Null
    $profile = aws iam get-login-profile --user-name test-no-mfa-user 2>&1
    if ($LASTEXITCODE -eq 0) {
        Add-Result "iam_user_mfa" $true "User test-no-mfa-user with console access, no MFA"
    } else {
        Add-Result "iam_user_mfa" $false "Login profile not created"
    }
} catch {
    Add-Result "iam_user_mfa" $false $_.Exception.Message
}

# 4-5. Security groups
$VpcId = aws ec2 describe-vpcs --region $Region --filters "Name=isDefault,Values=true" `
    --query "Vpcs[0].VpcId" --output text 2>&1
if (-not $VpcId -or $VpcId -eq "None") {
    Add-Result "open-ssh-sg" $false "No default VPC found in $Region"
    Add-Result "open-rdp-sg" $false "No default VPC found in $Region"
} else {
    $VpcId = $VpcId.Trim()
    Write-Host "Using VPC: $VpcId"
    Ensure-SecurityGroupRule -GroupName "open-ssh-sg" -Description "Test SG with open SSH" `
        -VpcId $VpcId -Port 22
    Ensure-SecurityGroupRule -GroupName "open-rdp-sg" -Description "Test SG with open RDP" `
        -VpcId $VpcId -Port 3389
}

Write-Host ""
$passCount = ($results | Where-Object { $_.Pass }).Count
$failCount = ($results | Where-Object { -not $_.Pass }).Count
Write-Host "=== Setup complete: $passCount passed, $failCount failed ===" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "Public bucket:      $PublicBucket"
Write-Host "Unencrypted bucket: $NoEncBucket"
Write-Host ""
Write-Host "Note: Root MFA disabled and missing password policy are default on new accounts."
Write-Host "Note: CloudTrail is not enabled by default — will trigger cloudtrail_not_logging."
Write-Host ""

$verifyScript = Join-Path $PSScriptRoot "verify_test_misconfigs.ps1"
if (Test-Path $verifyScript) {
    Write-Host "Running scanner-side verification..." -ForegroundColor Cyan
    & $verifyScript
}
