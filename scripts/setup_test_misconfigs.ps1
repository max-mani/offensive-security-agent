# AWS Test Environment Setup Scripts
# Run these with ADMIN credentials (not the scanner user).
# Region: ap-south-1

$ErrorActionPreference = "Stop"
$Region = "ap-south-1"
$Timestamp = [int][double]::Parse((Get-Date -UFormat %s))

Write-Host "=== Creating intentional misconfigurations in $Region ===" -ForegroundColor Cyan

# 1. S3 bucket with public ACL (CRITICAL)
$PublicBucket = "aivar-test-public-$Timestamp"
Write-Host "Creating public ACL bucket: $PublicBucket"
aws s3api create-bucket --bucket $PublicBucket --region $Region `
    --create-bucket-configuration LocationConstraint=$Region
aws s3api put-public-access-block --bucket $PublicBucket `
    --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
aws s3api put-bucket-acl --bucket $PublicBucket --acl public-read

# 2. S3 bucket without encryption (HIGH)
$NoEncBucket = "aivar-test-noenc-$Timestamp"
Write-Host "Creating unencrypted bucket: $NoEncBucket"
aws s3api create-bucket --bucket $NoEncBucket --region $Region `
    --create-bucket-configuration LocationConstraint=$Region

# 3. IAM user without MFA (HIGH)
Write-Host "Creating IAM user test-no-mfa-user"
aws iam create-user --user-name test-no-mfa-user 2>$null
aws iam create-login-profile --user-name test-no-mfa-user `
    --password "TestPass@123!" --no-password-reset-required 2>$null

# 4. Security Group with open SSH (CRITICAL)
Write-Host "Creating open-ssh-sg"
$VpcId = aws ec2 describe-vpcs --region $Region --filters "Name=isDefault,Values=true" `
    --query "Vpcs[0].VpcId" --output text
aws ec2 create-security-group --group-name open-ssh-sg `
    --description "Test SG with open SSH" --vpc-id $VpcId --region $Region 2>$null
aws ec2 authorize-security-group-ingress --group-name open-ssh-sg `
    --protocol tcp --port 22 --cidr 0.0.0.0/0 --region $Region 2>$null

# 5. Security Group with open RDP (CRITICAL)
Write-Host "Creating open-rdp-sg"
aws ec2 create-security-group --group-name open-rdp-sg `
    --description "Test SG with open RDP" --vpc-id $VpcId --region $Region 2>$null
aws ec2 authorize-security-group-ingress --group-name open-rdp-sg `
    --protocol tcp --port 3389 --cidr 0.0.0.0/0 --region $Region 2>$null

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Green
Write-Host "Public bucket:    $PublicBucket"
Write-Host "Unencrypted bucket: $NoEncBucket"
Write-Host ""
Write-Host "Note: Root MFA disabled and missing password policy are default on new accounts."
Write-Host "Note: CloudTrail is not enabled by default � will trigger cloudtrail_not_logging."
Write-Host ""
Write-Host "Next: Create scanner IAM user 'aivar-scanner' with read-only policies (see README)."
