# Cleanup test misconfigurations created by setup scripts
# Run with ADMIN credentials

$ErrorActionPreference = "Continue"
$Region = "ap-south-1"

Write-Host "=== Cleaning up test resources ===" -ForegroundColor Cyan

# Delete test S3 buckets
aws s3 ls | Select-String "aivar-test-" | ForEach-Object {
    $bucket = ($_ -split '\s+')[-1]
    Write-Host "Emptying and deleting bucket: $bucket"
    aws s3 rm "s3://$bucket" --recursive 2>$null
    aws s3api delete-bucket --bucket $bucket --region $Region 2>$null
}

# Delete test security groups
foreach ($sg in @("open-ssh-sg", "open-rdp-sg")) {
    Write-Host "Deleting security group: $sg"
    aws ec2 delete-security-group --group-name $sg --region $Region 2>$null
}

# Delete test IAM user
Write-Host "Deleting IAM user test-no-mfa-user"
aws iam delete-login-profile --user-name test-no-mfa-user 2>$null
aws iam list-access-keys --user-name test-no-mfa-user --query "AccessKeyMetadata[].AccessKeyId" --output text 2>$null | ForEach-Object {
    if ($_) { aws iam delete-access-key --user-name test-no-mfa-user --access-key-id $_ 2>$null }
}
aws iam delete-user --user-name test-no-mfa-user 2>$null

Write-Host "=== Cleanup complete ===" -ForegroundColor Green
