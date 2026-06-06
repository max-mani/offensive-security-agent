#!/usr/bin/env bash
# AWS Test Environment Setup � intentional misconfigurations
# Run with ADMIN credentials (not the scanner user). Region: ap-south-1

set -euo pipefail

REGION="ap-south-1"
TIMESTAMP=$(date +%s)

echo "=== Creating intentional misconfigurations in $REGION ==="

# 1. S3 bucket with public ACL (CRITICAL)
PUBLIC_BUCKET="aivar-test-public-${TIMESTAMP}"
echo "Creating public ACL bucket: $PUBLIC_BUCKET"
aws s3api create-bucket --bucket "$PUBLIC_BUCKET" --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION"
aws s3api put-public-access-block --bucket "$PUBLIC_BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
aws s3api put-bucket-acl --bucket "$PUBLIC_BUCKET" --acl public-read

# 2. S3 bucket without encryption (HIGH)
NOENC_BUCKET="aivar-test-noenc-${TIMESTAMP}"
echo "Creating unencrypted bucket: $NOENC_BUCKET"
aws s3api create-bucket --bucket "$NOENC_BUCKET" --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION"

# 3. IAM user without MFA (HIGH)
echo "Creating IAM user test-no-mfa-user"
aws iam create-user --user-name test-no-mfa-user 2>/dev/null || true
aws iam create-login-profile --user-name test-no-mfa-user \
  --password 'TestPass@123!' --no-password-reset-required 2>/dev/null || true

# 4. Security Group with open SSH (CRITICAL)
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
  --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text)
echo "Creating open-ssh-sg in VPC $VPC_ID"
aws ec2 create-security-group --group-name open-ssh-sg \
  --description "Test SG with open SSH" --vpc-id "$VPC_ID" --region "$REGION" 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-name open-ssh-sg \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 --region "$REGION" 2>/dev/null || true

# 5. Security Group with open RDP (CRITICAL)
echo "Creating open-rdp-sg"
aws ec2 create-security-group --group-name open-rdp-sg \
  --description "Test SG with open RDP" --vpc-id "$VPC_ID" --region "$REGION" 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-name open-rdp-sg \
  --protocol tcp --port 3389 --cidr 0.0.0.0/0 --region "$REGION" 2>/dev/null || true

echo ""
echo "=== Setup complete ==="
echo "Public bucket:      $PUBLIC_BUCKET"
echo "Unencrypted bucket: $NOENC_BUCKET"
echo ""
echo "Note: Root MFA disabled and missing password policy are default on new accounts."
echo "Note: CloudTrail is not enabled by default � will trigger cloudtrail_not_logging."
echo ""
echo "Next: Create scanner IAM user 'aivar-scanner' with read-only policies (see README)."
