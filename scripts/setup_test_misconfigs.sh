#!/usr/bin/env bash
# AWS Test Environment Setup — intentional misconfigurations
# Run with ADMIN credentials (not the scanner user). Region: ap-south-1

set -uo pipefail

REGION="ap-south-1"
TIMESTAMP=$(date +%s)
PASS=0
FAIL=0

log_result() {
    local name="$1"
    local ok="$2"
    local detail="$3"
    if [[ "$ok" == "1" ]]; then
        echo "  [PASS] $name - $detail"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name - $detail"
        FAIL=$((FAIL + 1))
    fi
}

ensure_sg_rule() {
    local group_name="$1"
    local description="$2"
    local vpc_id="$3"
    local port="$4"

    local sg_id
    sg_id=$(aws ec2 describe-security-groups --region "$REGION" \
        --filters "Name=group-name,Values=$group_name" "Name=vpc-id,Values=$vpc_id" \
        --query "SecurityGroups[0].GroupId" --output text 2>/dev/null || true)

    if [[ -z "$sg_id" || "$sg_id" == "None" ]]; then
        sg_id=$(aws ec2 create-security-group --group-name "$group_name" \
            --description "$description" --vpc-id "$vpc_id" --region "$REGION" \
            --query "GroupId" --output text 2>/dev/null || true)
    fi

    if [[ -z "$sg_id" || "$sg_id" == "None" ]]; then
        log_result "$group_name" 0 "Failed to create or find security group"
        return
    fi

    local has_rule
    has_rule=$(aws ec2 describe-security-groups --group-ids "$sg_id" --region "$REGION" \
        --query "SecurityGroups[0].IpPermissions[?FromPort<=$port && ToPort>=$port].IpRanges[?CidrIp=='0.0.0.0/0']" \
        --output text 2>/dev/null || true)

    if [[ -z "$has_rule" ]]; then
        if ! aws ec2 authorize-security-group-ingress --group-id "$sg_id" --region "$REGION" \
            --protocol tcp --port "$port" --cidr 0.0.0.0/0 2>/dev/null; then
            log_result "$group_name" 0 "Failed to add ingress rule on port $port"
            return
        fi
    fi

    log_result "$group_name" 1 "SG $sg_id allows port $port from 0.0.0.0/0"
}

echo "=== Creating intentional misconfigurations in $REGION ==="
echo ""

# 1. S3 bucket with public ACL (CRITICAL)
PUBLIC_BUCKET="aivar-test-public-${TIMESTAMP}"
echo "Creating public ACL bucket: $PUBLIC_BUCKET"
if aws s3api create-bucket --bucket "$PUBLIC_BUCKET" --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null \
    && aws s3api put-public-access-block --bucket "$PUBLIC_BUCKET" \
    --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" 2>/dev/null \
    && aws s3api put-bucket-ownership-controls --bucket "$PUBLIC_BUCKET" \
    --ownership-controls Rules=[{ObjectOwnership=ObjectWriter}] 2>/dev/null \
    && aws s3api put-bucket-acl --bucket "$PUBLIC_BUCKET" --acl public-read 2>/dev/null; then
    log_result "s3_public_acl" 1 "Bucket $PUBLIC_BUCKET with public-read ACL"
else
    log_result "s3_public_acl" 0 "Failed (check Block Public Access settings)"
fi

# 2. S3 bucket with public read policy (CRITICAL)
# Account-level default encryption prevents unencrypted-bucket demos on newer accounts.
POLICY_BUCKET="aivar-test-policy-${TIMESTAMP}"
echo "Creating public-policy bucket: $POLICY_BUCKET"
if aws s3api create-bucket --bucket "$POLICY_BUCKET" --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" 2>/dev/null \
    && aws s3api put-public-access-block --bucket "$POLICY_BUCKET" \
    --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" 2>/dev/null \
    && aws s3api put-bucket-policy --bucket "$POLICY_BUCKET" --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"PublicRead\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::${POLICY_BUCKET}/*\"}]}" 2>/dev/null; then
    log_result "s3_public_policy" 1 "Bucket $POLICY_BUCKET with public read policy"
else
    log_result "s3_public_policy" 0 "put-bucket-policy failed"
fi

# 3. IAM user without MFA (HIGH)
echo "Creating IAM user test-no-mfa-user"
aws iam create-user --user-name test-no-mfa-user 2>/dev/null || true
aws iam create-login-profile --user-name test-no-mfa-user \
    --password 'TestPass@123!' --no-password-reset-required 2>/dev/null || true
if aws iam get-login-profile --user-name test-no-mfa-user 2>/dev/null; then
    log_result "iam_user_mfa" 1 "User test-no-mfa-user with console access, no MFA"
else
    log_result "iam_user_mfa" 0 "Login profile not created"
fi

# 4-5. Security groups
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
    --filters "Name=isDefault,Values=true" --query "Vpcs[0].VpcId" --output text 2>/dev/null || true)
if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
    log_result "open-ssh-sg" 0 "No default VPC found in $REGION"
    log_result "open-rdp-sg" 0 "No default VPC found in $REGION"
else
    echo "Using VPC: $VPC_ID"
    ensure_sg_rule "open-ssh-sg" "Test SG with open SSH" "$VPC_ID" 22
    ensure_sg_rule "open-rdp-sg" "Test SG with open RDP" "$VPC_ID" 3389
fi

echo ""
echo "=== Setup complete: $PASS passed, $FAIL failed ==="
echo "Public bucket:      $PUBLIC_BUCKET"
echo "Unencrypted bucket: $NOENC_BUCKET"
echo ""
echo "Note: Root MFA disabled and missing password policy are default on new accounts."
echo "Note: CloudTrail is not enabled by default — will trigger cloudtrail_not_logging."
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/verify_test_misconfigs.ps1" ]]; then
    echo "Run scanner-side verification (PowerShell):"
    echo "  pwsh $SCRIPT_DIR/verify_test_misconfigs.ps1"
fi
