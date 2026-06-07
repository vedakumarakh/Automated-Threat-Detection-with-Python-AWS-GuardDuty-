#!/bin/bash
# ================================================================
# AWS Setup Script - GuardDuty Automated Response
# Author: Vedakumara K H
# ================================================================
# Run this step by step — do NOT run the whole script at once.
# Each section is a separate phase.
# ================================================================

set -e

REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
FUNCTION_NAME="guardduty-auto-response"
ROLE_NAME="guardduty-lambda-role"
TOPIC_NAME="guardduty-alerts"
RULE_NAME="guardduty-high-severity"

echo "Account ID: $ACCOUNT_ID"
echo "Region    : $REGION"

# ── PHASE 1: Enable GuardDuty ─────────────────────────────────
echo ""
echo "=== PHASE 1: Enable GuardDuty ==="

DETECTOR_ID=$(aws guardduty list-detectors \
  --region $REGION \
  --query 'DetectorIds[0]' \
  --output text 2>/dev/null || echo "None")

if [ "$DETECTOR_ID" == "None" ] || [ -z "$DETECTOR_ID" ]; then
  DETECTOR_ID=$(aws guardduty create-detector \
    --enable \
    --region $REGION \
    --query 'DetectorId' \
    --output text)
  echo "GuardDuty enabled. Detector ID: $DETECTOR_ID"
else
  echo "GuardDuty already enabled. Detector ID: $DETECTOR_ID"
fi

# ── PHASE 2: Create SNS Topic ─────────────────────────────────
echo ""
echo "=== PHASE 2: Create SNS Topic ==="

SNS_ARN=$(aws sns create-topic \
  --name $TOPIC_NAME \
  --region $REGION \
  --query 'TopicArn' \
  --output text)

echo "SNS Topic ARN: $SNS_ARN"

# Subscribe your email — replace with your actual email
YOUR_EMAIL="vedakumarakh@gmail.com"

aws sns subscribe \
  --topic-arn $SNS_ARN \
  --protocol email \
  --notification-endpoint $YOUR_EMAIL \
  --region $REGION

echo "Subscription email sent to $YOUR_EMAIL — confirm it in your inbox!"

# ── PHASE 3: Create Quarantine Security Group ─────────────────
echo ""
echo "=== PHASE 3: Create Isolation Security Group ==="

VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=isDefault,Values=true" \
  --query 'Vpcs[0].VpcId' \
  --output text \
  --region $REGION)

echo "Default VPC: $VPC_ID"

ISOLATION_SG_ID=$(aws ec2 create-security-group \
  --group-name "guardduty-quarantine-sg" \
  --description "GuardDuty quarantine - NO inbound or outbound rules - isolation only" \
  --vpc-id $VPC_ID \
  --region $REGION \
  --query 'GroupId' \
  --output text)

echo "Isolation SG created: $ISOLATION_SG_ID"

# Remove the default outbound rule from the isolation SG
aws ec2 revoke-security-group-egress \
  --group-id $ISOLATION_SG_ID \
  --protocol -1 \
  --port -1 \
  --cidr 0.0.0.0/0 \
  --region $REGION 2>/dev/null || true

echo "All rules removed from isolation SG — instance will be fully cut off"

# ── PHASE 4: Create IAM Role for Lambda ──────────────────────
echo ""
echo "=== PHASE 4: Create Lambda IAM Role ==="

aws iam create-role \
  --role-name $ROLE_NAME \
  --assume-role-policy-document file://iam/lambda-trust-policy.json \
  --region $REGION 2>/dev/null || echo "Role already exists"

aws iam put-role-policy \
  --role-name $ROLE_NAME \
  --policy-name "guardduty-lambda-policy" \
  --policy-document file://iam/lambda-execution-policy.json

LAMBDA_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo "Lambda Role ARN: $LAMBDA_ROLE_ARN"

# Wait for role to propagate
echo "Waiting 10s for IAM role propagation..."
sleep 10

# ── PHASE 5: Deploy Lambda Function ──────────────────────────
echo ""
echo "=== PHASE 5: Deploy Lambda Function ==="

# Package the Lambda
cd lambda
zip -r ../lambda-package.zip guardduty_response.py
cd ..

# Check if function exists
EXISTING=$(aws lambda get-function \
  --function-name $FUNCTION_NAME \
  --region $REGION \
  --query 'Configuration.FunctionName' \
  --output text 2>/dev/null || echo "None")

if [ "$EXISTING" == "None" ]; then
  aws lambda create-function \
    --function-name $FUNCTION_NAME \
    --runtime python3.12 \
    --role $LAMBDA_ROLE_ARN \
    --handler guardduty_response.lambda_handler \
    --zip-file fileb://lambda-package.zip \
    --timeout 30 \
    --memory-size 128 \
    --environment "Variables={SNS_TOPIC_ARN=$SNS_ARN,ISOLATION_SG_ID=$ISOLATION_SG_ID,AUTO_ISOLATE_THRESHOLD=7.0}" \
    --region $REGION
  echo "Lambda function created"
else
  aws lambda update-function-code \
    --function-name $FUNCTION_NAME \
    --zip-file fileb://lambda-package.zip \
    --region $REGION
  echo "Lambda function updated"
fi

LAMBDA_ARN=$(aws lambda get-function \
  --function-name $FUNCTION_NAME \
  --region $REGION \
  --query 'Configuration.FunctionArn' \
  --output text)

echo "Lambda ARN: $LAMBDA_ARN"

# ── PHASE 6: Create EventBridge Rule ─────────────────────────
echo ""
echo "=== PHASE 6: Create EventBridge Rule ==="

aws events put-rule \
  --name $RULE_NAME \
  --event-pattern file://eventbridge/event-pattern-medium-and-above.json \
  --state ENABLED \
  --region $REGION

RULE_ARN="arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/${RULE_NAME}"
echo "EventBridge rule ARN: $RULE_ARN"

# Grant EventBridge permission to invoke Lambda
aws lambda add-permission \
  --function-name $FUNCTION_NAME \
  --statement-id "EventBridgeGuardDuty" \
  --action "lambda:InvokeFunction" \
  --principal "events.amazonaws.com" \
  --source-arn $RULE_ARN \
  --region $REGION 2>/dev/null || echo "Permission already exists"

# Add Lambda as EventBridge target
aws events put-targets \
  --rule $RULE_NAME \
  --targets "Id=LambdaTarget,Arn=$LAMBDA_ARN" \
  --region $REGION

echo "EventBridge target set to Lambda"

# ── PHASE 7: Test End-to-End ──────────────────────────────────
echo ""
echo "=== PHASE 7: Generate Sample Findings (Test) ==="

aws guardduty create-sample-findings \
  --detector-id $DETECTOR_ID \
  --finding-types \
    "UnauthorizedAccess:EC2/SSHBruteForce" \
    "Recon:EC2/PortProbeUnprotectedPort" \
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B" \
  --region $REGION

echo ""
echo "✅ Sample findings generated!"
echo "   Wait 2-3 minutes then check:"
echo "   1. Your email inbox for SNS alert"
echo "   2. Lambda CloudWatch logs:"
echo "      aws logs tail /aws/lambda/$FUNCTION_NAME --follow --region $REGION"
echo ""
echo "================================================================"
echo "  SETUP COMPLETE"
echo "  Detector ID   : $DETECTOR_ID"
echo "  SNS Topic ARN : $SNS_ARN"
echo "  Isolation SG  : $ISOLATION_SG_ID"
echo "  Lambda ARN    : $LAMBDA_ARN"
echo "================================================================"
echo ""
echo "⚠️  IMPORTANT: Disable GuardDuty after testing to avoid charges:"
echo "   aws guardduty delete-detector --detector-id $DETECTOR_ID --region $REGION"
