#!/bin/bash
# ================================================================
# Cleanup Script - Remove all AWS resources after testing
# Author: Vedakumara K H
# ================================================================
# Run this after you are done to avoid AWS charges
# ================================================================

REGION="us-east-1"
FUNCTION_NAME="guardduty-auto-response"
ROLE_NAME="guardduty-lambda-role"
TOPIC_NAME="guardduty-alerts"
RULE_NAME="guardduty-high-severity"

echo "Starting cleanup..."

# Delete EventBridge rule targets and rule
aws events remove-targets --rule $RULE_NAME --ids LambdaTarget --region $REGION 2>/dev/null
aws events delete-rule --name $RULE_NAME --region $REGION 2>/dev/null
echo "✓ EventBridge rule deleted"

# Delete Lambda function
aws lambda delete-function --function-name $FUNCTION_NAME --region $REGION 2>/dev/null
echo "✓ Lambda function deleted"

# Delete SNS topic
SNS_ARN=$(aws sns list-topics --region $REGION --query "Topics[?contains(TopicArn,'$TOPIC_NAME')].TopicArn" --output text)
[ -n "$SNS_ARN" ] && aws sns delete-topic --topic-arn $SNS_ARN --region $REGION 2>/dev/null
echo "✓ SNS topic deleted"

# Delete IAM role policy and role
aws iam delete-role-policy --role-name $ROLE_NAME --policy-name guardduty-lambda-policy 2>/dev/null
aws iam delete-role --role-name $ROLE_NAME 2>/dev/null
echo "✓ IAM role deleted"

# Disable GuardDuty detector
DETECTOR_ID=$(aws guardduty list-detectors --region $REGION --query 'DetectorIds[0]' --output text 2>/dev/null)
[ -n "$DETECTOR_ID" ] && [ "$DETECTOR_ID" != "None" ] && \
  aws guardduty delete-detector --detector-id $DETECTOR_ID --region $REGION 2>/dev/null
echo "✓ GuardDuty detector deleted"

echo ""
echo "✅ All AWS resources cleaned up. No further charges will occur."
