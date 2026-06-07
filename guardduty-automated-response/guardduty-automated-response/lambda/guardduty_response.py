#!/usr/bin/env python3
"""
================================================================
GuardDuty Automated Threat Response - Lambda Function
================================================================
Project : Automated Threat Detection with Python + AWS GuardDuty
Author  : Vedakumara K H
GitHub  : https://github.com/vedakumarakh

What this does:
  1. Receives GuardDuty findings via EventBridge
  2. Parses finding type, severity, and affected resource
  3. For HIGH severity (>= 7): auto-isolates EC2 instance
     by moving it to a quarantine security group
  4. Sends detailed alert email via SNS
  5. Logs all actions to CloudWatch

Supported finding types handled:
  - UnauthorizedAccess:EC2/SSHBruteForce
  - Recon:EC2/PortProbeUnprotectedPort
  - UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
  - CryptoCurrency:EC2/BitcoinTool.B
  - Trojan:EC2/BlackholeTraffic
  - Backdoor:EC2/C&CActivity.B
================================================================
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

SNS_TOPIC_ARN   = os.environ["SNS_TOPIC_ARN"]
ISOLATION_SG_ID = os.environ["ISOLATION_SG_ID"]
AUTO_ISOLATE_THRESHOLD = float(os.environ.get("AUTO_ISOLATE_THRESHOLD", "7.0"))


# ── Severity mapping ──────────────────────────────────────────
SEVERITY_LABEL = {
    range(0, 4):   ("LOW",      "🟡"),
    range(4, 7):   ("MEDIUM",   "🟠"),
    range(7, 9):   ("HIGH",     "🔴"),
    range(9, 10):  ("CRITICAL", "🚨"),
}

def get_severity_label(score: float) -> tuple:
    score_int = int(score)
    for r, label in SEVERITY_LABEL.items():
        if score_int in r:
            return label
    return ("UNKNOWN", "⚪")


# ── Extract affected resource details ─────────────────────────
def extract_resource(detail: dict) -> dict:
    resource = detail.get("resource", {})
    resource_type = resource.get("resourceType", "Unknown")
    result = {"type": resource_type, "instance_id": None, "iam_user": None, "ip": None}

    if resource_type == "Instance":
        inst = resource.get("instanceDetails", {})
        result["instance_id"] = inst.get("instanceId")
        result["ip"] = inst.get("networkInterfaces", [{}])[0].get("privateIpAddress")
        result["image_id"] = inst.get("imageId", "N/A")
        result["tags"] = inst.get("tags", [])

    elif resource_type == "AccessKey":
        user = resource.get("accessKeyDetails", {})
        result["iam_user"] = user.get("userName", "Unknown")
        result["access_key"] = user.get("accessKeyId", "N/A")
        result["user_type"] = user.get("userType", "N/A")

    return result


# ── EC2 isolation logic ───────────────────────────────────────
def isolate_ec2_instance(instance_id: str) -> dict:
    """
    Moves EC2 instance to quarantine security group.
    Removes ALL existing security groups — cutting off network access.
    Returns dict with success status and previous SGs.
    """
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations:
            return {"success": False, "error": "Instance not found"}

        instance = reservations[0]["Instances"][0]
        current_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
        current_state = instance["State"]["Name"]

        if current_state == "terminated":
            return {"success": False, "error": "Instance already terminated"}

        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[ISOLATION_SG_ID]
        )

        logger.info(f"ISOLATION SUCCESS: {instance_id} moved to {ISOLATION_SG_ID}")
        logger.info(f"Previous SGs removed: {current_sgs}")

        return {
            "success": True,
            "instance_id": instance_id,
            "previous_sgs": current_sgs,
            "isolation_sg": ISOLATION_SG_ID,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except ec2.exceptions.ClientError as e:
        error_msg = str(e)
        logger.error(f"EC2 isolation FAILED for {instance_id}: {error_msg}")
        return {"success": False, "error": error_msg}

    except Exception as e:
        logger.error(f"Unexpected error isolating {instance_id}: {e}")
        return {"success": False, "error": str(e)}


# ── SNS alert builder ─────────────────────────────────────────
def build_alert_message(detail: dict, resource: dict, isolation_result: dict, severity_label: str, severity_icon: str) -> str:
    finding_type = detail.get("type", "Unknown")
    severity     = detail.get("severity", 0)
    region       = detail.get("region", "unknown")
    finding_id   = detail.get("id", "N/A")
    account_id   = detail.get("accountId", "N/A")
    description  = detail.get("description", "No description available.")
    timestamp    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "=" * 60,
        f"  {severity_icon} GUARDDUTY SECURITY ALERT — {severity_label}",
        "=" * 60,
        "",
        f"  Time        : {timestamp}",
        f"  Finding     : {finding_type}",
        f"  Severity    : {severity}/10  ({severity_label})",
        f"  Region      : {region}",
        f"  Account     : {account_id}",
        f"  Finding ID  : {finding_id}",
        "",
        "  DESCRIPTION",
        "  " + "-" * 56,
        f"  {description}",
        "",
        "  AFFECTED RESOURCE",
        "  " + "-" * 56,
        f"  Resource Type : {resource['type']}",
    ]

    if resource["instance_id"]:
        lines += [
            f"  Instance ID   : {resource['instance_id']}",
            f"  Private IP    : {resource.get('ip', 'N/A')}",
            f"  Image ID      : {resource.get('image_id', 'N/A')}",
        ]
        tags = resource.get("tags", [])
        if tags:
            lines.append(f"  Tags          : {', '.join([t['key']+':'+t['value'] for t in tags[:3]])}")

    if resource["iam_user"]:
        lines += [
            f"  IAM User      : {resource['iam_user']}",
            f"  Access Key    : {resource.get('access_key', 'N/A')}",
            f"  User Type     : {resource.get('user_type', 'N/A')}",
        ]

    lines += ["", "  AUTOMATED RESPONSE", "  " + "-" * 56]

    if isolation_result.get("success"):
        lines += [
            f"  ✅ EC2 ISOLATED — instance moved to quarantine SG",
            f"  Quarantine SG : {isolation_result['isolation_sg']}",
            f"  Previous SGs  : {', '.join(isolation_result.get('previous_sgs', []))}",
            f"  Isolated at   : {isolation_result.get('timestamp', 'N/A')}",
            "",
            "  ⚠️  ACTION REQUIRED: Investigate instance immediately.",
            "  To restore: manually re-add original security groups",
            "  after completing forensic investigation.",
        ]
    elif isolation_result.get("attempted") and not isolation_result.get("success"):
        lines += [
            f"  ❌ ISOLATION FAILED: {isolation_result.get('error', 'Unknown error')}",
            "  ⚠️  MANUAL ISOLATION REQUIRED IMMEDIATELY",
        ]
    else:
        lines += [
            f"  ℹ️  Auto-isolation not triggered",
            f"  Reason: Severity {severity} below threshold {AUTO_ISOLATE_THRESHOLD}",
            "  or no EC2 instance in this finding.",
            "",
            "  Review manually if needed.",
        ]

    lines += [
        "",
        "  " + "=" * 56,
        "  Automated by GuardDuty Response Lambda",
        "  Author: Vedakumara K H | github.com/vedakumarakh",
        "=" * 60,
    ]

    return "\n".join(lines)


# ── Main Lambda handler ───────────────────────────────────────
def lambda_handler(event, context):
    logger.info("GuardDuty response Lambda triggered")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    detail = event.get("detail", {})
    if not detail:
        logger.warning("No detail found in event — skipping")
        return {"statusCode": 400, "body": "No GuardDuty finding detail"}

    finding_type = detail.get("type", "Unknown")
    severity     = float(detail.get("severity", 0))
    finding_id   = detail.get("id", "N/A")

    severity_label, severity_icon = get_severity_label(severity)
    resource = extract_resource(detail)

    logger.info(f"Finding: {finding_type} | Severity: {severity} ({severity_label})")
    logger.info(f"Resource: {resource['type']} | Instance: {resource['instance_id']}")

    # ── Auto-isolation decision ──
    isolation_result = {"attempted": False, "success": False}

    if severity >= AUTO_ISOLATE_THRESHOLD and resource["instance_id"]:
        logger.info(f"HIGH severity + EC2 instance detected — initiating isolation")
        isolation_result = isolate_ec2_instance(resource["instance_id"])
        isolation_result["attempted"] = True
    else:
        logger.info(f"Auto-isolation not triggered (severity={severity}, instance={resource['instance_id']})")

    # ── Build and send SNS alert ──
    alert_body = build_alert_message(detail, resource, isolation_result, severity_label, severity_icon)

    subject = f"[{severity_icon} GuardDuty {severity_label}] {finding_type}"[:100]

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=alert_body
        )
        logger.info("SNS alert sent successfully")
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")

    response_body = {
        "finding_type":    finding_type,
        "finding_id":      finding_id,
        "severity":        severity,
        "severity_label":  severity_label,
        "resource_type":   resource["type"],
        "instance_id":     resource["instance_id"],
        "iam_user":        resource["iam_user"],
        "isolated":        isolation_result.get("success", False),
        "alert_sent":      True,
    }

    logger.info(f"Response: {json.dumps(response_body)}")
    return {"statusCode": 200, "body": json.dumps(response_body)}
