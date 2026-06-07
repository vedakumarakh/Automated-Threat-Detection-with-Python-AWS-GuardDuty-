# Automated Threat Detection with Python + AWS GuardDuty

An automated cloud security incident response system built on AWS. When GuardDuty detects a threat, this system automatically isolates the compromised EC2 instance and sends an alert — reducing mean time to respond from hours to under 60 seconds.

---

## Architecture

```
GuardDuty Finding
      │
      ▼
EventBridge Rule
(severity >= 4)
      │
      ▼
Lambda Function (Python)
      │
      ├── severity >= 7 + EC2?
      │         │
      │         ▼
      │   EC2 Auto-Isolation
      │   (quarantine SG)
      │
      └── All findings
                │
                ▼
           SNS → Email Alert
```

---

## What This Project Does

| Step | Action |
|---|---|
| 1 | GuardDuty detects a threat (brute force, port scan, suspicious API call) |
| 2 | EventBridge rule triggers Lambda for all findings with severity ≥ 4 |
| 3 | Lambda parses finding type, severity, affected resource |
| 4 | If severity ≥ 7 and EC2 instance involved → auto-isolates instance |
| 5 | Sends detailed email alert via SNS with full finding details |
| 6 | Logs all actions to CloudWatch |

---

## Repository Structure

```
guardduty-automated-response/
├── lambda/
│   └── guardduty_response.py          ← Main Lambda function (Python)
├── iam/
│   ├── lambda-execution-policy.json   ← IAM permissions policy
│   └── lambda-trust-policy.json       ← IAM trust policy
├── eventbridge/
│   ├── event-pattern-medium-and-above.json  ← Trigger rule (severity ≥ 4)
│   └── event-pattern-high-severity.json     ← High severity only (≥ 7)
├── tests/
│   ├── test_lambda.py                 ← Unit tests (unittest + mock)
│   └── sample-finding-high-severity.json    ← Sample event for testing
├── screenshots/                       ← Lab screenshots
├── docs/
│   └── architecture.md               ← Detailed architecture notes
├── setup.sh                           ← Step-by-step AWS setup script
├── cleanup.sh                         ← Resource teardown script
└── README.md
```

---

## Lambda Function — What It Does

**File**: `lambda/guardduty_response.py`

```python
def lambda_handler(event, context):
    # 1. Parse GuardDuty finding from EventBridge event
    # 2. Extract severity, finding type, affected resource
    # 3. If HIGH severity + EC2 instance → isolate instance
    # 4. Send SNS email alert with full details
    # 5. Return JSON response with all actions taken
```

### EC2 Auto-Isolation Logic

When a HIGH severity finding (≥ 7) involves an EC2 instance:

```python
ec2.modify_instance_attribute(
    InstanceId=instance_id,
    Groups=[ISOLATION_SG_ID]  # Quarantine SG — no inbound/outbound rules
)
```

This removes the instance from ALL security groups and moves it to an empty quarantine security group — completely cutting off network access in seconds.

### Supported Finding Types

| Finding Type | Severity | Auto-Isolate |
|---|---|---|
| UnauthorizedAccess:EC2/SSHBruteForce | 7.8 | ✅ Yes |
| Recon:EC2/PortProbeUnprotectedPort | 3.0–5.0 | ❌ Alert only |
| UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B | 5.0 | ❌ Alert only |
| CryptoCurrency:EC2/BitcoinTool.B | 8.0 | ✅ Yes |
| Backdoor:EC2/C&CActivity.B | 8.0 | ✅ Yes |
| Trojan:EC2/BlackholeTraffic | 8.0 | ✅ Yes |

---

## Setup — Step by Step

### Prerequisites
- AWS account (free tier is enough)
- AWS CLI configured (`aws configure`)
- Python 3.10+

### Step 1 — Clone and install

```bash
git clone https://github.com/vedakumarakh/guardduty-automated-response.git
cd guardduty-automated-response
pip install boto3
```

### Step 2 — Run setup script (phase by phase)

```bash
chmod +x setup.sh
bash setup.sh
```

The script will:
1. Enable GuardDuty
2. Create SNS topic + email subscription
3. Create quarantine security group (no rules)
4. Create Lambda IAM role with least-privilege policy
5. Deploy Lambda function with environment variables
6. Create EventBridge rule pointing to Lambda
7. Generate sample findings to test end-to-end

### Step 3 — Confirm email subscription

Check your inbox for an AWS SNS confirmation email and click **Confirm subscription**.

### Step 4 — Test

```bash
# Run unit tests
python -m pytest tests/test_lambda.py -v

# Invoke Lambda manually with sample finding
aws lambda invoke \
  --function-name guardduty-auto-response \
  --payload file://tests/sample-finding-high-severity.json \
  response.json \
  --region us-east-1

cat response.json
```

### Step 5 — Watch the logs

```bash
aws logs tail /aws/lambda/guardduty-auto-response --follow --region us-east-1
```

---

## Sample Alert Email

```
============================================================
  🔴 GUARDDUTY SECURITY ALERT — HIGH
============================================================

  Time        : 2026-01-15 12:00:00 UTC
  Finding     : UnauthorizedAccess:EC2/SSHBruteForce
  Severity    : 7.8/10  (HIGH)
  Region      : us-east-1
  Account     : 123456789012

  DESCRIPTION
  --------------------------------------------------------
  EC2 instance i-0abc1234567890def is performing SSH brute
  force attacks against 203.0.113.10.

  AFFECTED RESOURCE
  --------------------------------------------------------
  Resource Type : Instance
  Instance ID   : i-0abc1234567890def
  Private IP    : 10.0.1.25

  AUTOMATED RESPONSE
  --------------------------------------------------------
  ✅ EC2 ISOLATED — instance moved to quarantine SG
  Quarantine SG : sg-0quarantine123
  Previous SGs  : sg-0web456
  Isolated at   : 2026-01-15T12:00:05+00:00

  ⚠️  ACTION REQUIRED: Investigate instance immediately.
============================================================
```

---

## Environment Variables (Lambda)

| Variable | Description | Example |
|---|---|---|
| `SNS_TOPIC_ARN` | SNS topic for email alerts | `arn:aws:sns:us-east-1:123:guardduty-alerts` |
| `ISOLATION_SG_ID` | Quarantine security group ID | `sg-0abc123isolation` |
| `AUTO_ISOLATE_THRESHOLD` | Min severity to trigger isolation | `7.0` |

---

## AWS Cost

| Service | Usage | Cost |
|---|---|---|
| GuardDuty | 30-day free trial | $0 |
| Lambda | 1M requests/month free | $0 |
| SNS | 1000 emails/month free | $0 |
| EventBridge | 1M events/month free | $0 |
| CloudWatch Logs | 5GB free | $0 |
| **Total** | | **~$0** |

> Disable GuardDuty after testing: `bash cleanup.sh`

---

## Skills Demonstrated

- AWS GuardDuty — threat detection and finding types
- AWS Lambda — serverless Python function with IAM role
- AWS EventBridge — event-driven architecture, event patterns
- AWS SNS — pub/sub notification system
- AWS EC2 Security Groups — programmatic network isolation
- Python (boto3) — AWS SDK for automated cloud operations
- IAM — least-privilege role design
- Unit testing — unittest + mock for AWS services

---

## Author

**Vedakumara K H**
NOC System Engineer | Bharti Airtel
CCNA | CCNP | AWS Solutions Architect – Associate
📧 vedakumarakh@gmail.com
🔗 [GitHub](https://github.com/vedakumarakh)
