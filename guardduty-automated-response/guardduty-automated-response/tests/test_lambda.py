#!/usr/bin/env python3
"""
================================================================
Unit Tests - GuardDuty Automated Response
================================================================
Author: Vedakumara K H
Run   : python -m pytest tests/ -v
================================================================
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../lambda"))

os.environ["SNS_TOPIC_ARN"]       = "arn:aws:sns:us-east-1:123456789012:guardduty-alerts"
os.environ["ISOLATION_SG_ID"]     = "sg-0abc12345isolation"
os.environ["AUTO_ISOLATE_THRESHOLD"] = "7.0"

from guardduty_response import (
    get_severity_label,
    extract_resource,
    build_alert_message,
    lambda_handler,
)


class TestSeverityLabel(unittest.TestCase):
    def test_low(self):
        label, icon = get_severity_label(2.0)
        self.assertEqual(label, "LOW")

    def test_medium(self):
        label, icon = get_severity_label(5.0)
        self.assertEqual(label, "MEDIUM")

    def test_high(self):
        label, icon = get_severity_label(7.5)
        self.assertEqual(label, "HIGH")

    def test_critical(self):
        label, icon = get_severity_label(9.0)
        self.assertEqual(label, "CRITICAL")


class TestExtractResource(unittest.TestCase):
    def test_ec2_instance(self):
        detail = {
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": "i-0abc123",
                    "imageId": "ami-0abc",
                    "networkInterfaces": [{"privateIpAddress": "10.0.1.5"}],
                    "tags": [{"key": "Name", "value": "web-server"}]
                }
            }
        }
        result = extract_resource(detail)
        self.assertEqual(result["instance_id"], "i-0abc123")
        self.assertEqual(result["ip"], "10.0.1.5")
        self.assertEqual(result["type"], "Instance")

    def test_iam_user(self):
        detail = {
            "resource": {
                "resourceType": "AccessKey",
                "accessKeyDetails": {
                    "userName": "test-user",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "userType": "IAMUser"
                }
            }
        }
        result = extract_resource(detail)
        self.assertEqual(result["iam_user"], "test-user")
        self.assertEqual(result["type"], "AccessKey")

    def test_empty_resource(self):
        result = extract_resource({})
        self.assertEqual(result["type"], "Unknown")
        self.assertIsNone(result["instance_id"])


class TestBuildAlertMessage(unittest.TestCase):
    def test_message_contains_finding_type(self):
        detail = {
            "type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "severity": 7.8,
            "region": "us-east-1",
            "accountId": "123456789012",
            "id": "abc-123",
            "description": "SSH brute force attack detected."
        }
        resource = {"type": "Instance", "instance_id": "i-0abc123", "iam_user": None, "ip": "10.0.1.5", "image_id": "ami-0abc", "tags": []}
        isolation_result = {"success": True, "isolation_sg": "sg-quarantine", "previous_sgs": ["sg-0web"], "timestamp": "2026-01-01T00:00:00+00:00", "attempted": True}

        msg = build_alert_message(detail, resource, isolation_result, "HIGH", "🔴")
        self.assertIn("UnauthorizedAccess:EC2/SSHBruteForce", msg)
        self.assertIn("EC2 ISOLATED", msg)
        self.assertIn("i-0abc123", msg)

    def test_message_no_isolation(self):
        detail = {
            "type": "Recon:EC2/PortProbeUnprotectedPort",
            "severity": 3.0,
            "region": "us-east-1",
            "accountId": "123456789012",
            "id": "xyz-456",
            "description": "Port probe detected."
        }
        resource = {"type": "Instance", "instance_id": None, "iam_user": None, "ip": None}
        isolation_result = {"attempted": False, "success": False}

        msg = build_alert_message(detail, resource, isolation_result, "LOW", "🟡")
        self.assertIn("Auto-isolation not triggered", msg)


class TestLambdaHandler(unittest.TestCase):
    @patch("guardduty_response.sns")
    @patch("guardduty_response.ec2")
    def test_high_severity_ec2_triggers_isolation(self, mock_ec2, mock_sns):
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "State": {"Name": "running"},
                    "SecurityGroups": [{"GroupId": "sg-0original"}]
                }]
            }]
        }
        mock_ec2.modify_instance_attribute.return_value = {}
        mock_sns.publish.return_value = {"MessageId": "test-123"}

        event = {
            "detail": {
                "type": "UnauthorizedAccess:EC2/SSHBruteForce",
                "severity": 7.8,
                "region": "us-east-1",
                "accountId": "123456789012",
                "id": "test-finding-001",
                "description": "SSH brute force attack.",
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {
                        "instanceId": "i-0test12345",
                        "imageId": "ami-0test",
                        "networkInterfaces": [{"privateIpAddress": "10.0.1.10"}],
                        "tags": []
                    }
                }
            }
        }

        result = lambda_handler(event, {})
        self.assertEqual(result["statusCode"], 200)
        body = json.loads(result["body"])
        self.assertTrue(body["isolated"])
        mock_ec2.modify_instance_attribute.assert_called_once()
        mock_sns.publish.assert_called_once()

    @patch("guardduty_response.sns")
    @patch("guardduty_response.ec2")
    def test_low_severity_no_isolation(self, mock_ec2, mock_sns):
        mock_sns.publish.return_value = {"MessageId": "test-456"}

        event = {
            "detail": {
                "type": "Recon:EC2/PortProbeUnprotectedPort",
                "severity": 3.0,
                "region": "us-east-1",
                "accountId": "123456789012",
                "id": "test-finding-002",
                "description": "Port probe.",
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {
                        "instanceId": "i-0low123",
                        "imageId": "ami-0low",
                        "networkInterfaces": [],
                        "tags": []
                    }
                }
            }
        }

        result = lambda_handler(event, {})
        self.assertEqual(result["statusCode"], 200)
        body = json.loads(result["body"])
        self.assertFalse(body["isolated"])
        mock_ec2.modify_instance_attribute.assert_not_called()

    @patch("guardduty_response.sns")
    def test_empty_event_returns_400(self, mock_sns):
        result = lambda_handler({}, {})
        self.assertEqual(result["statusCode"], 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
