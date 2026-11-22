"""Scanner settings: environment readers (idle thresholds: common/idle.py, design §8.2 / §24)."""

import os

from common import idle

# EC2 idle thresholds and classify() live in common/idle.py (shared with the remediation re-check).
DEFAULT_DETECTION_WINDOW_MINUTES = idle.DEFAULT_DETECTION_WINDOW_MINUTES
DEFAULT_EIP_STOPPED_THRESHOLD_HOURS = 24
DEFAULT_REGION = "us-west-2"


def _int_env(name, default):
    value = os.environ.get(name, "").strip()
    return int(value) if value else default


def detection_window_minutes():
    return _int_env("DETECTION_WINDOW_MINUTES", DEFAULT_DETECTION_WINDOW_MINUTES)


def eip_stopped_threshold_hours():
    return _int_env("EIP_STOPPED_THRESHOLD_HOURS", DEFAULT_EIP_STOPPED_THRESHOLD_HOURS)


def scan_regions():
    """SCAN_REGIONS: "all" or a comma-separated list. Task #20 scans only the first one (#22 adds the rest)."""
    raw = os.environ.get("SCAN_REGIONS", "all").strip()
    if not raw or raw.lower() == "all":
        return [DEFAULT_REGION]
    return [r.strip() for r in raw.split(",") if r.strip()]


def dev_scope():
    return os.environ.get("DEV_SCOPE", "").strip()


def sfn_arn(finding_type):
    name = {"EC2_IDLE": "EC2_SFN_ARN", "EBS_UNATTACHED": "EBS_SFN_ARN"}[finding_type]
    return os.environ.get(name, "").strip()
