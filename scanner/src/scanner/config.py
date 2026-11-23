"""Scanner settings: environment readers (idle thresholds: common/idle.py, design §8.2 / §24)."""

import os

from common import idle

# EC2 idle thresholds and classify() live in common/idle.py (shared with the remediation re-check).
DEFAULT_DETECTION_WINDOW_MINUTES = idle.DEFAULT_DETECTION_WINDOW_MINUTES
DEFAULT_EIP_STOPPED_THRESHOLD_HOURS = 24
DEFAULT_REGION = "us-west-2"  # where the Guardian runs; DescribeRegions is called here, and the fallback region
DEFAULT_MAX_WORKERS = 8


def _int_env(name, default):
    value = os.environ.get(name, "").strip()
    return int(value) if value else default


def detection_window_minutes():
    return _int_env("DETECTION_WINDOW_MINUTES", DEFAULT_DETECTION_WINDOW_MINUTES)


def eip_stopped_threshold_hours():
    return _int_env("EIP_STOPPED_THRESHOLD_HOURS", DEFAULT_EIP_STOPPED_THRESHOLD_HOURS)


def scan_regions():
    """SCAN_REGIONS (CONTRACT §6): "all" (the handler resolves it with DescribeRegions) or the listed regions."""
    raw = os.environ.get("SCAN_REGIONS", "all").strip()
    regions = [] if raw.lower() == "all" else list(dict.fromkeys(r.strip() for r in raw.split(",") if r.strip()))
    return regions or "all"


def scan_max_workers():
    """SCAN_MAX_WORKERS: most regions scanned at once (default 8, at least 1)."""
    return max(1, _int_env("SCAN_MAX_WORKERS", DEFAULT_MAX_WORKERS))


def dev_scope():
    return os.environ.get("DEV_SCOPE", "").strip()


def sfn_arn(finding_type):
    name = {"EC2_IDLE": "EC2_SFN_ARN", "EBS_UNATTACHED": "EBS_SFN_ARN"}[finding_type]
    return os.environ.get(name, "").strip()
