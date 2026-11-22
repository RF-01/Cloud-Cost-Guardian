"""Scanner settings: detection thresholds (initial values, design §8.2 / §24) and environment readers."""

import os

# --- EC2 idle thresholds, per hour, scaled to the detection window -----------------------------------
CPU_AVG_PERCENT = 5.0  # CPU average below this is "low"
CPU_MAX_PERCENT = 20.0  # CPU maximum at or above this is a spike (periodic)
NETWORK_BYTES_PER_HOUR = 2 * 1024 * 1024  # NetworkIn + NetworkOut, 2 MB per hour
DISK_OPS_PER_HOUR = 100  # VolumeReadOps + VolumeWriteOps over all attached volumes

METRIC_PERIOD_SECONDS = 300  # basic monitoring granularity

DEFAULT_DETECTION_WINDOW_MINUTES = 30  # demo value; the real tool uses e.g. 1440
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
