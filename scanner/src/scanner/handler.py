"""Scanner Lambda (lane B, design §8): finds idle EC2, unattached EBS, unused Elastic IPs and missing tags.

Task #20: one region only (the first of SCAN_REGIONS; us-west-2 for "all"). `scan_region` is the unit that
task #22 loops over / parallelizes. Not yet here: tag copying (#33), CloudTrail lookup (#34),
resolve / reopen (#35), emails (#36). Cost estimates come from the internal price table (pricing.py, #21).
"""

import json
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import boto3

from common import idle, timeline
from scanner import config, findings, pricing

TIMELINE_TYPES = ("EC2_IDLE", "EBS_UNATTACHED")
REQUIRED_TAGS = ("owner", "project")
# "User initiated (2026-11-20 10:15:00 GMT)" (AWS); moto writes "UTC".
STOP_TIME = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?:GMT|UTC)\)")


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tags(resource):
    return {t["Key"]: t["Value"] for t in resource.get("Tags", []) or []}


def _in_scope(tags, scope):
    return not scope or tags.get("guardian:dev-scope") == scope


def _report_only_reason(tags):
    if tags.get("guardian:protect", "").strip().lower() == "true":
        return "protected"
    if "aws:autoscaling:groupName" in tags:
        return "autoscaling"
    return None


def _base_attrs(resource_type, region, tags):
    owner = tags.get("owner", "").strip().lower()
    return {
        "resourceType": resource_type,
        "region": region,
        "owner": owner or None,
        "ownerSource": "tag" if owner else "unknown",
        "project": tags.get("project", "").strip() or None,
        "name": tags.get("Name") or None,
    }


def _stop_time(instance):
    """When a stopped instance was stopped, from StateTransitionReason, or None if unparseable."""
    match = STOP_TIME.search(instance.get("StateTransitionReason") or "")
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- one region


class _Scan:
    """State of one region's scan: what was found and what to start."""

    def __init__(self, region, now):
        self.region = region
        self.now = now
        self.now_iso = _iso(now)
        self.counts = Counter()
        self.timelines = Counter()
        self.skipped = 0
        self.report_only = Counter()

    def record(self, resource_id, finding_type, attrs, report_only=None):
        is_new, item = findings.upsert(resource_id, finding_type, attrs, self.now_iso)
        self.counts[finding_type] += 1
        if finding_type in TIMELINE_TYPES:
            item = self._apply_report_only(item, report_only)
            self._maybe_start(item)
        return item

    def _apply_report_only(self, item, reason):
        """CONTRACT §3.2: report-only rules (tag found / tag removed). Returns the finding as it is now."""
        rid, ftype, status = item["resourceId"], item["findingType"], item.get("status")
        current = item.get("reportOnlyReason")
        if reason and current != reason:
            if status == "open":
                if findings.set_report_only(rid, ftype, reason):
                    self.report_only["set"] += 1
                    return dict(item, reportOnlyReason=reason)
            elif status in ("in_progress", "failed"):
                try:
                    updated = timeline.stop_timeline(rid, ftype, "open", reason)
                    self.report_only["stopped_timeline"] += 1
                    return updated
                except Exception as err:  # one bad finding must not stop the scan
                    self.report_only["error"] += 1
                    findings.log(rid, ftype, "report_only", "error", error=str(err))
            else:  # remediated (and resolved, handled by #35): unchanged
                self.report_only["unchanged"] += 1
                findings.log(rid, ftype, "report_only", "unchanged", status=status, reportOnlyReason=reason)
        elif not reason and current and status == "open":
            # Tag removed: back to normal; the timeline starts on this same scan (_maybe_start).
            if findings.clear_report_only(rid, ftype):
                self.report_only["cleared"] += 1
                return {k: v for k, v in item.items() if k != "reportOnlyReason"}
        return item

    def _maybe_start(self, item):
        if item.get("reportOnlyReason"):
            return
        status = item.get("status")
        pending = status == "in_progress" and item.get("executionName") and not item.get("executionArn")
        if status != "open" and not pending:
            return
        rid, ftype = item["resourceId"], item["findingType"]
        if not config.sfn_arn(ftype):
            self.timelines["skipped_no_state_machine"] += 1
            findings.log(rid, ftype, "start_timeline", "timeline skipped: no state machine")
            return
        try:
            out = timeline.start_timeline(rid, ftype, "new")
            self.timelines[out["result"]] += 1
        except Exception as err:  # one bad finding must not stop the scan
            self.timelines["error"] += 1
            findings.log(rid, ftype, "start_timeline", "error", error=str(err))

    def missing_tags(self, resource_id, resource_type, tags, attrs):
        missing = [t for t in REQUIRED_TAGS if not tags.get(t, "").strip()]
        if missing:
            self.record(resource_id, "MISSING_TAGS", dict(attrs, missingTags=missing))


def _all_instances(ec2):
    out = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page["Reservations"]:
            out.extend(reservation["Instances"])
    return [i for i in out if i["State"]["Name"] not in ("terminated", "shutting-down")]


def _scan_instances(scan, ec2, cloudwatch, instances, scope):
    window = config.detection_window_minutes()
    start = scan.now - timedelta(minutes=window)
    for inst in instances:
        tags = _tags(inst)
        if not _in_scope(tags, scope):
            scan.skipped += 1
            continue
        iid = inst["InstanceId"]
        attrs = _base_attrs("ec2", scan.region, tags)
        scan.missing_tags(iid, "ec2", tags, attrs)

        if inst["State"]["Name"] != "running" or inst["LaunchTime"] > start:
            continue  # stopped instances send no CPU data; too new to judge over the window
        volumes = [m["Ebs"]["VolumeId"] for m in inst.get("BlockDeviceMappings", []) if "Ebs" in m]
        signals = idle.instance_signals(cloudwatch, iid, volumes, start, scan.now)
        classification = idle.classify(signals, window)
        findings.log(iid, "EC2_IDLE", "classify", classification or "active", **signals)
        if classification != "idle":
            continue
        scan.record(iid, "EC2_IDLE", dict(attrs, classification="idle",
                                          estimatedMonthlyCost=pricing.estimate("ec2", scan.region, inst)),
                    report_only=_report_only_reason(tags))


def _scan_volumes(scan, ec2, scope):
    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page["Volumes"]:
            tags = _tags(vol)
            if not _in_scope(tags, scope):
                scan.skipped += 1
                continue
            vid = vol["VolumeId"]
            attrs = _base_attrs("ebs", scan.region, tags)
            scan.missing_tags(vid, "ebs", tags, attrs)
            if vol["State"] == "available":
                scan.record(vid, "EBS_UNATTACHED",
                            dict(attrs, estimatedMonthlyCost=pricing.estimate("ebs", scan.region, vol),
                                 estimatedSnapshotMonthlyCost=pricing.estimate_snapshot(
                                     scan.region, vol.get("Size"), resource_id=vid)),
                            report_only=_report_only_reason(tags))


def _scan_addresses(scan, ec2, instances, scope):
    by_id = {i["InstanceId"]: i for i in instances}
    threshold = timedelta(hours=config.eip_stopped_threshold_hours())
    for addr in ec2.describe_addresses()["Addresses"]:
        tags = _tags(addr)
        if not _in_scope(tags, scope):
            scan.skipped += 1
            continue
        aid = addr.get("AllocationId") or addr["PublicIp"]
        attrs = _base_attrs("eip", scan.region, tags)
        scan.missing_tags(aid, "eip", tags, attrs)
        cost = pricing.estimate("eip", scan.region, addr)
        if not addr.get("AssociationId"):
            scan.record(aid, "EIP_UNASSOCIATED", dict(attrs, estimatedMonthlyCost=cost))
            continue
        inst = by_id.get(addr.get("InstanceId"))
        if inst is None or inst["State"]["Name"] != "stopped":
            continue
        stopped_at = _stop_time(inst)
        if stopped_at is None:
            findings.log(aid, "EIP_ON_STOPPED_INSTANCE", "check", "skipped: stop time unknown",
                         instanceId=inst["InstanceId"], reason=inst.get("StateTransitionReason"))
            continue
        if scan.now - stopped_at > threshold:
            scan.record(aid, "EIP_ON_STOPPED_INSTANCE", dict(attrs, estimatedMonthlyCost=cost))


def scan_region(region, now=None):
    """Run every detection rule in one region. Returns that region's summary."""
    scan = _Scan(region, now or datetime.now(timezone.utc))
    scope = config.dev_scope()
    ec2 = boto3.client("ec2", region_name=region)
    cloudwatch = boto3.client("cloudwatch", region_name=region)

    instances = _all_instances(ec2)
    _scan_instances(scan, ec2, cloudwatch, instances, scope)
    _scan_volumes(scan, ec2, scope)
    _scan_addresses(scan, ec2, instances, scope)

    if scope:
        findings.log(region, "*", "dev_scope_filter", "skipped", skipped=scan.skipped, devScope=scope)
    return {
        "region": region,
        "findings": dict(scan.counts),
        "timelines": dict(scan.timelines),
        "skippedOutOfScope": scan.skipped,
        "reportOnly": dict(scan.report_only),
    }


def handler(event, context):
    started = time.monotonic()
    region = config.scan_regions()[0]  # task #22 scans all of them
    summary = scan_region(region)
    summary["durationSeconds"] = round(time.monotonic() - started, 3)
    print(json.dumps({"action": "scan", "result": "done", **summary}, default=str))
    return summary
