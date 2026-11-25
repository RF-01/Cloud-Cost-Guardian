"""Scanner Lambda (lane B, design §8): finds idle EC2, unattached EBS, unused Elastic IPs and missing tags.

Scans every region (design §8.1, task #22): SCAN_REGIONS = "all" → the account's enabled regions from
DescribeRegions (called in us-west-2; falls back to us-west-2 alone if that call fails), otherwise the listed
regions. Regions run in parallel threads (SCAN_MAX_WORKERS, default 8); `scan_region` is the per-region unit and
one failing region never stops the others. Each thread has its own boto3 session (scanner/clients.py), and every
client is bounded by timeouts and retries so one slow region can't eat the 5-minute timeout (design §17).
Not yet here: tag copying (#33), CloudTrail lookup (#34), resolve / reopen (#35), emails (#36). Cost estimates
come from the internal price table (pricing.py, #21).
"""

import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from common import audit, idle, timeline
from scanner import clients, config, findings, pricing

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
        if is_new:
            # CONTRACT §3.3: a newly created finding (any type). Reopen / resolve are #35.
            audit.write_audit(resource_id, "scanner", "finding_opened", finding_type=finding_type,
                              region=self.region,
                              details={k: attrs[k] for k in ("estimatedMonthlyCost", "missingTags")
                                       if attrs.get(k) is not None})
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
        if status not in ("open", "failed") and not pending:
            return
        rid, ftype = item["resourceId"], item["findingType"]
        if not config.sfn_arn(ftype):
            self.timelines["skipped_no_state_machine"] += 1
            findings.log(rid, ftype, "start_timeline", "timeline skipped: no state machine")
            return
        if status == "failed":
            self._maybe_restart(item)
            return
        try:
            out = timeline.start_timeline(rid, ftype, "new")
            self.timelines[out["result"]] += 1
        except Exception as err:  # one bad finding must not stop the scan
            self.timelines["error"] += 1
            findings.log(rid, ftype, "start_timeline", "error", error=str(err))

    def _maybe_restart(self, item):
        """CONTRACT §3.2 failed → in_progress: the problem is still there on this scan, so restart the timeline
        while restartCount < MAX_RESTARTS. At the limit the finding stays failed and is only logged."""
        rid, ftype = item["resourceId"], item["findingType"]
        count = int(item.get("restartCount", 0))
        if count >= config.max_restarts():
            self.timelines["restart_limit"] += 1
            findings.log(rid, ftype, "restart_timeline", "limit", restartCount=count)
            return
        try:
            out = timeline.start_timeline(rid, ftype, "restart")
            self.timelines["restart_" + out["result"]] += 1
        except ValueError as err:  # e.g. the status changed since the upsert: not an error
            self.timelines["restart_refused"] += 1
            findings.log(rid, ftype, "restart_timeline", "refused", restartCount=count, error=str(err))
        except Exception as err:  # one bad finding must not stop the scan
            self.timelines["error"] += 1
            findings.log(rid, ftype, "restart_timeline", "error", error=str(err))

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
    ec2 = clients.client("ec2", region)  # this thread's session (boto3 sessions are not thread-safe)
    cloudwatch = clients.client("cloudwatch", region)

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


# ---------------------------------------------------------------- all regions


def resolve_regions():
    """(regions, discovery) for this run. discovery says how the list was obtained, for the summary."""
    configured = config.scan_regions()
    if configured != "all":
        return configured, {"mode": "list"}
    try:
        response = clients.client("ec2", config.DEFAULT_REGION).describe_regions()  # enabled regions only
        regions = sorted(r["RegionName"] for r in response["Regions"])
        if not regions:
            raise RuntimeError("DescribeRegions returned no regions")
        return regions, {"mode": "all"}
    except Exception as err:
        error = f"{type(err).__name__}: {err}"
        print(json.dumps({"resourceId": "*", "findingType": "*", "action": "describe_regions",
                          "result": "error: falling back to " + config.DEFAULT_REGION, "error": error}))
        return [config.DEFAULT_REGION], {"mode": "all", "fallback": config.DEFAULT_REGION, "error": error}


def _timed_scan(region, now, durations):
    """Worker thread: scan one region and record how long it took (also when it raises)."""
    started = time.monotonic()
    try:
        return scan_region(region, now=now)
    finally:
        durations[region] = time.monotonic() - started  # one key per thread: safe without a lock


def _collect(future):
    """Main thread: (summary, None) or (None, the exception scan_region raised)."""
    try:
        return future.result(), None
    except Exception as err:  # one bad region must never stop the others
        return None, err


def _merge(totals, summary):
    for key in ("findings", "timelines", "reportOnly"):
        totals[key].update(summary.get(key) or {})
    totals["skippedOutOfScope"] += summary.get("skippedOutOfScope") or 0


def handler(event, context):
    started = time.monotonic()
    now = datetime.now(timezone.utc)  # one scan time for every region (firstSeenAt / lastSeenAt)
    clients.preload(config.DEFAULT_REGION)  # parse the service models once, before the threads (clients.py)
    regions, discovery = resolve_regions()
    workers = min(config.scan_max_workers(), len(regions))

    durations = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as pool:
        futures = {region: pool.submit(_timed_scan, region, now, durations) for region in regions}
        results = {region: _collect(future) for region, future in futures.items()}

    per_region, scanned, failed = {}, [], {}
    totals = {"findings": Counter(), "timelines": Counter(), "reportOnly": Counter(), "skippedOutOfScope": 0}
    for region in regions:
        (summary, err), seconds = results[region], durations.get(region, 0.0)
        if err is None:
            scanned.append(region)
            per_region[region] = dict(summary, status="ok", durationSeconds=round(seconds, 3))
            _merge(totals, summary)
        else:
            error = f"{type(err).__name__}: {err}"
            failed[region] = error
            per_region[region] = {"region": region, "status": "error", "error": error,
                                  "durationSeconds": round(seconds, 3)}
            print(json.dumps({"resourceId": region, "findingType": "*", "action": "scan_region", "result": "error",
                              "region": region, "errorType": type(err).__name__, "message": str(err)}))

    # Note for #35 (resolve / reopen): resolve rules must only apply to regions in regionsScanned. A region in
    # regionsFailed was not seen this run, so its findings must never be resolved because they are "missing".
    slowest = max(regions, key=lambda r: durations.get(r, 0.0))
    out = {
        "regionsScanned": scanned,
        "regionsFailed": failed,
        "regionDiscovery": discovery,
        "maxWorkers": workers,
        "regions": per_region,
        "totals": {k: dict(v) if isinstance(v, Counter) else v for k, v in totals.items()},
        "durationSeconds": round(time.monotonic() - started, 3),
        "slowestRegion": {"region": slowest, "durationSeconds": round(durations.get(slowest, 0.0), 3)},
    }
    print(json.dumps({"resourceId": "*", "findingType": "*", "action": "scan",
                      "result": "failed" if not scanned else "done", **out}, default=str))
    if not scanned:
        raise RuntimeError(f"scan failed in every region: {failed}")
    return out
