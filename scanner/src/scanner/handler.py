"""Scanner Lambda (lane B, design §8): finds idle EC2, unattached EBS, unused Elastic IPs and missing tags.

Scans every region (design §8.1, task #22): SCAN_REGIONS = "all" → the account's enabled regions from
DescribeRegions (called in us-west-2; falls back to us-west-2 alone if that call fails), otherwise the listed
regions. Regions run in parallel threads (SCAN_MAX_WORKERS, default 8); `scan_region` is the per-region unit and
one failing region never stops the others. Each thread has its own boto3 session (scanner/clients.py), and every
client is bounded by timeouts and retries so one slow region can't eat the 5-minute timeout (design §17).
Before the detection rules, each region records volume attachments and copies missing owner / project tags from
instances to attached volumes and associated Elastic IPs (design §8.6, task #33; DRY_RUN = log only), so the
missing-tag check sees the copied tags. Then in-scope resources still without an owner get it from their creator in
CloudTrail (creator.py, task #34; results kept in creator-lookups, at most MAX_LOOKUPS_PER_REGION per region per
scan, no more lookups in a region after its first throttle; DRY_RUN = log only). Not yet here: resolve / reopen (#35), emails (#36).
Cost estimates come from the internal price table (pricing.py, #21).
"""

import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from common import audit, idle, timeline
from scanner import attachments, clients, config, creator, findings, pricing

TIMELINE_TYPES = ("EC2_IDLE", "EBS_UNATTACHED")
REQUIRED_TAGS = ("owner", "project")
COPIED_TAGS = ("owner", "project")  # the only keys ever copied from an instance (never Name, never guardian:*)
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
        self.tag_copy = Counter()
        self.attachment_records = Counter()
        self.creator_lookup = Counter()
        self.owner_copied = set()  # resource IDs whose owner tag was copied on this scan (ownerSource "copied")
        self.owner_cloudtrail = set()  # resource IDs whose owner tag was set from CloudTrail on this scan

    def attrs(self, resource_id, resource_type, tags):
        """The scanner attributes of a resource for this scan (CONTRACT §3.1)."""
        attrs = _base_attrs(resource_type, self.region, tags)
        if resource_id in self.owner_copied and attrs["owner"]:
            attrs["ownerSource"] = "copied"
        elif resource_id in self.owner_cloudtrail and attrs["owner"]:
            attrs["ownerSource"] = "cloudtrail"
        return attrs

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
        attrs = scan.attrs(iid, "ec2", tags)
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


def _all_volumes(ec2):
    out = []
    for page in ec2.get_paginator("describe_volumes").paginate():
        out.extend(page["Volumes"])
    return out


def _scan_volumes(scan, volumes, scope):
    for vol in volumes:
        tags = _tags(vol)
        if not _in_scope(tags, scope):
            scan.skipped += 1
            continue
        vid = vol["VolumeId"]
        attrs = scan.attrs(vid, "ebs", tags)
        scan.missing_tags(vid, "ebs", tags, attrs)
        if vol["State"] == "available":
            scan.record(vid, "EBS_UNATTACHED",
                        dict(attrs, estimatedMonthlyCost=pricing.estimate("ebs", scan.region, vol),
                             estimatedSnapshotMonthlyCost=pricing.estimate_snapshot(
                                 scan.region, vol.get("Size"), resource_id=vid)),
                        report_only=_report_only_reason(tags))


def _scan_addresses(scan, addresses, instances, scope):
    by_id = {i["InstanceId"]: i for i in instances}
    threshold = timedelta(hours=config.eip_stopped_threshold_hours())
    for addr in addresses:
        tags = _tags(addr)
        if not _in_scope(tags, scope):
            scan.skipped += 1
            continue
        aid = addr.get("AllocationId") or addr["PublicIp"]
        attrs = scan.attrs(aid, "eip", tags)
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


# ---------------------------------------------------------------- attachments and tag copying (design §8.6, #33)


def _attached_instance_id(volume):
    if volume.get("State") != "in-use":
        return None
    for attachment in volume.get("Attachments") or []:
        if attachment.get("InstanceId"):
            return attachment["InstanceId"]
    return None


def _record_attachments(scan, volumes, scope):
    """CONTRACT §3.5: one volume-attachments row per in-scope in-use volume, overwritten every scan."""
    for vol in volumes:
        iid = _attached_instance_id(vol)
        if iid is None or not _in_scope(_tags(vol), scope):
            continue
        try:
            attachments.put(vol["VolumeId"], iid, scan.region, scan.now_iso)
            scan.attachment_records["written"] += 1
        except Exception as err:  # never stops the scan
            scan.attachment_records["error"] += 1
            findings.log(vol["VolumeId"], "*", "volume_attachment", "error", instanceId=iid, error=str(err))


def _blank(tags, key):
    return not (tags.get(key) or "").strip()


def _copy_from_instance(scan, ec2, resource, resource_id, instance_id, by_id, dry_run):
    """Copy the owner / project tags the resource lacks from its instance. Updates resource["Tags"] in place
    only after a real, successful copy, so the detection rules that follow see what is really there."""
    tags = _tags(resource)
    lacking = [k for k in COPIED_TAGS if _blank(tags, k)]
    if not lacking:
        return
    inst = by_id.get(instance_id)
    if inst is None:
        scan.tag_copy["skipped"] += 1
        findings.log(resource_id, "*", "copy_tags", "skipped: instance not found", instanceId=instance_id,
                     missingTags=lacking)
        return
    inst_tags = _tags(inst)
    to_copy = {k: inst_tags[k] for k in lacking if not _blank(inst_tags, k)}  # value exactly as on the instance
    if not to_copy:
        return
    if dry_run:
        scan.tag_copy["would_copy"] += 1
        findings.log(resource_id, "*", "copy_tags", "dry-run: would copy", tags=to_copy, fromInstance=instance_id)
        return
    try:
        ec2.create_tags(Resources=[resource_id], Tags=[{"Key": k, "Value": v} for k, v in to_copy.items()])
    except Exception as err:  # keep the tags unchanged; the missing-tag check reports them
        error = f"{type(err).__name__}: {err}"[:300]
        scan.tag_copy["error"] += 1
        findings.log(resource_id, "*", "copy_tags", "error", tags=to_copy, fromInstance=instance_id, error=error)
        audit.write_audit(resource_id, "scanner", "tags_copied", region=scan.region, dry_run=False,
                          result="error", details={"error": error})
        return
    kept = [t for t in resource.get("Tags") or [] if t["Key"] not in to_copy]  # drops blank values being replaced
    resource["Tags"] = kept + [{"Key": k, "Value": v} for k, v in to_copy.items()]
    if "owner" in to_copy:
        scan.owner_copied.add(resource_id)
    scan.tag_copy["copied"] += 1
    findings.log(resource_id, "*", "copy_tags", "copied", tags=to_copy, fromInstance=instance_id)
    audit.write_audit(resource_id, "scanner", "tags_copied", region=scan.region, dry_run=False, result="ok",
                      details={"tags": to_copy, "fromInstance": instance_id})


def _copy_tags(scan, ec2, instances, volumes, addresses, scope):
    """design §8.6 step 1: attached volumes and associated Elastic IPs get missing owner / project tags from their
    instance. Only in-scope resources; DRY_RUN = log only (CONTRACT §6)."""
    by_id = {i["InstanceId"]: i for i in instances}
    dry_run = config.dry_run()
    for vol in volumes:
        iid = _attached_instance_id(vol)
        if iid is not None and _in_scope(_tags(vol), scope):
            _copy_from_instance(scan, ec2, vol, vol["VolumeId"], iid, by_id, dry_run)
    for addr in addresses:
        if not addr.get("AssociationId") or not _in_scope(_tags(addr), scope):
            continue  # unassociated: nothing to copy from
        tags = _tags(addr)
        if not addr.get("InstanceId") or not addr.get("AllocationId"):
            # NAT gateway / network interface (or an EC2-Classic address, which can't be tagged).
            if any(_blank(tags, k) for k in COPIED_TAGS):
                scan.tag_copy["skipped"] += 1
                findings.log(addr.get("AllocationId") or addr.get("PublicIp"), "*", "copy_tags",
                             "skipped: not associated with an instance",
                             networkInterfaceId=addr.get("NetworkInterfaceId"))
            continue
        _copy_from_instance(scan, ec2, addr, addr["AllocationId"], addr["InstanceId"], by_id, dry_run)


# ---------------------------------------------------------------- creator lookup (design §8.6 step 2, #34)


def _owner_candidates(instances, volumes, addresses, scope):
    """In-scope resources still without an owner after tag copying: (resourceType, id, resource)."""
    out = []
    for inst in instances:  # _all_instances already leaves out terminated / shutting-down
        if _in_scope(_tags(inst), scope) and _blank(_tags(inst), "owner"):
            out.append(("ec2", inst["InstanceId"], inst))
    for vol in volumes:  # in-use volumes: their instance is looked up, tag copying does the rest
        if vol.get("State") == "available" and _in_scope(_tags(vol), scope) and _blank(_tags(vol), "owner"):
            out.append(("ebs", vol["VolumeId"], vol))
    for addr in addresses:  # instance-associated EIPs get the owner by tag copying
        if not addr.get("AllocationId") or (addr.get("AssociationId") and addr.get("InstanceId")):
            continue
        if _in_scope(_tags(addr), scope) and _blank(_tags(addr), "owner"):
            out.append(("eip", addr["AllocationId"], addr))
    return out


def _young_unknown(record, now):
    try:
        looked_up = datetime.strptime(record.get("lookedUpAt", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False  # unreadable: look it up again
    return now - looked_up < timedelta(hours=config.UNKNOWN_RETRY_HOURS)


def _set_owner(scan, ec2, resource, resource_id, email, method, dry_run):
    """Tag the resource's owner from a `found` record. In-memory tags change only after a real, successful write."""
    if dry_run:
        scan.creator_lookup["would_set"] += 1
        findings.log(resource_id, "*", "set_owner", "dry-run: would set", owner=email, method=method)
        return
    try:
        ec2.create_tags(Resources=[resource_id], Tags=[{"Key": "owner", "Value": email}])
    except Exception as err:  # tags unchanged; the stored `found` record is used again next scan
        scan.creator_lookup["error"] += 1
        findings.log(resource_id, "*", "set_owner", "error", owner=email, method=method,
                     error=f"{type(err).__name__}: {err}"[:300])
        return
    kept = [t for t in resource.get("Tags") or [] if t["Key"] != "owner"]  # drops a blank owner value
    resource["Tags"] = kept + [{"Key": "owner", "Value": email}]
    scan.owner_cloudtrail.add(resource_id)
    scan.creator_lookup["set"] += 1
    findings.log(resource_id, "*", "set_owner", "set", owner=email, method=method)


def _lookup_owner(scan, ec2, lookup, resource_type, resource_id, resource, dry_run):
    counts = scan.creator_lookup
    record = creator.get_record(resource_id)
    if record and record.get("result") == "found" and record.get("email"):
        counts["cached"] += 1  # permanent: no CloudTrail call, no new owner_found
        _set_owner(scan, ec2, resource, resource_id, record["email"], record.get("method"), dry_run)
        return
    if record and record.get("result") == "unknown" and _young_unknown(record, scan.now):
        counts["cached"] += 1
        return
    if lookup.throttled:
        counts["skipped_throttle"] += 1  # no more CloudTrail / IAM calls in this region's scan
        return
    if lookup.resources >= config.MAX_LOOKUPS_PER_REGION:
        counts["skipped_cap"] += 1  # left for the next scan
        return
    try:
        result = lookup.find(resource_type, resource_id)
    except Exception as err:
        if not creator.is_throttle(err):
            raise
        lookup.throttled = True  # stop calling CloudTrail / IAM for the rest of this region's scan
        counts["throttled"] += 1  # not stored: the next scan retries
        findings.log(resource_id, "*", "creator_lookup", "throttled", error=f"{type(err).__name__}: {err}"[:300])
        return
    creator.put_record(dict(result, resourceId=resource_id, region=scan.region, lookedUpAt=scan.now_iso))
    if result["result"] != "found":
        counts["unknown"] += 1
        findings.log(resource_id, "*", "creator_lookup", "unknown: " + result["reason"], method=result["method"])
        return
    counts["found"] += 1
    findings.log(resource_id, "*", "creator_lookup", "found", method=result["method"])
    details = {k: result[k] for k in ("email", "method", "creatorArn") if result.get(k)}
    audit.write_audit(resource_id, "scanner", "owner_found", region=scan.region, dry_run=dry_run, result="ok",
                      details=details)
    _set_owner(scan, ec2, resource, resource_id, result["email"], result["method"], dry_run)


def _lookup_owners(scan, ec2, instances, volumes, addresses, scope):
    """design §8.6 step 2: owner from the creator in CloudTrail, for what tag copying could not fill. Never raises:
    one resource's failure is counted and logged, and the next resource goes on."""
    candidates = _owner_candidates(instances, volumes, addresses, scope)
    if not candidates:
        return
    lookup = creator.Lookup(scan.region)
    dry_run = config.dry_run()
    for resource_type, resource_id, resource in candidates:
        try:
            _lookup_owner(scan, ec2, lookup, resource_type, resource_id, resource, dry_run)
        except Exception as err:  # errors are never stored: the next scan retries
            scan.creator_lookup["error"] += 1
            findings.log(resource_id, "*", "creator_lookup", "error", error=f"{type(err).__name__}: {err}"[:300])


def scan_region(region, now=None):
    """Run every detection rule in one region. Returns that region's summary."""
    scan = _Scan(region, now or datetime.now(timezone.utc))
    scope = config.dev_scope()
    ec2 = clients.client("ec2", region)  # this thread's session (boto3 sessions are not thread-safe)
    cloudwatch = clients.client("cloudwatch", region)

    instances = _all_instances(ec2)
    volumes = _all_volumes(ec2)  # described once, used by every step below
    addresses = ec2.describe_addresses()["Addresses"]
    _record_attachments(scan, volumes, scope)
    _copy_tags(scan, ec2, instances, volumes, addresses, scope)  # before the rules: they must see copied tags
    _lookup_owners(scan, ec2, instances, volumes, addresses, scope)  # after copying: only what is still missing
    _scan_instances(scan, ec2, cloudwatch, instances, scope)
    _scan_volumes(scan, volumes, scope)
    _scan_addresses(scan, addresses, instances, scope)

    if scope:
        findings.log(region, "*", "dev_scope_filter", "skipped", skipped=scan.skipped, devScope=scope)
    return {
        "region": region,
        "findings": dict(scan.counts),
        "timelines": dict(scan.timelines),
        "skippedOutOfScope": scan.skipped,
        "reportOnly": dict(scan.report_only),
        "tagCopy": dict(scan.tag_copy),
        "attachmentRecords": dict(scan.attachment_records),
        "creatorLookup": dict(scan.creator_lookup),
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
    for key in ("findings", "timelines", "reportOnly", "tagCopy", "attachmentRecords", "creatorLookup"):
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
    totals = {"findings": Counter(), "timelines": Counter(), "reportOnly": Counter(), "tagCopy": Counter(),
              "attachmentRecords": Counter(), "creatorLookup": Counter(), "skippedOutOfScope": 0}
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
