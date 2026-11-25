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
scan, no more lookups in a region after its first throttle; DRY_RUN = log only).
Resolve / reopen (design §9.7, CONTRACT §3.2, task #35): a problem seen again on a `resolved` finding reopens it
(new firstSeenAt; timeline types start the next generation with reason "reopen"). After every detection rule, the
region's not-resolved findings (one Scan per invocation, grouped by region) are resolved only on positive evidence
that the problem is gone; missing or uncertain evidence leaves them unchanged (counted "unknown"). A region whose
scan raised never gets that far, so nothing in it is resolved. Resolve / reopen change only finding records, so they
are not gated by DRY_RUN.
Emails (design §10.1 / §10.2, CONTRACT §4.8, task #36): after every detection rule and before the resolve pass, the
region sends REPORT_NOTICE / MISSING_TAGS / MISSING_TAGS_GROUPED through the Notify Lambda, once per episode (a
finding created or reopened in this scan, or Auto Scaling report-only newly applied), only for in-scope resources,
never retried, at most MAX_NOTICES_PER_REGION per region and MAX_NOTICES_PER_SCAN per invocation; a region stops
sending after its first Notify error. DRY_RUN does not suppress them (CONTRACT §4.1).
Cost estimates come from the internal price table (pricing.py, #21).
"""

import json
import re
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from common import audit, idle, timeline
from scanner import attachments, clients, config, creator, findings, notices, pricing

TIMELINE_TYPES = ("EC2_IDLE", "EBS_UNATTACHED")
# REPORT_NOTICE reason per report-only finding type (CONTRACT §4.2); timeline types use "autoscaling" only.
EIP_REPORT_REASONS = {"EIP_UNASSOCIATED": "eip_unassociated", "EIP_ON_STOPPED_INSTANCE": "eip_on_stopped_instance"}
ASG_TAG = "aws:autoscaling:groupName"
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
    if ASG_TAG in tags:
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
        self.resolution = Counter()  # resolved / reopened / unknown / skipped / error (task #35)
        self.recorded = set()  # (resourceId, findingType) seen as a problem on this scan: never resolved
        self.ec2_signals = {}  # instanceId -> (signals, classification), from _scan_instances (resolve pass)
        # Emails (task #36). Only findings of this scan's episode are queued; _send_notices sends them.
        self.notices = Counter()  # sent / error / skipped_* / suppressed_covered / ..._creator_found / ..._protected
        self.report_queue = []  # [_Notice] REPORT_NOTICE candidates
        self.tag_queue = []  # [_TagCandidate] new / reopened MISSING_TAGS findings
        self.copy_keys = {}  # resourceId -> keys copied (real) or that would be copied (dry-run) from its instance
        self.copy_failed = {}  # resourceId -> keys whose real copy failed on this scan
        self.lookup_found = set()  # resource IDs whose creator lookup returned found (fresh or cached, any mode)

    def attrs(self, resource_id, resource_type, tags):
        """The scanner attributes of a resource for this scan (CONTRACT §3.1)."""
        attrs = _base_attrs(resource_type, self.region, tags)
        if resource_id in self.owner_copied and attrs["owner"]:
            attrs["ownerSource"] = "copied"
        elif resource_id in self.owner_cloudtrail and attrs["owner"]:
            attrs["ownerSource"] = "cloudtrail"
        return attrs

    def record(self, resource_id, finding_type, attrs, report_only=None, tags=None, attached_to=None):
        """Upsert one finding seen on this scan. `tags`: the resource's tags (emails: dev scope, Auto Scaling group);
        `attached_to`: MISSING_TAGS only, the instance of an in-use volume / instance-associated Elastic IP."""
        is_new, item = findings.upsert(resource_id, finding_type, attrs, self.now_iso)
        self.counts[finding_type] += 1
        self.recorded.add((resource_id, finding_type))
        start_reason = "new"
        episode = is_new  # created or reopened on this scan: the only time an email is queued (CONTRACT §4.8)
        if is_new:
            # CONTRACT §3.3: a newly created finding (any type).
            audit.write_audit(resource_id, "scanner", "finding_opened", finding_type=finding_type,
                              region=self.region,
                              details={k: attrs[k] for k in ("estimatedMonthlyCost", "missingTags")
                                       if attrs.get(k) is not None})
        elif item.get("status") == "resolved":
            item = self._reopen(item)
            if item is None:
                return None  # lost race or error: left as it is, counted and logged
            start_reason = "reopen"
            episode = True
        tags = tags or {}
        if finding_type in TIMELINE_TYPES:
            before = item.get("reportOnlyReason")
            item = self._apply_report_only(item, report_only)
            if item.get("reportOnlyReason") == "autoscaling" and (episode or before != "autoscaling"):
                self.report_queue.append(_Notice(item, attrs, tags, "autoscaling"))
            self._maybe_start(item, start_reason)
        elif episode and finding_type in EIP_REPORT_REASONS:
            # EIP findings have no reportOnlyReason: a protected Elastic IP is checked here (CONTRACT §4.8).
            if _report_only_reason(tags) == "protected":
                self.notices["suppressed_protected"] += 1
                findings.log(resource_id, finding_type, "notify", "suppressed_protected", region=self.region,
                             template="REPORT_NOTICE")
            else:
                self.report_queue.append(_Notice(item, attrs, tags, EIP_REPORT_REASONS[finding_type]))
        elif episode and finding_type == "MISSING_TAGS":
            self.tag_queue.append(_TagCandidate(item, attrs, tags, attached_to))
        return item

    def _reopen(self, item):
        """CONTRACT §3.2 reopen of a `resolved` finding whose problem is back. Returns the reopened finding, or None
        (lost race: not an error; DynamoDB error: counted "error")."""
        rid, ftype = item["resourceId"], item["findingType"]
        previous = item.get("resolvedAt")
        try:
            reopened = findings.reopen(rid, ftype, self.now_iso)
        except Exception as err:  # one bad finding must not stop the scan
            self.resolution["error"] += 1
            findings.log(rid, ftype, "reopen_finding", "error", error=f"{type(err).__name__}: {err}"[:300])
            return None
        if reopened is None:
            self.resolution["skipped"] += 1
            findings.log(rid, ftype, "reopen_finding", "skipped: status changed", region=self.region)
            return None
        self.resolution["reopened"] += 1
        findings.log(rid, ftype, "reopen_finding", "reopened", region=self.region, previousResolvedAt=previous)
        audit.write_audit(rid, "scanner", "finding_reopened", finding_type=ftype, region=self.region,
                          generation=reopened.get("generation"), result="ok",
                          details={"previousResolvedAt": previous})
        return reopened

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
            else:  # remediated: unchanged (a resolved finding was reopened before this, so it is open here)
                self.report_only["unchanged"] += 1
                findings.log(rid, ftype, "report_only", "unchanged", status=status, reportOnlyReason=reason)
        elif not reason and current and status == "open":
            # Tag removed: back to normal; the timeline starts on this same scan (_maybe_start).
            if findings.clear_report_only(rid, ftype):
                self.report_only["cleared"] += 1
                return {k: v for k, v in item.items() if k != "reportOnlyReason"}
        return item

    def _maybe_start(self, item, reason="new"):
        """Start the timeline of an `open` finding (reason "new", or "reopen" right after a reopen), restart a
        `failed` one, or retry a pending start."""
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
            out = timeline.start_timeline(rid, ftype, reason if status == "open" else "new")
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

    def missing_tags(self, resource_id, resource_type, tags, attrs, attached_to=None):
        missing = [t for t in REQUIRED_TAGS if not tags.get(t, "").strip()]
        if missing:
            self.record(resource_id, "MISSING_TAGS", dict(attrs, missingTags=missing), tags=tags,
                        attached_to=attached_to)


class _Notice:
    """A REPORT_NOTICE candidate: the finding (after the write), this scan's attributes, the resource's tags."""

    def __init__(self, item, attrs, tags, reason):
        self.item, self.attrs, self.tags, self.reason = item, attrs, tags, reason


class _TagCandidate:
    """A MISSING_TAGS finding created or reopened on this scan."""

    def __init__(self, item, attrs, tags, attached_to):
        self.item, self.attrs, self.tags, self.attached_to = item, attrs, tags, attached_to
        self.resource_id = item["resourceId"]
        self.resource_type = attrs["resourceType"]
        self.missing = list(attrs["missingTags"])


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
        scan.ec2_signals[iid] = (signals, classification)  # the resolve pass reuses them (no second fetch)
        findings.log(iid, "EC2_IDLE", "classify", classification or "active", **signals)
        if classification != "idle":
            continue
        scan.record(iid, "EC2_IDLE", dict(attrs, classification="idle",
                                          estimatedMonthlyCost=pricing.estimate("ec2", scan.region, inst)),
                    report_only=_report_only_reason(tags), tags=tags)


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
        scan.missing_tags(vid, "ebs", tags, attrs, attached_to=_attached_instance_id(vol))
        if vol["State"] == "available":
            scan.record(vid, "EBS_UNATTACHED",
                        dict(attrs, estimatedMonthlyCost=pricing.estimate("ebs", scan.region, vol),
                             estimatedSnapshotMonthlyCost=pricing.estimate_snapshot(
                                 scan.region, vol.get("Size"), resource_id=vid)),
                        report_only=_report_only_reason(tags), tags=tags)


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
        scan.missing_tags(aid, "eip", tags, attrs, attached_to=_eip_instance_id(addr))
        cost = pricing.estimate("eip", scan.region, addr)
        if not addr.get("AssociationId"):
            scan.record(aid, "EIP_UNASSOCIATED", dict(attrs, estimatedMonthlyCost=cost), tags=tags)
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
            scan.record(aid, "EIP_ON_STOPPED_INSTANCE", dict(attrs, estimatedMonthlyCost=cost), tags=tags)


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


def _eip_instance_id(address):
    """The instance an Elastic IP is associated with (None: unassociated, or on a NAT gateway / network interface)."""
    if not address.get("AssociationId"):
        return None
    return address.get("InstanceId") or None


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
        scan.copy_keys[resource_id] = set(to_copy)  # emails: covered, the next real scan copies them (#36)
        scan.tag_copy["would_copy"] += 1
        findings.log(resource_id, "*", "copy_tags", "dry-run: would copy", tags=to_copy, fromInstance=instance_id)
        return
    try:
        ec2.create_tags(Resources=[resource_id], Tags=[{"Key": k, "Value": v} for k, v in to_copy.items()])
    except Exception as err:  # keep the tags unchanged; the missing-tag check reports them
        error = f"{type(err).__name__}: {err}"[:300]
        scan.copy_failed[resource_id] = set(to_copy)  # emails: not covered (design §10.2 "tag copy fails")
        scan.tag_copy["error"] += 1
        findings.log(resource_id, "*", "copy_tags", "error", tags=to_copy, fromInstance=instance_id, error=error)
        audit.write_audit(resource_id, "scanner", "tags_copied", region=scan.region, dry_run=False,
                          result="error", details={"error": error})
        return
    kept = [t for t in resource.get("Tags") or [] if t["Key"] not in to_copy]  # drops blank values being replaced
    resource["Tags"] = kept + [{"Key": k, "Value": v} for k, v in to_copy.items()]
    scan.copy_keys[resource_id] = set(to_copy)
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
        scan.lookup_found.add(resource_id)
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
    scan.lookup_found.add(resource_id)
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


# ---------------------------------------------------------------- emails (design §10.1 / §10.2, CONTRACT §4.8, #36)


class _Message:
    """One Notify call: its input (CONTRACT §4.1) and the tags of every resource it is about (dev scope check)."""

    def __init__(self, template, to, items, vars_, tags, label):
        self.payload = {"template": template, "to": to or None,
                        "findings": [notices.finding_ref(i) for i in items], "vars": vars_}
        self.template = template
        self.tags = tags
        self.label = label  # resourceId for the log line (the instance for a grouped email)
        self.resource_ids = [i["resourceId"] for i in items]


def _report_message(scan, notice):
    item, attrs = notice.item, notice.attrs
    cost = item.get("estimatedMonthlyCost", attrs.get("estimatedMonthlyCost"))
    vars_ = {"resourceId": item["resourceId"], "resourceType": attrs["resourceType"], "region": scan.region,
             "findingType": item["findingType"], "estimatedMonthlyCost": cost, "reason": notice.reason}
    if attrs.get("name"):
        vars_["name"] = attrs["name"]
    if notice.reason == "autoscaling" and notice.tags.get(ASG_TAG):
        vars_["autoScalingGroup"] = notice.tags[ASG_TAG]
    return _Message("REPORT_NOTICE", attrs.get("owner"), [item], vars_, [notice.tags], item["resourceId"])


def _covered_by_instance(scan, cand, by_id):
    """design §10.2 "resource untagged, its instance tagged": every missing key is (or will be, next scan) copied
    from the instance. Not covered when the real copy of that key failed on this scan."""
    inst = by_id.get(cand.attached_to)
    inst_tags = _tags(inst) if inst else {}
    copied = scan.copy_keys.get(cand.resource_id, set())
    failed = scan.copy_failed.get(cand.resource_id, set())
    for key in cand.missing:
        if key in copied:
            continue  # dry-run "would copy" (a real copy leaves no missing key)
        if key in failed:
            return False
        if not _blank(inst_tags, key):
            continue  # the instance got it after the copy step (owner from CloudTrail): copied next scan
        if key == "owner" and cand.attached_to in scan.lookup_found:
            continue  # the instance's creator is known (dry-run: not written)
        return False
    return True


def _tag_verdict(scan, cand, by_id):
    """"covered" | "creator_found" | "email" for a new / reopened MISSING_TAGS finding (design §10.2)."""
    if cand.attached_to and _covered_by_instance(scan, cand, by_id):
        return "covered"
    if "owner" in cand.missing and cand.resource_id in scan.lookup_found:
        return "creator_found"
    return "email"


def _single_tag_message(scan, cand):
    vars_ = {"resourceId": cand.resource_id, "resourceType": cand.resource_type, "region": scan.region,
             "missingTags": cand.missing}
    return _Message("MISSING_TAGS", cand.attrs.get("owner"), [cand.item], vars_, [cand.tags], cand.resource_id)


def _tag_messages(scan, by_id):
    """MISSING_TAGS / MISSING_TAGS_GROUPED for the region's emailable findings. Counts the suppressed ones."""
    emailable = []
    for cand in scan.tag_queue:
        verdict = _tag_verdict(scan, cand, by_id)
        if verdict == "email":
            emailable.append(cand)
            continue
        result = "suppressed_" + verdict
        scan.notices[result] += 1
        findings.log(cand.resource_id, "MISSING_TAGS", "notify", result, region=scan.region,
                     missingTags=cand.missing, instanceId=cand.attached_to)
    instances = {c.resource_id for c in emailable if c.resource_type == "ec2"}
    groups = defaultdict(list)  # instanceId -> its attached resources' candidates
    for cand in emailable:
        if cand.resource_type != "ec2" and cand.attached_to in instances:
            groups[cand.attached_to].append(cand)
    out = []
    for cand in emailable:
        if cand.resource_type == "ec2" and cand.resource_id in groups:
            members = groups[cand.resource_id]
            vars_ = {"instanceId": cand.resource_id, "region": scan.region,
                     "resources": [{"resourceId": m.resource_id, "resourceType": m.resource_type,
                                    "missingTags": m.missing} for m in members]}
            out.append(_Message("MISSING_TAGS_GROUPED", None, [cand.item] + [m.item for m in members], vars_,
                                [cand.tags] + [m.tags for m in members], cand.resource_id))
        elif cand.resource_type != "ec2" and cand.attached_to in groups:
            continue  # in its instance's grouped email
        else:
            out.append(_single_tag_message(scan, cand))
    return out


def _add_creator_lookup(message):
    """MISSING_TAGS: the `unknown` reason of the resource's creator-lookups record, as text (CONTRACT §4.2)."""
    rid = message.payload["vars"]["resourceId"]
    try:
        text = notices.creator_lookup_text(creator.get_record(rid))
    except Exception as err:  # the email goes without it
        findings.log(rid, "MISSING_TAGS", "creator_lookup_text", "error", error=f"{type(err).__name__}: {err}"[:300])
        return
    if text:
        message.payload["vars"]["creatorLookup"] = text


def _send_one(scan, message, state):
    """Send one email unless a cap or an earlier error in this region stops it. Returns the result counted."""
    if state["failed"]:
        return "skipped_error", None
    if state["attempts"] >= config.MAX_NOTICES_PER_REGION or not state["budget"].take():
        return "skipped_cap", None
    state["attempts"] += 1
    try:
        if state["client"] is None:
            # Notify lives in us-west-2 whatever region is scanned; this thread's session, no automatic retry.
            state["client"] = clients.notify_client(config.DEFAULT_REGION)
        if message.template == "MISSING_TAGS":
            _add_creator_lookup(message)
        out = notices.invoke(state["client"], config.notify_function_name(), message.payload)
    except Exception as err:  # counted and logged; never retried, nothing more is sent in this region
        state["failed"] = True
        return "error", f"{type(err).__name__}: {err}"[:300]
    return "sent", out


def _send_notices(scan, instances, scope, budget):
    """Send this region's queued emails through Notify. Never raises."""
    try:
        by_id = {i["InstanceId"]: i for i in instances}
        messages = [_report_message(scan, n) for n in scan.report_queue] + _tag_messages(scan, by_id)
        # CONTRACT §6: never email about a resource outside DEV_SCOPE (detection already skips them).
        messages = [m for m in messages if all(_in_scope(t, scope) for t in m.tags)]
        state = {"failed": False, "attempts": 0, "budget": budget, "client": None}
        for message in messages:
            result, detail = _send_one(scan, message, state)
            scan.notices[result] += 1
            extra = {}
            if result == "error":
                extra["error"] = detail
            elif result == "sent":
                extra = {k: detail.get(k) for k in ("recipient", "fallback", "messageId") if k in detail}
            findings.log(message.label, message.payload["findings"][0]["findingType"], "notify", result,
                         region=scan.region, template=message.template, resourceIds=message.resource_ids, **extra)
    except Exception as err:  # a bug here must never stop the scan or the resolve pass
        scan.notices["error"] += 1
        findings.log(scan.region, "*", "notify", "error", region=scan.region,
                     error=f"{type(err).__name__}: {err}"[:300])


# ---------------------------------------------------------------- resolve (design §9.7, CONTRACT §3.2, #35)

GONE, STILL, UNKNOWN = "gone", "still", "unknown"
ACTIVE_STATUSES = ("open", "in_progress", "failed")
SNAPSHOT_NOT_FOUND = "InvalidSnapshot.NotFound"


def _parse_iso(value):
    try:
        return datetime.strptime(value or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


class _Seen:
    """The region's FULL describe results (in-scope or not), after tag copying / creator lookup, for the verdicts."""

    def __init__(self, scan, ec2, instances, volumes, addresses, scope):
        self.scan = scan
        self.ec2 = ec2
        self.scope = scope
        self.instances = {i["InstanceId"]: i for i in instances}  # terminated / shutting-down are left out
        self.volumes = {v["VolumeId"]: v for v in volumes}
        self.by_allocation = {a["AllocationId"]: a for a in addresses if a.get("AllocationId")}
        self.by_ip = {a["PublicIp"]: a for a in addresses if a.get("PublicIp")}
        self.window_start = scan.now - timedelta(minutes=config.detection_window_minutes())

    def address(self, resource_id):
        """Like the finding key: AllocationId, else PublicIp."""
        return self.by_allocation.get(resource_id) or self.by_ip.get(resource_id)

    def out_of_scope(self, resource):
        return not _in_scope(_tags(resource), self.scope)


def _ec2_verdict(seen, item):
    """EC2_IDLE. Remediated: only (a) a real restart after remediatedAt or (b) terminated / missing."""
    inst = seen.instances.get(item["resourceId"])
    if inst is None:
        return GONE, "terminated"  # missing applies regardless of scope (the finding is in this stack's table)
    if seen.out_of_scope(inst):
        return UNKNOWN, "out_of_scope"
    state = inst["State"]["Name"]
    if item.get("status") == "remediated":
        remediated_at = _parse_iso(item.get("remediatedAt"))  # absent / unreadable: rule (a) never applies
        if state == "running" and remediated_at is not None and inst["LaunchTime"] > remediated_at:
            return GONE, "restarted"
        return STILL, None  # e.g. a dry-run "stop": LaunchTime unchanged, so it stays remediated (no loop)
    if state == "pending":
        return UNKNOWN, "pending"
    if state != "running":
        return GONE, "stopped"
    if inst["LaunchTime"] > seen.window_start:
        return GONE, "restarted"
    signals, classification = seen.scan.ec2_signals.get(inst["InstanceId"], (None, None))
    if signals is None or signals.get("cpuAvg") is None:
        return UNKNOWN, "no_cpu_data"  # classify() returns None for busy AND no data: check cpuAvg ourselves
    if classification != "idle":
        return GONE, "not_idle"  # underused, periodic or busy
    return STILL, None


def _ebs_verdict(seen, item):
    vol = seen.volumes.get(item["resourceId"])
    if vol is None:
        return GONE, "resource_gone"
    if seen.out_of_scope(vol):
        return UNKNOWN, "out_of_scope"
    if vol.get("State") == "in-use":
        return GONE, "attached"
    if vol.get("State") == "available":
        return STILL, None
    return UNKNOWN, "volume_state_" + str(vol.get("State"))


def _eip_unassociated_verdict(seen, item):
    addr = seen.address(item["resourceId"])
    if addr is None:
        return GONE, "resource_gone"
    if seen.out_of_scope(addr):
        return UNKNOWN, "out_of_scope"
    if addr.get("AssociationId"):
        return GONE, "associated"
    return STILL, None


def _eip_on_stopped_verdict(seen, item):
    addr = seen.address(item["resourceId"])
    if addr is None:
        return GONE, "resource_gone"
    if seen.out_of_scope(addr):
        return UNKNOWN, "out_of_scope"
    if not addr.get("AssociationId") or not addr.get("InstanceId"):
        return GONE, "associated"  # no longer on an instance (unassociated, or on a network interface)
    inst = seen.instances.get(addr["InstanceId"])
    if inst is None:
        return GONE, "terminated"
    state = inst["State"]["Name"]
    if state == "running":
        return GONE, "restarted"
    if state != "stopped":
        return UNKNOWN, "instance_state_" + state
    if _stop_time(inst) is None:
        return UNKNOWN, "stop_time_unknown"
    return STILL, None


def _missing_tags_verdict(seen, item):
    rtype = item.get("resourceType")
    if rtype == "ec2":
        resource = seen.instances.get(item["resourceId"])
    elif rtype == "ebs":
        resource = seen.volumes.get(item["resourceId"])
    elif rtype == "eip":
        resource = seen.address(item["resourceId"])
    else:
        return UNKNOWN, "resource_type_" + str(rtype)
    if resource is None:
        return GONE, "resource_gone"
    if seen.out_of_scope(resource):
        return UNKNOWN, "out_of_scope"
    tags = _tags(resource)  # after tag copying / creator lookup (a dry-run changes nothing in memory)
    if all(not _blank(tags, k) for k in REQUIRED_TAGS):
        return GONE, "tags_present"
    return STILL, None


def _snapshot_verdict(seen, item):
    try:
        seen.ec2.describe_snapshots(SnapshotIds=[item["resourceId"]])
    except Exception as err:
        code = getattr(err, "response", {}).get("Error", {}).get("Code")
        if code == SNAPSHOT_NOT_FOUND:
            return GONE, "snapshot_gone"
        return UNKNOWN, "describe_error: " + (code or type(err).__name__)  # never resolve on errors
    return STILL, None


VERDICTS = {
    "EC2_IDLE": _ec2_verdict,
    "EBS_UNATTACHED": _ebs_verdict,
    "EIP_UNASSOCIATED": _eip_unassociated_verdict,
    "EIP_ON_STOPPED_INSTANCE": _eip_on_stopped_verdict,
    "MISSING_TAGS": _missing_tags_verdict,
    "SNAPSHOT_REMINDER": _snapshot_verdict,
}


def _verdict(seen, item):
    """(GONE | STILL | UNKNOWN, reason) for a finding, or None if this status / type is never resolved."""
    status, ftype = item.get("status"), item.get("findingType")
    if status not in ACTIVE_STATUSES and not (status == "remediated" and ftype == "EC2_IDLE"):
        return None  # remediated EBS (deleted on purpose) and every other remediated type: never touched
    if ftype not in VERDICTS:
        return UNKNOWN, "finding_type_" + str(ftype)
    if status == "in_progress" and item.get("timelineStep") == "acting":
        return UNKNOWN, "acting"  # the workflow is stopping / deleting right now: let it set remediated
    return VERDICTS[ftype](seen, item)


def _resolve_one(scan, seen, item, reason):
    rid, ftype, seen_status = item["resourceId"], item["findingType"], item["status"]
    counts = scan.resolution
    fresh = findings.get_finding(rid, ftype)  # re-read right before acting
    if fresh is None or fresh.get("status") != seen_status:
        counts["skipped"] += 1
        findings.log(rid, ftype, "resolve_finding", "skipped: status changed", region=scan.region,
                     seenStatus=seen_status, status=(fresh or {}).get("status"))
        return
    if ftype != "SNAPSHOT_REMINDER":  # in-memory verdicts are free: confirm on the fresh item
        verdict, reason = _verdict(seen, fresh) or (STILL, None)
        if verdict != GONE:
            if verdict == UNKNOWN:
                counts["unknown"] += 1
            findings.log(rid, ftype, "resolve_finding", verdict, region=scan.region, reason=reason)
            return
    if ftype in TIMELINE_TYPES and seen_status in ACTIVE_STATUSES:
        timeline.stop_timeline(rid, ftype, "resolved")  # stops a running execution, sets resolvedAt, audits
    elif not findings.resolve(rid, ftype, seen_status, scan.now_iso):
        counts["skipped"] += 1
        findings.log(rid, ftype, "resolve_finding", "skipped: status changed", region=scan.region,
                     seenStatus=seen_status)
        return
    counts["resolved"] += 1
    findings.log(rid, ftype, "resolve_finding", "resolved", region=scan.region, reason=reason,
                 previousStatus=seen_status)
    audit.write_audit(rid, "scanner", "finding_resolved", finding_type=ftype, region=scan.region,
                      generation=fresh.get("generation"), result="ok",
                      details={"reason": reason, "previousStatus": seen_status})


def _resolve_pass(scan, seen, active):
    """Resolve this region's not-resolved findings whose problem is gone. Never raises: one finding's failure is
    counted "error" and logged, and the rest go on."""
    for item in active:
        rid, ftype = item.get("resourceId"), item.get("findingType")
        if (rid, ftype) in scan.recorded:
            continue  # seen as a problem on this scan
        try:
            out = _verdict(seen, item)
            if out is None:
                continue
            verdict, reason = out
            if verdict == UNKNOWN:
                scan.resolution["unknown"] += 1
                findings.log(rid, ftype, "resolve_finding", "unknown", region=scan.region, reason=reason,
                             status=item.get("status"))
            elif verdict == GONE:
                _resolve_one(scan, seen, item, reason)
        except Exception as err:
            scan.resolution["error"] += 1
            findings.log(rid, ftype, "resolve_finding", "error", region=scan.region,
                         error=f"{type(err).__name__}: {err}"[:300])


def _load_active():
    """(the not-resolved findings grouped by region, how many the Scan loaded), or (None, None) if the Scan failed
    (logged; nothing is resolved)."""
    try:
        items = findings.list_active()
    except Exception as err:
        findings.log("*", "*", "list_findings", "error", error=f"{type(err).__name__}: {err}"[:300])
        return None, None
    by_region = defaultdict(list)
    for item in items:
        if not item.get("region"):
            findings.log(item.get("resourceId"), item.get("findingType"), "resolve_finding",
                         "skipped: no region", status=item.get("status"))
            continue
        by_region[item["region"]].append(item)
    return by_region, len(items)


def scan_region(region, now=None, active=None, budget=None):
    """Run every detection rule in one region, send its emails, then the resolve pass. Returns its summary.

    `active`: this region's not-resolved findings (the handler loads them once per invocation); None = load them
    here (direct callers, tests). `budget`: the invocation's email budget shared by every region; None = a fresh
    one (direct callers, tests)."""
    scan = _Scan(region, now or datetime.now(timezone.utc))
    scope = config.dev_scope()
    if budget is None:
        budget = notices.Budget(config.MAX_NOTICES_PER_SCAN)
    if active is None:
        by_region, _ = _load_active()
        if by_region is None:
            scan.resolution["error"] += 1
            active = []  # no resolve pass; detection and reopen still run
        else:
            active = by_region.get(region, [])
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
    # Only a region whose detection finished gets here: an exception above loses its queued emails (never retried).
    _send_notices(scan, instances, scope, budget)
    # Last: only a region whose detection finished gets here (an exception above skips it).
    _resolve_pass(scan, _Seen(scan, ec2, instances, volumes, addresses, scope), active)

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
        "resolution": dict(scan.resolution),
        "notices": dict(scan.notices),
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


def _timed_scan(region, now, active, budget, durations):
    """Worker thread: scan one region and record how long it took (also when it raises)."""
    started = time.monotonic()
    try:
        return scan_region(region, now=now, active=active, budget=budget)
    finally:
        durations[region] = time.monotonic() - started  # one key per thread: safe without a lock


def _collect(future):
    """Main thread: (summary, None) or (None, the exception scan_region raised)."""
    try:
        return future.result(), None
    except Exception as err:  # one bad region must never stop the others
        return None, err


def _merge(totals, summary):
    for key in ("findings", "timelines", "reportOnly", "tagCopy", "attachmentRecords", "creatorLookup",
                "resolution", "notices"):
        totals[key].update(summary.get(key) or {})
    totals["skippedOutOfScope"] += summary.get("skippedOutOfScope") or 0


def handler(event, context):
    started = time.monotonic()
    now = datetime.now(timezone.utc)  # one scan time for every region (firstSeenAt / lastSeenAt)
    clients.preload(config.DEFAULT_REGION)  # parse the service models once, before the threads (clients.py)
    regions, discovery = resolve_regions()
    workers = min(config.scan_max_workers(), len(regions))
    # The not-resolved findings, loaded once for every region (task #35). If the Scan fails, every region gets an
    # empty list: no resolve pass this invocation, detection and reopen still run.
    by_region, loaded = _load_active()
    print(json.dumps({"resourceId": "*", "findingType": "*", "action": "list_findings",
                      "result": "error" if by_region is None else "ok",
                      "active_findings_loaded": "error" if loaded is None else loaded}))
    # Emails: at most MAX_NOTICES_PER_SCAN for this invocation, all regions together (never kept across invocations).
    budget = notices.Budget(config.MAX_NOTICES_PER_SCAN)

    durations = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as pool:
        futures = {region: pool.submit(_timed_scan, region, now, (by_region or {}).get(region, []), budget,
                                       durations)
                   for region in regions}
        results = {region: _collect(future) for region, future in futures.items()}

    per_region, scanned, failed = {}, [], {}
    totals = {"findings": Counter(), "timelines": Counter(), "reportOnly": Counter(), "tagCopy": Counter(),
              "attachmentRecords": Counter(), "creatorLookup": Counter(), "resolution": Counter(),
              "notices": Counter(), "skippedOutOfScope": 0,
              "activeFindingsLoaded": "error" if loaded is None else loaded}
    if by_region is None:
        totals["resolution"]["error"] += 1
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
