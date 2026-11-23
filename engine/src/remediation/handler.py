"""Remediation Lambda (lane A, CONTRACT §4.3, design §9.2 / §9.3 / §9.5). Called by the timeline workflows only.

Input: {"action": "<ACTION>", "resourceId": "...", "region": "...", "dryRun": true,
        "findingType": "...", "generation": N, ...}   (findingType / generation optional, for the audit entry)

    CHECK_EC2        -> {"stillIdle": bool, "protected": bool, "state": "running"}
    STOP_INSTANCE    -> {"stopped": bool, "dryRun": bool, "elasticIps": [...]}  (already stopped: false, false)
    CHECK_EBS        -> {"stillUnattached": bool, "protected": bool, "exists": bool}
    CREATE_SNAPSHOT  -> {"snapshotId": "snap-..." | null in dry-run, "dryRun": bool}
    SNAPSHOT_STATUS  -> {"state": "pending" | "completed" | "error"}      (input: snapshotId)
    DELETE_VOLUME    -> {"deleted": bool, "dryRun": bool}                (input: snapshotId)

Safety:
- Every call runs in the input's region and refuses (raises) on resources outside DEV_SCOPE.
- Dry-run if the input says so OR the DRY_RUN env var isn't "false": stop / snapshot / delete are logged only.
- Never stops or deletes anything tagged guardian:protect=true (IAM denies it too).
- DELETE_VOLUME refuses unless snapshotId is a completed snapshot tagged guardian:source-volume=<volume>.
- Errors raise so Step Functions retries; refusals raise RefusedError (the workflow doesn't retry those).
- One JSON log line per action. The only DynamoDB writes are audit entries (CONTRACT §3.3, actor
  "remediation"): instance_stopped (stopped or dry-run stop; not when someone else had already stopped it),
  snapshot_created (details.snapshotId, null in dry-run), volume_deleted. They never raise (common/audit.py).
  The findings table is updated by the workflow.

Environment: NAME_PREFIX, TABLE_FINDINGS, TABLE_AUDIT, DRY_RUN, DEV_SCOPE, DETECTION_WINDOW_MINUTES.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

from common import audit, idle

PROTECT_TAG = "guardian:protect"
SCOPE_TAG = "guardian:dev-scope"
SOURCE_VOLUME_TAG = "guardian:source-volume"
FINDING_TYPES = {"CHECK_EC2": "EC2_IDLE", "STOP_INSTANCE": "EC2_IDLE"}  # every other action is EBS


class RefusedError(Exception):
    """A safety rule refused the action. Not retried by the workflow (the answer won't change)."""


# ---------------------------------------------------------------- helpers


def _log(resource_id, action, result, **extra):
    record = {"resourceId": resource_id, "findingType": extra.pop("findingType", None), "action": action,
              "result": result}
    record.update(extra)
    print(json.dumps(record, default=str))


def _env_dry_run():
    # Safe default: anything other than an explicit "false" is a dry run.
    return os.environ.get("DRY_RUN", "true").strip().lower() != "false"


def _dry_run(event):
    return event.get("dryRun") is not False or _env_dry_run()


def _window_minutes():
    value = os.environ.get("DETECTION_WINDOW_MINUTES", "").strip()
    return int(value) if value else idle.DEFAULT_DETECTION_WINDOW_MINUTES


def _tags(resource):
    return {t["Key"]: t["Value"] for t in resource.get("Tags", []) or []}


def _protected(tags):
    return tags.get(PROTECT_TAG, "").strip().lower() == "true"


def _check_scope(resource_id, tags):
    scope = os.environ.get("DEV_SCOPE", "").strip()
    if scope and tags.get(SCOPE_TAG) != scope:
        raise RefusedError(f"{resource_id} is outside dev scope {scope!r} (tag {SCOPE_TAG}="
                           f"{tags.get(SCOPE_TAG)!r})")


def _code(err):
    return err.response.get("Error", {}).get("Code", "")


def _instance(ec2, instance_id):
    """The instance dict, or None if it doesn't exist."""
    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as err:
        if _code(err) == "InvalidInstanceID.NotFound":
            return None
        raise
    instances = [i for r in reservations for i in r["Instances"]]
    return instances[0] if instances else None


def _volume(ec2, volume_id):
    """The volume dict, or None if it doesn't exist."""
    try:
        volumes = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
    except ClientError as err:
        if _code(err) == "InvalidVolume.NotFound":
            return None
        raise
    return volumes[0] if volumes else None


def _snapshot(ec2, snapshot_id):
    try:
        snapshots = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"]
    except ClientError as err:
        if _code(err) == "InvalidSnapshot.NotFound":
            return None
        raise
    return snapshots[0] if snapshots else None


def _audit(event, name, default_finding_type, dry, details=None):
    """Audit entry for an action taken (or logged in dry-run). findingType / generation come from the input."""
    audit.write_audit(event["resourceId"], "remediation", name,
                      finding_type=event.get("findingType") or default_finding_type, region=event.get("region"),
                      generation=event.get("generation"), dry_run=dry, result="ok", details=details)


def _require(event, key):
    value = event.get(key)
    if not value:
        raise ValueError(f"{event.get('action')}: input needs {key!r}")
    return value


# ---------------------------------------------------------------- EC2


def check_ec2(event, ec2, cloudwatch, now):
    rid = event["resourceId"]
    inst = _instance(ec2, rid)
    if inst is None:
        _log(rid, "CHECK_EC2", "not_found", findingType="EC2_IDLE")
        return {"stillIdle": False, "protected": False, "state": "not_found"}
    tags = _tags(inst)
    _check_scope(rid, tags)
    state = inst["State"]["Name"]
    protected = _protected(tags)
    still_idle = False
    extra = {}
    if state == "running":
        window = _window_minutes()
        start = now - timedelta(minutes=window)
        if inst["LaunchTime"] > start:
            extra["reason"] = "started within the detection window"  # restarted: activity, not idle
        else:
            volumes = [m["Ebs"]["VolumeId"] for m in inst.get("BlockDeviceMappings", []) if "Ebs" in m]
            signals = idle.instance_signals(cloudwatch, rid, volumes, start, now)
            classification = idle.classify(signals, window)
            still_idle = classification == "idle"
            extra.update(signals, classification=classification or "active", windowMinutes=window)
    _log(rid, "CHECK_EC2", "idle" if still_idle else "not_idle", findingType="EC2_IDLE", state=state,
         protected=protected, **extra)
    return {"stillIdle": still_idle, "protected": protected, "state": state}


def stop_instance(event, ec2):
    rid = event["resourceId"]
    dry = _dry_run(event)
    inst = _instance(ec2, rid)
    if inst is None:
        raise RefusedError(f"{rid} not found")
    tags = _tags(inst)
    _check_scope(rid, tags)
    if _protected(tags):
        raise RefusedError(f"{rid} is tagged {PROTECT_TAG}=true")
    elastic_ips = [a["PublicIp"] for a in ec2.describe_addresses(
        Filters=[{"Name": "instance-id", "Values": [rid]}])["Addresses"]]
    state = inst["State"]["Name"]
    if state in ("stopped", "stopping"):
        # Someone else stopped it: nothing done or simulated, so dryRun is false even in dry-run (CONTRACT §4.3);
        # the workflow resolves the finding instead of counting a Guardian saving.
        _log(rid, "STOP_INSTANCE", "already_stopped", findingType="EC2_IDLE", state=state, dryRun=False)
        return {"stopped": False, "dryRun": False, "elasticIps": elastic_ips}
    if state != "running":
        raise RefusedError(f"{rid} is {state}, not running")
    if dry:
        _log(rid, "STOP_INSTANCE", "dry_run", findingType="EC2_IDLE", dryRun=True, elasticIps=elastic_ips)
        _audit(event, "instance_stopped", "EC2_IDLE", True, {"elasticIps": elastic_ips})
        return {"stopped": False, "dryRun": True, "elasticIps": elastic_ips}
    ec2.stop_instances(InstanceIds=[rid])  # graceful: no Force, OS shutdown not skipped (design §9.2)
    _log(rid, "STOP_INSTANCE", "stopped", findingType="EC2_IDLE", dryRun=False, elasticIps=elastic_ips)
    _audit(event, "instance_stopped", "EC2_IDLE", False, {"elasticIps": elastic_ips})
    return {"stopped": True, "dryRun": False, "elasticIps": elastic_ips}


# ---------------------------------------------------------------- EBS


def check_ebs(event, ec2):
    rid = event["resourceId"]
    vol = _volume(ec2, rid)
    if vol is None:
        _log(rid, "CHECK_EBS", "not_found", findingType="EBS_UNATTACHED")
        return {"stillUnattached": False, "protected": False, "exists": False}
    tags = _tags(vol)
    _check_scope(rid, tags)
    unattached = vol["State"] == "available"
    protected = _protected(tags)
    _log(rid, "CHECK_EBS", "unattached" if unattached else "attached", findingType="EBS_UNATTACHED",
         state=vol["State"], protected=protected)
    return {"stillUnattached": unattached, "protected": protected, "exists": True}


def create_snapshot(event, ec2):
    rid = event["resourceId"]
    dry = _dry_run(event)
    vol = _volume(ec2, rid)
    if vol is None:
        raise RefusedError(f"{rid} not found")
    tags = _tags(vol)
    _check_scope(rid, tags)
    if _protected(tags):
        raise RefusedError(f"{rid} is tagged {PROTECT_TAG}=true")
    if dry:
        _log(rid, "CREATE_SNAPSHOT", "dry_run", findingType="EBS_UNATTACHED", dryRun=True)
        _audit(event, "snapshot_created", "EBS_UNATTACHED", True, {"snapshotId": None})
        return {"snapshotId": None, "dryRun": True}
    # Copy the volume's tags (aws:* keys are reserved and can't be set) + the source-volume tag, at creation.
    snap_tags = [{"Key": k, "Value": v} for k, v in tags.items()
                 if not k.startswith("aws:") and k != SOURCE_VOLUME_TAG]
    snap_tags.append({"Key": SOURCE_VOLUME_TAG, "Value": rid})
    snap = ec2.create_snapshot(
        VolumeId=rid,
        Description=f"cost-guardian: snapshot of {rid} before deleting it",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": snap_tags}],
    )
    _log(rid, "CREATE_SNAPSHOT", "created", findingType="EBS_UNATTACHED", dryRun=False,
         snapshotId=snap["SnapshotId"])
    _audit(event, "snapshot_created", "EBS_UNATTACHED", False, {"snapshotId": snap["SnapshotId"]})
    return {"snapshotId": snap["SnapshotId"], "dryRun": False}


def _our_snapshot(ec2, rid, snapshot_id):
    """The snapshot, checked to be in scope and tagged for this volume. Raises otherwise."""
    snap = _snapshot(ec2, snapshot_id)
    if snap is None:
        raise RefusedError(f"snapshot {snapshot_id} not found")
    tags = _tags(snap)
    _check_scope(snapshot_id, tags)
    if tags.get(SOURCE_VOLUME_TAG) != rid:
        raise RefusedError(f"snapshot {snapshot_id} is not tagged {SOURCE_VOLUME_TAG}={rid}")
    return snap


def snapshot_status(event, ec2):
    rid = event["resourceId"]
    snapshot_id = _require(event, "snapshotId")
    state = _our_snapshot(ec2, rid, snapshot_id)["State"]
    _log(rid, "SNAPSHOT_STATUS", state, findingType="EBS_UNATTACHED", snapshotId=snapshot_id)
    return {"state": state}


def delete_volume(event, ec2):
    rid = event["resourceId"]
    dry = _dry_run(event)
    vol = _volume(ec2, rid)
    if vol is None:
        raise RefusedError(f"{rid} not found")
    tags = _tags(vol)
    _check_scope(rid, tags)
    if _protected(tags):
        raise RefusedError(f"{rid} is tagged {PROTECT_TAG}=true")
    if dry:
        _log(rid, "DELETE_VOLUME", "dry_run", findingType="EBS_UNATTACHED", dryRun=True,
             snapshotId=event.get("snapshotId"))
        _audit(event, "volume_deleted", "EBS_UNATTACHED", True, {"snapshotId": event.get("snapshotId")})
        return {"deleted": False, "dryRun": True}
    snapshot_id = _require(event, "snapshotId")
    snap = _our_snapshot(ec2, rid, snapshot_id)
    if snap["State"] != "completed":
        raise RefusedError(f"snapshot {snapshot_id} is {snap['State']}, not completed")
    if vol["State"] != "available":
        raise RefusedError(f"{rid} is {vol['State']}, not available")
    ec2.delete_volume(VolumeId=rid)
    _log(rid, "DELETE_VOLUME", "deleted", findingType="EBS_UNATTACHED", dryRun=False, snapshotId=snapshot_id)
    _audit(event, "volume_deleted", "EBS_UNATTACHED", False, {"snapshotId": snapshot_id})
    return {"deleted": True, "dryRun": False}


# ---------------------------------------------------------------- entry point


def handler(event, context, now=None):
    action = event.get("action")
    rid = _require(event, "resourceId")
    region = _require(event, "region")
    ec2 = boto3.client("ec2", region_name=region)
    try:
        if action == "CHECK_EC2":
            cloudwatch = boto3.client("cloudwatch", region_name=region)
            return check_ec2(event, ec2, cloudwatch, now or datetime.now(timezone.utc))
        if action == "STOP_INSTANCE":
            return stop_instance(event, ec2)
        if action == "CHECK_EBS":
            return check_ebs(event, ec2)
        if action == "CREATE_SNAPSHOT":
            return create_snapshot(event, ec2)
        if action == "SNAPSHOT_STATUS":
            return snapshot_status(event, ec2)
        if action == "DELETE_VOLUME":
            return delete_volume(event, ec2)
    except RefusedError as err:
        _log(rid, action, "refused", findingType=FINDING_TYPES.get(action, "EBS_UNATTACHED"), error=str(err),
             region=region)
        raise
    except Exception as err:
        _log(rid, action, "error", findingType=FINDING_TYPES.get(action, "EBS_UNATTACHED"), error=str(err),
             region=region)
        raise
    raise ValueError(f"unknown action {action!r}")
