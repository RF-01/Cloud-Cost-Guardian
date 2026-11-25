"""Writes <prefix>volume-attachments (CONTRACT §3.5, design §8.6, task #33).

One row per in-scope volume seen `in-use`: {volumeId, instanceId (first attachment), region, seenAt}. Overwritten
on every scan and never deleted, so an orphaned volume keeps the last instance it was attached to (the creator
lookup, #34, reads it with `get`).
"""

import os
import threading

from scanner import clients, config

_local = threading.local()  # per-thread Table resource (regions are scanned in parallel threads)


def table():
    """This thread's volume-attachments Table (boto3 resources are not thread-safe)."""
    local = _local
    if not hasattr(local, "table"):
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or config.DEFAULT_REGION
        local.table = clients.resource("dynamodb", region).Table(config.table_volume_attachments())
    return local.table


def reset_clients():
    global _local
    _local = threading.local()


def put(volume_id, instance_id, region, seen_at):
    table().put_item(Item={"volumeId": volume_id, "instanceId": instance_id, "region": region, "seenAt": seen_at})


def get(volume_id):
    """The row for a volume, or None (read by the creator lookup, #34)."""
    return table().get_item(Key={"volumeId": volume_id}).get("Item")
