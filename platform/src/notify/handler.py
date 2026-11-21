"""Notify Lambda: STUB until task #24.

Logs the incoming event as one JSON line and returns {"sent": false, "stub": true}.
It never calls SES (the real templates, tokens and sending come in task #24, CONTRACT §4.1).
"""

import json


def handler(event, context):
    print(json.dumps({"action": "notify_stub", "result": "skipped", "event": event}, default=str))
    return {"sent": False, "stub": True}
