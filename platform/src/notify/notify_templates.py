"""Notify email templates (CONTRACT §4.2): input validation and rendering to subject, HTML and text.

Stdlib only. Every value interpolated into the HTML goes through html.escape: tag values such as `name` are
untrusted text. The subject is a plain-text header, so it is not escaped; clean_subject strips CR/LF instead.
"""

import html
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

# R variables per template (CONTRACT §4.2). O variables are read with .get().
_TIMELINE_VARS = ("resourceId", "resourceType", "region", "estimatedMonthlyCost", "deadlineAt",
                  "plannedAction", "dryRun")
REQUIRED_VARS = {
    "FIRST_NOTICE": _TIMELINE_VARS,
    "FINAL_WARNING": _TIMELINE_VARS,
    "STOP_CONFIRMATION": ("resourceId", "region", "realizedMonthlySavings", "dryRun", "elasticIps"),
    "DELETE_CONFIRMATION": ("resourceId", "region", "sizeGb", "snapshotId", "realizedMonthlySavings", "dryRun"),
    "WORKFLOW_FAILED": ("resourceId", "region", "findingType", "failedStep", "errorMessage", "progress"),
    "REPORT_NOTICE": ("resourceId", "resourceType", "region", "findingType", "estimatedMonthlyCost", "reason"),
    "MISSING_TAGS": ("resourceId", "resourceType", "region", "missingTags"),
    "MISSING_TAGS_GROUPED": ("instanceId", "region", "resources"),
    "RESTORE_DONE": ("sourceVolumeId", "snapshotId", "newVolumeId", "availabilityZone", "region"),
    "DIGEST": ("findings", "protected", "snapshots", "budgetAlerts", "missingTags"),
}
TEMPLATES = frozenset(REQUIRED_VARS)

# Prices come in task #21, so money values may be null for now.
MONEY_VARS = frozenset({"estimatedMonthlyCost", "realizedMonthlySavings", "monthlyCost"})
LIST_VARS = frozenset({"elasticIps", "missingTags", "resources", "findings", "protected", "snapshots",
                       "budgetAlerts"})

ACTIONS = frozenset({"protect", "postpone", "restore"})
ALLOWED_ACTIONS = {
    "FIRST_NOTICE": frozenset({"protect", "postpone"}),
    "FINAL_WARNING": frozenset({"protect", "postpone"}),
    "DIGEST": frozenset({"protect", "postpone"}),
    "DELETE_CONFIRMATION": frozenset({"restore"}),  # and only when vars.dryRun is false
}
# Which findings each action may point to (CONTRACT §3.4, §4.1).
ACTION_FINDING_TYPES = {
    "protect": frozenset({"EC2_IDLE", "EBS_UNATTACHED"}),
    "postpone": frozenset({"EC2_IDLE", "EBS_UNATTACHED"}),
    "restore": frozenset({"EBS_UNATTACHED"}),
}
PLANNED_ACTIONS = frozenset({"stop", "snapshot_and_delete"})
REPORT_REASONS = frozenset({"eip_unassociated", "eip_on_stopped_instance", "autoscaling"})

ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SUBJECT_MAX = 150
NOT_ESTIMATED = "not estimated yet"


# ---------------------------------------------------------------- validation

def parse_iso(value):
    """CONTRACT §2 time (`2026-11-20T16:30:00Z`) -> aware datetime. ValueError otherwise."""
    if not isinstance(value, str) or not ISO_RE.match(value):
        raise ValueError(f"not an ISO 8601 UTC time (YYYY-MM-DDTHH:MM:SSZ): {value!r}")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _is_number(value):
    return isinstance(value, (int, float, Decimal)) and not isinstance(value, bool)


def validate(event):
    """Check the Notify input (CONTRACT §4.1, §4.2). Returns (template, findings, vars). Raises ValueError."""
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    template = event.get("template")
    if template not in TEMPLATES:
        raise ValueError(f"unknown template: {template!r}")

    vars_ = event.get("vars")
    if not isinstance(vars_, dict):
        raise ValueError("vars must be an object")
    vars_ = _normalize_vars(template, vars_)
    _validate_vars(template, vars_)

    findings = event.get("findings")
    if findings is None:
        findings = []
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    if not findings and template != "DIGEST":
        raise ValueError(f"{template} needs at least one finding")
    clean = [_validate_finding(template, vars_, f) for f in findings]
    keys = [finding_key(f) for f in clean]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate finding in findings")
    return template, clean, vars_


def _normalize_vars(template, vars_):
    """JSONata in the workflow may drop an empty list or unwrap a one-item list (CONTRACT §4.2)."""
    if template != "STOP_CONFIRMATION":
        return vars_
    vars_ = dict(vars_)  # never change the caller's event
    ips = vars_.get("elasticIps")
    if ips is None:
        vars_["elasticIps"] = []
    elif isinstance(ips, str):
        vars_["elasticIps"] = [ips]
    elif not isinstance(ips, list):
        raise ValueError("STOP_CONFIRMATION: 'elasticIps' must be a list, a string or null")
    return vars_


def _validate_vars(template, vars_):
    dry_run = vars_.get("dryRun")
    if "dryRun" in vars_ and not isinstance(dry_run, bool):
        raise ValueError("vars.dryRun must be a boolean")
    for name in REQUIRED_VARS[template]:
        if name not in vars_:
            raise ValueError(f"{template}: missing required variable {name!r}")
        value = vars_[name]
        if value is None:
            if name in MONEY_VARS:
                continue
            # A dry-run CREATE_SNAPSHOT returns snapshotId null (CONTRACT §4.3).
            if template == "DELETE_CONFIRMATION" and name == "snapshotId" and dry_run is True:
                continue
            raise ValueError(f"{template}: required variable {name!r} is null")
        if name in MONEY_VARS and not _is_number(value):
            raise ValueError(f"{template}: {name!r} must be a number or null")
        if name in LIST_VARS and not isinstance(value, list):
            raise ValueError(f"{template}: {name!r} must be a list")
    if template in ("FIRST_NOTICE", "FINAL_WARNING"):
        if vars_["plannedAction"] not in PLANNED_ACTIONS:
            raise ValueError(f"plannedAction must be one of {sorted(PLANNED_ACTIONS)}")
        parse_iso(vars_["deadlineAt"])
    if template == "REPORT_NOTICE" and vars_["reason"] not in REPORT_REASONS:
        raise ValueError(f"reason must be one of {sorted(REPORT_REASONS)}")
    for name in LIST_VARS & set(REQUIRED_VARS[template]):
        if name in ("elasticIps", "missingTags") and template != "DIGEST":
            continue  # lists of strings
        if any(not isinstance(item, dict) for item in vars_[name]):
            raise ValueError(f"{template}: every item of {name!r} must be an object")


def _validate_finding(template, vars_, finding):
    if not isinstance(finding, dict):
        raise ValueError("every finding must be an object")
    for name in ("resourceId", "findingType"):
        if not isinstance(finding.get(name), str) or not finding[name]:
            raise ValueError(f"finding.{name} must be a non-empty string")
    generation = finding.get("generation")
    if not isinstance(generation, int) or isinstance(generation, bool):
        raise ValueError(f"finding.generation must be an integer, got {generation!r}")
    actions = finding.get("actions") or []
    if not isinstance(actions, list):
        raise ValueError("finding.actions must be a list")
    if len(set(actions)) != len(actions):
        raise ValueError("finding.actions has duplicates")
    allowed = ALLOWED_ACTIONS.get(template, frozenset())
    for action in actions:
        if action not in ACTIONS:
            raise ValueError(f"unknown action: {action!r}")
        if action not in allowed:
            raise ValueError(f"action {action!r} is not allowed in {template}")
        if action == "restore" and vars_.get("dryRun") is not False:
            raise ValueError("restore links only on a non-dry-run DELETE_CONFIRMATION")
        if finding["findingType"] not in ACTION_FINDING_TYPES[action]:
            raise ValueError(f"action {action!r} not allowed on {finding['findingType']}")
    expires_at = finding.get("expiresAt")
    if actions:
        parse_iso(expires_at)  # required when actions is non-empty
    return {"resourceId": finding["resourceId"], "findingType": finding["findingType"],
            "generation": generation, "actions": list(actions), "expiresAt": expires_at}


def finding_key(finding):
    """CONTRACT §2 finding key: `<resourceId>#<findingType>`."""
    return f"{finding['resourceId']}#{finding['findingType']}"


# ---------------------------------------------------------------- formatting

def fmt_time(value):
    """`2026-11-23T16:30:00Z` -> `Nov 23, 2026 16:30 UTC` (raw text if it doesn't parse)."""
    try:
        dt = parse_iso(value)
    except ValueError:
        return str(value)
    return f"{dt:%b} {dt.day}, {dt:%Y %H:%M} UTC"


def fmt_money(value, per_month=True):
    if value is None:
        return NOT_ESTIMATED
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return str(value)
    return f"${amount:,.2f}" + ("/month" if per_month else "")


RESOURCE_LABELS = {"ec2": "EC2 instance", "ebs": "EBS volume", "eip": "Elastic IP", "snapshot": "snapshot"}
ACTION_LABELS = {"protect": "Protect (keep it)", "postpone": "Postpone the deadline",
                 "restore": "Restore from snapshot"}


def _label(resource_type):
    return RESOURCE_LABELS.get(resource_type, str(resource_type))


def _short(value, limit=80):
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _named(resource_id, name):
    return f"{resource_id} ({_short(name)})" if name else str(resource_id)


class _Body:
    """A list of blocks, rendered once to HTML (escaped) and once to plain text."""

    def __init__(self):
        self.blocks = []

    def h(self, text):
        self.blocks.append(("h", text))

    def h3(self, text):
        self.blocks.append(("h3", text))

    def p(self, text):
        self.blocks.append(("p", text))

    def note(self, text):
        self.blocks.append(("note", text))

    def facts(self, rows):
        rows = [(label, value) for label, value in rows if value not in (None, "")]
        if rows:
            self.blocks.append(("facts", rows))

    def bullets(self, items):
        if items:
            self.blocks.append(("bullets", list(items)))

    def buttons(self, links, expires_at=None):
        """links: {action: url} for one finding."""
        if links:
            ordered = [(ACTION_LABELS[a], links[a]) for a in ("protect", "postpone", "restore") if a in links]
            self.blocks.append(("buttons", (ordered, expires_at)))


_E = lambda value: html.escape(str(value), quote=True)  # noqa: E731

_STYLE = {
    "h": "margin:0 0 12px;font-size:18px;color:#1a1a1a;",
    "h3": "margin:18px 0 6px;font-size:15px;color:#1a1a1a;",
    "p": "margin:0 0 12px;",
    "note": "margin:0 0 12px;padding:8px 12px;background:#fff4ce;border-left:4px solid #e0a800;",
    "td_l": "padding:3px 12px 3px 0;color:#555;vertical-align:top;white-space:nowrap;",
    "td_v": "padding:3px 0;vertical-align:top;",
    "btn": ("display:inline-block;margin:0 8px 8px 0;padding:10px 16px;background:#1a5fb4;color:#ffffff;"
            "text-decoration:none;border-radius:4px;font-weight:bold;"),
    "small": "margin:0 0 12px;font-size:12px;color:#666;",
}


def _html(blocks, footer):
    out = []
    for kind, data in blocks:
        if kind in ("h", "h3"):
            tag = "h2" if kind == "h" else "h3"
            out.append(f'<{tag} style="{_STYLE[kind]}">{_E(data)}</{tag}>')
        elif kind in ("p", "note"):
            out.append(f'<p style="{_STYLE[kind]}">{_E(data)}</p>')
        elif kind == "facts":
            rows = "".join(f'<tr><td style="{_STYLE["td_l"]}">{_E(l)}</td><td style="{_STYLE["td_v"]}">{_E(v)}</td></tr>'
                           for l, v in data)
            out.append(f'<table style="margin:0 0 12px;border-collapse:collapse;">{rows}</table>')
        elif kind == "bullets":
            out.append('<ul style="margin:0 0 12px;padding-left:20px;">'
                       + "".join(f"<li>{_E(item)}</li>" for item in data) + "</ul>")
        elif kind == "buttons":
            ordered, expires_at = data
            out.append('<p style="margin:0 0 4px;">'
                       + "".join(f'<a href="{_E(url)}" style="{_STYLE["btn"]}">{_E(label)}</a>'
                                 for label, url in ordered) + "</p>")
            out.append(f'<p style="{_STYLE["small"]}">{_E(_links_note(expires_at))}</p>')
    out.append(f'<p style="{_STYLE["small"]}">{_E(footer)}</p>')
    return ('<!DOCTYPE html><html><head><meta charset="UTF-8"></head>'
            '<body style="margin:0;padding:0;background:#f4f4f4;">'
            '<div style="max-width:600px;margin:0 auto;padding:20px;background:#ffffff;'
            'font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;color:#222222;">'
            + "".join(out) + "</div></body></html>")


def _text(blocks, footer):
    out = []
    for kind, data in blocks:
        if kind == "h":
            out.append(f"{data}\n{'=' * min(len(data), 70)}")
        elif kind == "h3":
            out.append(f"{data}\n{'-' * min(len(data), 70)}")
        elif kind == "p":
            out.append(data)
        elif kind == "note":
            out.append(f"NOTE: {data}")
        elif kind == "facts":
            out.append("\n".join(f"  {l}: {v}" for l, v in data))
        elif kind == "bullets":
            out.append("\n".join(f"  - {item}" for item in data))
        elif kind == "buttons":
            ordered, expires_at = data
            out.append("\n".join(f"{label}:\n  {url}" for label, url in ordered) + "\n" + _links_note(expires_at))
    out.append(f"--\n{footer}")
    return "\n\n".join(out) + "\n"


def _links_note(expires_at):
    note = "Each link opens a confirmation page first; nothing changes until you press Confirm. Each link works once"
    return note + (f" and expires on {fmt_time(expires_at)}." if expires_at else ".")


FOOTER = "Cloud Cost Guardian (CMPS 297U). Automated message; replies go to the team address."


def clean_subject(subject, dry_run):
    subject = " ".join(subject.replace("\r", " ").replace("\n", " ").split())
    if dry_run:
        subject = "[DRY RUN] " + subject
    if len(subject) > SUBJECT_MAX:
        subject = subject[: SUBJECT_MAX - 1] + "…"
    return subject


# ---------------------------------------------------------------- templates

def render(template, vars_, findings, links):
    """Returns (subject, html, text). links: {"<resourceId>#<findingType>": {action: url}}."""
    body = _Body()
    dry_run = vars_.get("dryRun") is True
    subject = _RENDERERS[template](body, vars_, findings, links, dry_run)
    if dry_run:
        body.blocks.insert(1, ("note", "Dry run: nothing will actually be stopped or deleted. "
                                       "This email shows what would happen."))
    return clean_subject(subject, dry_run), _html(body.blocks, FOOTER), _text(body.blocks, FOOTER)


def _finding_buttons(body, findings, links):
    for f in findings:
        body.buttons(links.get(finding_key(f)), f.get("expiresAt"))


def _timeline_notice(final):
    def render_(body, v, findings, links, dry_run):
        what = _label(v["resourceType"])
        who = _named(v["resourceId"], v.get("name"))
        verb = "stopped" if v["plannedAction"] == "stop" else "snapshotted and deleted"
        deadline = fmt_time(v["deadlineAt"])
        if final:
            title = f"Final warning: {what} {who} will be {verb} on {deadline}"
        else:
            title = f"{what} {who} looks unused and will be {verb} on {deadline}"
        body.h(title)
        if final:
            body.p(f"This is the last email before the action. On {deadline} the Guardian checks this {what} "
                   f"once more and, if it is still unused, it will be {verb}.")
        else:
            body.p(f"The Guardian found that this {what} looks unused. Unless you act, it will be {verb} "
                   f"on {deadline}.")
        body.facts([
            ("Resource", f"{what} {v['resourceId']}"),
            ("Name", _short(v["name"]) if v.get("name") else None),
            ("Project", v.get("project")),
            ("Region", v["region"]),
            ("Estimated cost", fmt_money(v["estimatedMonthlyCost"])),
            ("Activity", v.get("idleSummary")),
            ("Days unattached", v.get("daysUnattached")),
            ("Planned action", "stop the instance" if v["plannedAction"] == "stop"
             else "take a snapshot, then delete the volume"),
            ("Deadline", deadline),
        ])
        if v["plannedAction"] == "stop":
            body.p("Stopping is reversible: the disks are kept and you can start the instance again at any time.")
        else:
            body.p("Before deleting, the Guardian takes a snapshot, so the volume can be restored from it.")
        _finding_buttons(body, findings, links)
        if any(links.values()):
            body.p("Protect keeps the resource and stops these warnings (it adds guardian:protect=true). "
                   "Postpone moves the deadline later.")
        return title
    return render_


def _stop_confirmation(body, v, findings, links, dry_run):
    who = _named(v["resourceId"], v.get("name"))
    title = f"Instance {who} would have been stopped" if dry_run else f"Instance {who} was stopped"
    body.h(title)
    body.p("The instance stayed unused until its deadline. " +
           ("In a real run it would now be stopped." if dry_run
            else "It is now stopped; its disks are kept. Start it again from the EC2 console when you need it."))
    body.facts([("Region", v["region"]), ("Monthly savings", fmt_money(v["realizedMonthlySavings"]))])
    ips = [str(ip) for ip in v["elasticIps"]]
    if ips:
        body.note("These Elastic IPs are still associated with the stopped instance and are still billed: "
                  + ", ".join(ips) + ". Release them if you don't need them (the Guardian never releases them).")
    return title


def _delete_confirmation(body, v, findings, links, dry_run):
    who = _named(v["resourceId"], v.get("name"))
    snapshot = v["snapshotId"] or "none (dry run)"
    if dry_run:
        title = f"Volume {who} would have been deleted"
    else:
        title = f"Volume {who} was deleted (snapshot {snapshot} kept)"
    body.h(title)
    body.p("The volume stayed unattached until its deadline. " +
           ("In a real run the Guardian would now snapshot and delete it." if dry_run
            else "The Guardian took a snapshot and deleted the volume. The snapshot is kept."))
    body.facts([
        ("Region", v["region"]),
        ("Availability Zone", v.get("availabilityZone")),
        ("Size", f"{v['sizeGb']} GB"),
        ("Snapshot", snapshot),
        ("Monthly savings", fmt_money(v["realizedMonthlySavings"])),
    ])
    _finding_buttons(body, findings, links)
    if not dry_run:
        body.p("After the restore link expires you can still restore the volume from the snapshot in the EC2 "
               "console. The snapshot costs a little per month until someone deletes it.")
    return title


def _workflow_failed(body, v, findings, links, dry_run):
    title = f"Cost Guardian could not finish on {v['resourceId']}"
    body.h(title)
    body.p("The Guardian's timeline for this resource stopped with an error. The team has been alerted; "
           "a later scan may retry it. Check the resource: the progress line shows what was already done.")
    body.facts([
        ("Resource", v["resourceId"]),
        ("Finding", v["findingType"]),
        ("Region", v["region"]),
        ("Failed step", v["failedStep"]),
        ("Error", _short(v["errorMessage"], 300)),
        ("Progress", v["progress"]),
    ])
    return title


_REPORT_TITLES = {
    "eip_unassociated": "Unused Elastic IP {who}",
    "eip_on_stopped_instance": "Elastic IP {who} is on a stopped instance",
    "autoscaling": "Idle instance {who} in an Auto Scaling group",
}
_REPORT_TEXT = {
    "eip_unassociated": "This Elastic IP is not associated with anything and is billed by the hour. "
                        "Release it if it is not needed.",
    "eip_on_stopped_instance": "This Elastic IP is associated with an instance that has been stopped for a while. "
                               "It is billed by the hour; release it if it is not needed.",
    "autoscaling": "This instance looks unused, but it belongs to an Auto Scaling group: stopping it would only "
                   "make the group start a replacement. If the group is bigger than needed, scale the group "
                   "down instead (lower its desired capacity, and its minimum size if needed).",
}


def _report_notice(body, v, findings, links, dry_run):
    who = _named(v["resourceId"], v.get("name"))
    title = _REPORT_TITLES[v["reason"]].format(who=who)
    body.h(title)
    body.p(_REPORT_TEXT[v["reason"]])
    body.facts([
        ("Resource", f"{_label(v['resourceType'])} {v['resourceId']}"),
        ("Finding", v["findingType"]),
        ("Region", v["region"]),
        ("Auto Scaling group", v.get("autoScalingGroup")),
        ("Estimated cost", fmt_money(v["estimatedMonthlyCost"])),
    ])
    body.p("The Guardian only reports this; it will not change the resource.")
    return title


def _missing_tags(body, v, findings, links, dry_run):
    title = f"Missing tags on {_label(v['resourceType'])} {v['resourceId']}"
    tags = ", ".join(str(t) for t in v["missingTags"])
    body.h(title)
    body.p(f"This resource is missing the tags: {tags}. Without them the Guardian cannot tell whom to warn "
           "or which project pays for it.")
    body.facts([("Resource", v["resourceId"]), ("Region", v["region"]), ("Creator lookup", v.get("creatorLookup"))])
    body.p("Add the tags in the console; the next scan picks them up.")
    return title


def _missing_tags_grouped(body, v, findings, links, dry_run):
    resources = v["resources"]
    title = f"Missing tags on instance {v['instanceId']} and {len(resources)} attached resource(s)"
    body.h(title)
    body.p(f"Instance {v['instanceId']} ({v['region']}) and the resources attached to it have missing tags, "
           "and their creator could not be found. Tagging the instance is enough: the Guardian copies its "
           "tags to its volumes and Elastic IPs on the next scan.")
    body.bullets(f"{r.get('resourceId')} ({_label(r.get('resourceType'))}): missing "
                 + ", ".join(str(t) for t in (r.get("missingTags") or [])) for r in resources)
    return title


def _restore_done(body, v, findings, links, dry_run):
    title = f"Volume {v['sourceVolumeId']} restored as {v['newVolumeId']}"
    body.h(title)
    body.p(f"A new volume was created from snapshot {v['snapshotId']} in {v['availabilityZone']}, with the "
           "original tags. It is not attached: attach it to an instance in the same Availability Zone. "
           "Like any volume it is billed, and it is reported again if it stays unattached.")
    body.facts([
        ("New volume", v["newVolumeId"]),
        ("Original volume", v["sourceVolumeId"]),
        ("Snapshot", v["snapshotId"]),
        ("Availability Zone", v["availabilityZone"]),
        ("Region", v["region"]),
    ])
    return title


def _digest(body, v, findings, links, dry_run):
    items = v["findings"]
    title = f"Cost Guardian weekly digest: {len(items)} open finding(s)"
    body.h(title)
    if v.get("aiSummary"):
        body.h3("AI summary (written by Amazon Bedrock from the data below)")
        body.p(str(v["aiSummary"]))
    if v["budgetAlerts"]:
        body.h3("Budget alerts")
        body.bullets(f"{a.get('budgetName')}: {a.get('thresholdType')} threshold {a.get('threshold')} "
                     f"reached on {fmt_time(a.get('receivedAt'))}" for a in v["budgetAlerts"])
    expiries = {finding_key(f): f.get("expiresAt") for f in findings}
    if items:
        body.h3("Open findings")
        for item in items:
            key = f"{item.get('resourceId')}#{item.get('findingType')}"
            body.p(f"{_label(item.get('resourceType'))} {_named(item.get('resourceId'), item.get('name'))}")
            body.facts([
                ("Finding", item.get("findingType")),
                ("Region", item.get("region")),
                ("Status", item.get("status")),
                ("Report only", item.get("reportOnlyReason")),
                ("Estimated cost", fmt_money(item.get("estimatedMonthlyCost"))),
                ("Cost so far", fmt_money(item.get("costSoFar"), per_month=False)),
                ("Days open", item.get("daysOpen")),
                ("Timeline step", item.get("timelineStep")),
                ("Deadline", fmt_time(item["deadlineAt"]) if item.get("deadlineAt") else None),
            ])
            body.buttons(links.get(key), expiries.get(key))
    if v["protected"]:
        body.h3("Protected (reported only, no warnings)")
        body.bullets(f"{_label(p.get('resourceType'))} {_named(p.get('resourceId'), p.get('name'))}, "
                     f"{p.get('region')}: {fmt_money(p.get('estimatedMonthlyCost'))}" for p in v["protected"])
    if v["snapshots"]:
        body.h3("Snapshots kept by the Guardian")
        body.bullets(f"{s.get('snapshotId')} (from {s.get('sourceVolumeId')}, {s.get('region')}, "
                     f"{s.get('sizeGb')} GB, {s.get('ageDays')} days old): {fmt_money(s.get('monthlyCost'))}"
                     for s in v["snapshots"])
    if v["missingTags"]:
        body.h3("Missing tags")
        body.bullets(f"{_label(m.get('resourceType'))} {m.get('resourceId')} ({m.get('region')}): missing "
                     + ", ".join(str(t) for t in (m.get("missingTags") or [])) for m in v["missingTags"])
    if not (items or v["protected"] or v["snapshots"] or v["missingTags"] or v["budgetAlerts"]):
        body.p("Nothing open this week.")
    return title


_RENDERERS = {
    "FIRST_NOTICE": _timeline_notice(final=False),
    "FINAL_WARNING": _timeline_notice(final=True),
    "STOP_CONFIRMATION": _stop_confirmation,
    "DELETE_CONFIRMATION": _delete_confirmation,
    "WORKFLOW_FAILED": _workflow_failed,
    "REPORT_NOTICE": _report_notice,
    "MISSING_TAGS": _missing_tags,
    "MISSING_TAGS_GROUPED": _missing_tags_grouped,
    "RESTORE_DONE": _restore_done,
    "DIGEST": _digest,
}
assert set(_RENDERERS) == TEMPLATES
