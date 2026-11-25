"""IAM review of every Guardian role (task #39, lane C). Read-only.

Usage:
    python platform/tools/iam_review.py --prefix cg-dev- --profile guardian --account 788575282701 \
        --dev-scope cg-dev- --out docs/iam-review.md
    (--dev-scope "" for a team stack; --no-simulate skips the IAM policy simulator)

AWS calls (all read-only): sts GetCallerIdentity; iam ListRoles / GetRole / ListRolePolicies / GetRolePolicy /
ListAttachedRolePolicies / ListInstanceProfilesForRole / SimulatePrincipalPolicy; lambda ListFunctions / GetPolicy;
sns GetTopicAttributes; s3 GetBucketPolicy; sqs GetQueueUrl / GetQueueAttributes. Never Terraform state or plans.

Exit code 1 when a hard rule (H1-H7) fails or a simulator case gives an unexpected decision; warnings exit 0.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from functools import lru_cache

# ---------------------------------------------------------------- expectations

# Role short name (name minus prefix and "-role") -> the one service principal its trust policy may name.
EXPECTED_ROLES = {
    "remediation": "lambda.amazonaws.com",
    "action": "lambda.amazonaws.com",
    "ec2-timeline": "states.amazonaws.com",
    "ebs-timeline": "states.amazonaws.com",
    "scanner": "lambda.amazonaws.com",
    "notify": "lambda.amazonaws.com",
    "budget-subscriber": "lambda.amazonaws.com",
    "scheduler": "scheduler.amazonaws.com",
    "daily-cost": "lambda.amazonaws.com",
    "daily-summary": "lambda.amazonaws.com",
    "dashboard": "ec2.amazonaws.com",
}
# Roles that may exist but are not deployed yet (reported as "not deployed", not as missing).
OPTIONAL_ROLES = {"digest": "lambda.amazonaws.com"}  # task #42

# H1: never granted to any Guardian role (design §16.1, CLAUDE.md).
NEVER_GRANTED = ["ec2:DeleteSnapshot", "ec2:ReleaseAddress"]

# H5: privilege escalation actions never granted in a permission policy.
ESCALATION_PATTERNS = ["iam:PassRole", "iam:Create*", "iam:Put*", "iam:Attach*", "iam:Update*", "iam:Delete*",
                       "sts:AssumeRole"]

# H7: actions allowed with Resource "*" because they have no resource-level permissions (the "Resource types"
# column is empty in the Service Authorization Reference).
STAR_RESOURCE_ALLOWLIST = {
    "ec2:Describe*": "EC2 Describe* actions support no resource-level permissions (resource types column empty).",
    "cloudwatch:GetMetricStatistics": "No resource types for GetMetricStatistics; metrics cannot be scoped by ARN.",
    "ce:GetCostAndUsage": "Cost Explorer read APIs have no resource types (account-wide billing data).",
    "ce:GetCostForecast": "Cost Explorer read APIs have no resource types (account-wide billing data).",
    "cloudtrail:LookupEvents": "LookupEvents reads the account's event history; it has no resource types.",
}

# Mutating EC2 actions = anything EC2 that is not a read.
EC2_READ_PREFIXES = ("ec2:describe", "ec2:get", "ec2:list", "ec2:search")

DEV_SCOPE_KEYS = ("ec2:resourcetag/guardian:dev-scope", "aws:resourcetag/guardian:dev-scope",
                  "aws:requesttag/guardian:dev-scope")

DYNAMODB_WRITES = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"]

# Design §16.1 "key permissions" per role (logs permissions are implicit for every Lambda and ignored).
DESIGN_16_1 = {
    "scanner": ["ec2:Describe*", "cloudwatch:GetMetricStatistics", "ec2:CreateTags", "cloudtrail:LookupEvents",
                "iam:ListUserTags", "states:StartExecution", "states:StopExecution", "dynamodb:*"],
    "ec2-timeline": ["lambda:InvokeFunction", "dynamodb:UpdateItem", "dynamodb:PutItem"],
    "ebs-timeline": ["lambda:InvokeFunction", "dynamodb:UpdateItem", "dynamodb:PutItem"],
    "notify": ["ses:SendEmail", "dynamodb:PutItem", "dynamodb:BatchWriteItem", "dynamodb:UpdateItem"],
    "remediation": ["ec2:StopInstances", "ec2:DeleteVolume", "ec2:CreateSnapshot", "ec2:CreateTags",
                    "ec2:Describe*", "dynamodb:*"],
    "action": ["ec2:CreateTags", "ec2:CreateVolume", "states:StartExecution", "states:StopExecution", "dynamodb:*"],
    "daily-cost": ["ce:GetCostAndUsage", "ce:GetCostForecast", "dynamodb:*"],
    "daily-summary": ["dynamodb:*"],
    "digest": ["dynamodb:*", "bedrock:InvokeModel", "lambda:InvokeFunction"],
    "budget-subscriber": ["dynamodb:*"],
    "dashboard": ["dynamodb:*", "bedrock:InvokeModel"],
}
# Differences an action-level comparison cannot see (tables, conditions, roles the design doesn't list).
DESIGN_NOTES = {
    "scanner": "Live scopes CreateTags to owner/project keys on volumes / Elastic IPs and owner on instances, with "
               "the dev-scope tag condition; DynamoDB limited to findings, audit, volume-attachments, "
               "creator-lookups. Invoking Notify is new since §16.1 (CONTRACT §4.8, #36).",
    "ec2-timeline": "Design has one Step Functions role; live has one per workflow. EC2: UpdateItem on findings and "
                    "PutItem on audit only (no PutItem on findings).",
    "ebs-timeline": "PutItem on findings only for snap-* keys (SNAPSHOT_REMINDER, CONTRACT v2.16).",
    "notify": "SendEmail pinned by ses:FromAddress; audit PutItem for every notice (CONTRACT §4.1), not only "
              "fallbacks; UpdateItem on findings limited by dynamodb:Attributes and ReturnValues; DLQ SendMessage "
              "(async invocations).",
    "remediation": "DynamoDB is audit PutItem only (no findings writes: the workflows own them). CreateTags only on "
                   "new snapshots (ec2:CreateAction). Adds cloudwatch:GetMetricStatistics for the CHECK_EC2 re-check.",
    "action": "CreateVolume also requires the guardian:restored-from request tag on the new volume; tags on restored "
              "volumes at creation only; invokes Notify for RESTORE_DONE (not in §16.1); tokens: GetItem / "
              "UpdateItem only (Notify writes them).",
    "daily-cost": "No ce:GetCostForecast (AWS Budgets covers forecasts); DLQ SendMessage.",
    "daily-summary": "Findings Scan, audit Query on GSI byDay only, PutItem on daily-summaries; DLQ SendMessage.",
    "digest": "Not deployed yet (#42).",
    "budget-subscriber": "PutItem on budget-alerts only; DLQ SendMessage (not in §16.1).",
    "dashboard": "Read-only DynamoDB; no Bedrock and no counters write yet (#43); adds s3:GetObject on its artifact "
                 "prefix and ssm:GetParameter on its origin-secret parameter.",
    "scheduler": "Not in design §16.1 (CONTRACT §8, #37): invokes exactly the scheduled functions, DLQ SendMessage.",
}

DEFAULT_BEDROCK_MODEL_ID = "us.amazon.nova-2-lite-v1:0"  # CONTRACT §6


# ---------------------------------------------------------------- policy helpers

def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def globs_intersect(a: str, b: str) -> bool:
    """True if some action name matches both IAM wildcard patterns (only * and ?), case-insensitive."""
    a, b = a.lower(), b.lower()

    @lru_cache(maxsize=None)
    def go(i, j):
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i] == "*":
            return go(i + 1, j) or (j < len(b) and go(i, j + 1))
        if j < len(b) and b[j] == "*":
            return go(i, j + 1) or (i < len(a) and go(i + 1, j))
        if i == len(a) or j == len(b):
            return False
        if a[i] == "?" or b[j] == "?" or a[i] == b[j]:
            return go(i + 1, j + 1)
        return False

    return go(0, 0)


def covered_by(action: str, pattern: str) -> bool:
    """True if every action matching `action` also matches `pattern` (approximation: the action's own wildcards
    are treated as literals, so "ec2:Describe*" is covered by "ec2:Describe*" but "ec2:*" is not)."""
    return fnmatchcase(action.lower(), pattern.lower())


@dataclass
class Stmt:
    sid: str
    effect: str
    actions: list
    not_actions: list
    resources: list
    not_resources: list
    conditions: dict
    principal: object = None

    @property
    def allow(self):
        return self.effect == "Allow"

    def condition_keys(self):
        """{lowercased key: (operator, values)} for every condition."""
        out = {}
        for op, block in (self.conditions or {}).items():
            for key, values in block.items():
                out[key.lower()] = (op, as_list(values))
        return out


def parse_policy(doc) -> list:
    if isinstance(doc, str):
        doc = json.loads(doc)
    stmts = []
    for i, s in enumerate(as_list(doc.get("Statement"))):
        stmts.append(Stmt(
            sid=s.get("Sid") or f"#{i}",
            effect=s.get("Effect", ""),
            actions=as_list(s.get("Action")),
            not_actions=as_list(s.get("NotAction")),
            resources=as_list(s.get("Resource")),
            not_resources=as_list(s.get("NotResource")),
            conditions=s.get("Condition") or {},
            principal=s.get("Principal"),
        ))
    return stmts


def action_matches(stmt: Stmt, target: str) -> bool:
    """Could this statement's action element apply to an action matching `target` (a pattern)?"""
    if stmt.not_actions:
        return not any(covered_by(target, na) for na in stmt.not_actions)
    return any(globs_intersect(a, target) for a in stmt.actions)


def fmt_cond(conditions: dict) -> str:
    parts = []
    for op, block in (conditions or {}).items():
        for key, values in block.items():
            parts.append(f"{op} {key} = {', '.join(map(str, as_list(values)))}")
    return "; ".join(parts)


# ---------------------------------------------------------------- findings

@dataclass
class Issue:
    rule: str
    role: str
    sid: str
    message: str
    fix: str = ""


@dataclass
class Review:
    prefix: str
    account: str
    region: str
    dev_scope: str
    roles: dict = field(default_factory=dict)          # short -> role data
    extra_roles: list = field(default_factory=list)
    missing_roles: list = field(default_factory=list)
    not_deployed: list = field(default_factory=list)
    resource_policies: list = field(default_factory=list)  # dicts: kind, name, policy (dict|None), note
    hard: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    info: list = field(default_factory=list)
    accepted: list = field(default_factory=list)       # reviewed and accepted, not changed
    verdicts: dict = field(default_factory=dict)        # (role, sid) -> list[str]
    star_used: dict = field(default_factory=dict)       # allowlist pattern -> set(roles)
    h3_note: str = ""
    simulation: list = field(default_factory=list)

    def flag(self, kind, rule, role, sid, message, fix=""):
        issue = Issue(rule, role, sid, message, fix)
        {"hard": self.hard, "warn": self.warnings, "info": self.info, "accepted": self.accepted}[kind].append(issue)
        if kind not in ("info", "accepted"):
            self.verdicts.setdefault((role, sid), []).append(("FAIL " if kind == "hard" else "WARN ") + rule)


def short_name(role_name: str, prefix: str) -> str:
    name = role_name[len(prefix):]
    return name[:-5] if name.endswith("-role") else name


# ---------------------------------------------------------------- hard rules

def check_h1(rv, role, stmts):
    for s in stmts:
        if not s.allow:
            continue
        for forbidden in NEVER_GRANTED:
            if action_matches(s, forbidden):
                rv.flag("hard", "H1", role, s.sid, f"Allow matches {forbidden} "
                        f"({', '.join(s.actions) or 'NotAction ' + ', '.join(s.not_actions)}).",
                        f"Remove {forbidden} (or the wildcard covering it) from statement {s.sid}.")


def check_h2(rv, role, stmts):
    for s in stmts:
        if not s.allow:
            continue
        if s.not_actions:
            rv.flag("hard", "H2", role, s.sid, "Allow with NotAction grants every other action of every service.",
                    "Replace NotAction with an explicit Action list.")
        for a in s.actions:
            if a == "*" or a.endswith(":*"):
                rv.flag("hard", "H2", role, s.sid, f"Allow with full wildcard action {a}.",
                        "List the actions the code calls.")


def check_h3(rv, roles):
    role = "remediation"
    stmts = roles.get(role, {}).get("statements")
    if stmts is None:
        rv.flag("hard", "H3", role, "-", "Remediation role not found; the protect Deny cannot be checked.")
        return
    need = {"ec2:StopInstances", "ec2:DeleteVolume"}
    notes = []
    for s in stmts:
        if s.effect != "Deny" or s.not_actions:
            continue
        covered = {a for a in need if any(globs_intersect(x, a) for x in s.actions)}
        if not covered:
            continue
        if s.not_resources or not any(r == "*" or "instance/" in r or "volume/" in r for r in s.resources):
            continue
        for op, block in s.conditions.items():
            for key, values in block.items():
                if key.lower() == "aws:resourcetag/guardian:protect" and "true" in [v.lower() for v in as_list(values)]:
                    base = op.split(":")[-1]
                    if base == "StringEqualsIgnoreCase":
                        case = "value compared case-insensitively (true / TRUE / True all match)"
                    elif base in ("StringEquals", "StringLike"):
                        case = "value compared case-SENSITIVELY: only lowercase 'true' is denied"
                    else:
                        case = f"operator {op}"
                    if "IfExists" in op or op.startswith("ForAnyValue") or op.startswith("ForAllValues"):
                        case += f" (operator {op} needs review)"
                    notes.append((s.sid, covered, case))
                    need -= covered
    if need:
        rv.flag("hard", "H3", role, "-", f"No explicit Deny on {', '.join(sorted(need))} conditioned on "
                "aws:ResourceTag/guardian:protect = true.",
                "Add a Deny statement for ec2:StopInstances and ec2:DeleteVolume, Resource *, condition "
                "StringEqualsIgnoreCase aws:ResourceTag/guardian:protect = true.")
    rv.h3_note = "; ".join(f"{sid} covers {', '.join(sorted(c))}: {case}" for sid, c, case in notes) or "none"


def check_h4(rv, role, trust_doc, expected_service):
    stmts = parse_policy(trust_doc)
    allows = [s for s in stmts if s.allow]
    if not allows:
        rv.flag("hard", "H4", role, "trust", "Trust policy has no Allow statement.")
    for s in allows:
        p = s.principal
        if p == "*" or not isinstance(p, dict):
            rv.flag("hard", "H4", role, "trust", f"Principal {p!r} is not a single service principal.",
                    f"Principal {{\"Service\": \"{expected_service}\"}} only.")
            continue
        services = as_list(p.get("Service"))
        others = {k: v for k, v in p.items() if k != "Service"}
        if others:
            rv.flag("hard", "H4", role, "trust", f"Non-service principals {others}.",
                    f"Remove them; only {expected_service}.")
        if services != [expected_service]:
            rv.flag("hard", "H4", role, "trust", f"Service principals {services}, expected [{expected_service}].",
                    f"Only {expected_service}.")
        if s.not_actions or [a.lower() for a in s.actions] != ["sts:assumerole"]:
            rv.flag("hard", "H4", role, "trust", f"Trust actions {s.actions or s.not_actions}, expected "
                    "sts:AssumeRole only.", "Action sts:AssumeRole only.")
        keys = s.condition_keys()
        if not ({"aws:sourceaccount", "aws:sourcearn"} & keys.keys()):
            if expected_service == "ec2.amazonaws.com":
                rv.flag("info", "W1", role, "trust", "EC2 instance-profile trust without aws:SourceAccount: AWS's "
                        "confused-deputy guidance does not cover EC2 instance roles; not flagged.")
            elif expected_service == "lambda.amazonaws.com":
                rv.flag("accepted", "W1", role, "trust", "Lambda trust policy without aws:SourceAccount / "
                        "aws:SourceArn.", W1_LAMBDA_ACCEPTED)
            else:
                rv.flag("warn", "W1", role, "trust", "Trust policy has no aws:SourceAccount / aws:SourceArn "
                        "condition (confused-deputy protection).",
                        f"Add condition StringEquals aws:SourceAccount = {rv.account} to the trust policy.")


W1_LAMBDA_ACCEPTED = ("Accepted, not changed (task #39 review): AWS does not clearly document aws:SourceAccount / "
                      "aws:SourceArn for Lambda execution roles, and iam:PassRole within this account is the real "
                      "guard (only principals of this account that may pass the role can attach it to a function).")


def check_h5(rv, role, attached, stmts):
    for pol in attached:
        rv.flag("hard", "H5", role, "attached", f"Attached managed policy {pol.get('PolicyArn')}.",
                "Detach it; Guardian roles use one inline policy each.")
    for s in stmts:
        if not s.allow:
            continue
        for pattern in ESCALATION_PATTERNS:
            if action_matches(s, pattern):
                rv.flag("hard", "H5", role, s.sid, f"Allow matches {pattern}.", f"Remove {pattern}.")


def _ddb_arn_ok(resource, rv):
    import re
    pat = (rf"^arn:aws:dynamodb:{re.escape(rv.region)}:{re.escape(rv.account)}:table/{re.escape(rv.prefix)}"
           r"[A-Za-z0-9_.-]+(/index/[A-Za-z0-9_.-]+)?$")
    return re.match(pat, resource) is not None


def check_h6(rv, role, stmts):
    for s in stmts:
        if not s.allow or not action_matches(s, "dynamodb:*"):
            continue
        if any(a.lower() == "dynamodb:*" for a in s.actions) or s.not_actions:
            rv.flag("hard", "H6", role, s.sid, "dynamodb:* (or NotAction) granted.", "List the DynamoDB actions.")
        if s.not_resources:
            rv.flag("hard", "H6", role, s.sid, "DynamoDB actions with NotResource.", "Use Resource = table ARN.")
        bad = [r for r in s.resources if not _ddb_arn_ok(r, rv)]
        if bad:
            rv.flag("hard", "H6", role, s.sid, f"DynamoDB resource not a table of this stack: {', '.join(bad)}.",
                    f"Resource = arn:aws:dynamodb:{rv.region}:{rv.account}:table/{rv.prefix}<table>.")


def check_h7(rv, role, stmts):
    for s in stmts:
        if not s.allow:
            continue
        star = "*" in s.resources or bool(s.not_resources)
        if not star:
            continue
        if s.not_actions:
            rv.flag("hard", "H7", role, s.sid, "Resource * with NotAction.", "Explicit Action list.")
            continue
        for a in s.actions:
            match = next((p for p in STAR_RESOURCE_ALLOWLIST if covered_by(a, p)), None)
            if match:
                rv.star_used.setdefault(match, set()).add(role)
            else:
                what = "NotResource" if s.not_resources else "Resource *"
                rv.flag("hard", "H7", role, s.sid, f"{what} for {a}, which is not on the no-resource-level "
                        "allowlist.", f"Scope {a} to the resource ARNs it acts on.")


# ---------------------------------------------------------------- warnings

def warn_findings_writes(rv, role, stmts):
    findings = f"table/{rv.prefix}findings"
    for s in stmts:
        if not s.allow or not any(r.endswith(findings) for r in s.resources):
            continue
        writes = [w for w in DYNAMODB_WRITES if action_matches(s, w)]
        if not writes:
            continue
        keys = s.condition_keys()
        limits = [k for k in ("dynamodb:attributes", "dynamodb:leadingkeys") if k in keys]
        if not limits:
            rv.flag("warn", "W3", role, s.sid, f"{', '.join(writes)} on findings with no dynamodb:Attributes / "
                    "LeadingKeys limit.", FINDINGS_WRITE_FIXES.get(role, "None proposed (the role owns most "
                                                                         "finding attributes)."))
        for k in limits:
            op, _ = keys[k]
            if op.startswith("ForAllValues"):
                null_guard = any(o == "Null" and k in {x.lower() for x in b} for o, b in s.conditions.items())
                if not null_guard:
                    name = next(x for b in s.conditions.values() for x in b if x.lower() == k)
                    rv.flag("warn", "W3", role, s.sid, f"{op} {name} without a Null guard: a request without the "
                            "key passes vacuously.", f"Add condition Null {name} = false to statement {s.sid}.")


FINDINGS_WRITE_FIXES = {
    "ec2-timeline": "None proposed: the workflow updates status / timelineStep / failure fields on any EC2 finding. "
                    "Optional: ForAllValues:StringLike dynamodb:LeadingKeys = i-* (+ Null guard).",
    "ebs-timeline": "Optional: UpdateItem limited by ForAllValues:StringLike dynamodb:LeadingKeys = vol-*, snap-* "
                    "(+ Null guard).",
    "action": "Optional: ForAllValues:StringLike dynamodb:LeadingKeys = i-*, vol-* (+ Null guard); protect / "
              "postpone / restore only act on EC2_IDLE / EBS_UNATTACHED.",
    "scanner": "None proposed: the scanner owns most finding attributes for every resource type (i-, vol-, "
               "eipalloc-, snap-).",
}


def warn_logs(rv, role, stmts):
    own = f"arn:aws:logs:{rv.region}:{rv.account}:log-group:/aws/lambda/{rv.prefix}{role}:*"
    for s in stmts:
        if not s.allow or not action_matches(s, "logs:*"):
            continue
        bad = [r for r in s.resources if r != own]
        logs_actions = [a for a in s.actions if a.lower().startswith("logs:") or a == "*"]
        if bad:
            rv.flag("warn", "W5", role, s.sid, f"logs permissions ({', '.join(logs_actions)}) beyond its own log "
                    f"group: {', '.join(bad)}.", f"Resource = {own}.")
        if any(a.lower() in ("logs:createloggroup", "logs:*") for a in logs_actions):
            rv.flag("warn", "W5", role, s.sid, "logs:CreateLogGroup granted although Terraform creates the group.",
                    "Remove logs:CreateLogGroup.")


def warn_dashboard_scope(rv, roles):
    stmts = roles.get("dashboard", {}).get("statements") or []
    seen = {"kms": [], "ssm": [], "s3": [], "bedrock": []}
    for s in stmts:
        if not s.allow:
            continue
        for a in s.actions:
            svc = a.split(":")[0].lower()
            if svc in seen:
                seen[svc].append((s.sid, a, s.resources))
    param = f"arn:aws:ssm:{rv.region}:{rv.account}:parameter/{rv.prefix}dashboard/"
    bucket = f"arn:aws:s3:::{rv.prefix}dashboard-artifacts-{rv.account}/"
    for sid, a, res in seen["ssm"]:
        if any(not r.startswith(param) or "*" in r for r in res):
            rv.flag("warn", "W4", "dashboard", sid, f"{a} beyond the origin-secret parameter: {res}.",
                    f"Resource = {param}origin-secret.")
        else:
            rv.flag("info", "W4", "dashboard", sid, f"{a} limited to {', '.join(res)}.")
    for sid, a, res in seen["s3"]:
        if a.lower() != "s3:getobject" or any(not r.startswith(bucket) for r in res):
            rv.flag("warn", "W4", "dashboard", sid, f"{a} on {res}: beyond read of its artifact prefix.",
                    f"s3:GetObject on {bucket}dashboard-web/* only.")
        else:
            rv.flag("info", "W4", "dashboard", sid, f"{a} limited to {', '.join(res)}.")
    if seen["kms"]:
        for sid, a, res in seen["kms"]:
            rv.flag("warn", "W4", "dashboard", sid, f"{a} on {res}: the aws/ssm key policy already allows "
                    "decrypt through SSM.", "Remove the KMS statement.")
    else:
        rv.flag("info", "W4", "dashboard", "-", "No KMS permission: the SecureString uses aws/ssm, whose key policy "
                "allows decrypt via SSM for principals of the account (kms:ViaService).")
    if not seen["bedrock"]:
        rv.flag("info", "W4", "dashboard", "-", "No bedrock:InvokeModel yet (#43): 'one model only' cannot be "
                "checked until then.")


def warn_dev_scope(rv, role, stmts):
    if not rv.dev_scope:
        return
    for s in stmts:
        if not s.allow:
            continue
        mutating = [a for a in s.actions
                    if a.lower().startswith("ec2:") and not a.lower().startswith(EC2_READ_PREFIXES)]
        if s.not_actions and action_matches(s, "ec2:*"):
            mutating.append("NotAction(" + ",".join(s.not_actions) + ")")
        if not mutating:
            continue
        keys = s.condition_keys()
        scoped = any(k in keys and rv.dev_scope in keys[k][1] for k in DEV_SCOPE_KEYS)
        if not scoped:
            rv.flag("warn", "W6", role, s.sid, f"{', '.join(mutating)} without a guardian:dev-scope tag condition "
                    "(dev scope enforced in code only).", DEV_SCOPE_FIXES.get((role, s.sid), "Add condition "
                    f"StringEquals ec2:ResourceTag/guardian:dev-scope = var.dev_scope (dynamic, only when "
                    "dev_scope != \"\")."))


_DYN = "dynamic condition (only when var.dev_scope != \"\"), like scanner/terraform/main.tf CopyOwnerProjectTags"
DEV_SCOPE_FIXES = {
    ("remediation", "StopInstances"): f"engine/terraform/remediation.tf StopInstances: add {_DYN}: StringEquals "
                                      "ec2:ResourceTag/guardian:dev-scope = var.dev_scope.",
    ("remediation", "DeleteVolumes"): f"engine/terraform/remediation.tf DeleteVolumes: add {_DYN}: StringEquals "
                                      "ec2:ResourceTag/guardian:dev-scope = var.dev_scope.",
    ("remediation", "CreateSnapshots"): "engine/terraform/remediation.tf CreateSnapshots: split into "
                                        "CreateSnapshotOfVolume (volume/*, ec2:ResourceTag/guardian:dev-scope = "
                                        "var.dev_scope) and CreateSnapshotNew (snapshot/*, aws:RequestTag/"
                                        "guardian:dev-scope = var.dev_scope); the handler already copies the "
                                        "volume's tags, dev-scope included, onto the snapshot at creation.",
    ("remediation", "TagNewSnapshots"): "engine/terraform/remediation.tf TagNewSnapshots: add "
                                        f"{_DYN}: StringEquals aws:RequestTag/guardian:dev-scope = var.dev_scope.",
    ("action", "ProtectTagOnly"): f"engine/terraform/action.tf ProtectTagOnly: add {_DYN}: StringEquals "
                                  "ec2:ResourceTag/guardian:dev-scope = var.dev_scope.",
    ("action", "RestoreFromGuardianSnapshots"): "engine/terraform/action.tf RestoreFromGuardianSnapshots: add "
                                                f"{_DYN}: StringEquals ec2:ResourceTag/guardian:dev-scope = "
                                                "var.dev_scope (Guardian snapshots carry the volume's dev-scope "
                                                "tag).",
    ("action", "RestoredVolumes"): f"engine/terraform/action.tf RestoredVolumes: add {_DYN}: StringEquals "
                                   "aws:RequestTag/guardian:dev-scope = var.dev_scope (_restore_tags copies the "
                                   "snapshot's tags).",
    ("action", "TagRestoredVolumes"): f"engine/terraform/action.tf TagRestoredVolumes: add {_DYN}: StringEquals "
                                      "aws:RequestTag/guardian:dev-scope = var.dev_scope.",
}


def check_resource_policies(rv):
    for rp in rv.resource_policies:
        if rp["policy"] is None:
            continue
        for s in parse_policy(rp["policy"]):
            keys = s.condition_keys()
            p = s.principal
            if s.allow and (p == "*" or (isinstance(p, dict) and "*" in as_list(p.get("AWS")))) and not keys:
                rv.flag("warn", "W7", rp["name"], s.sid, "Allow to Principal * without a condition.",
                        "Name the principal or add aws:SourceAccount / aws:SourceArn.")
            aws_principals = as_list(p.get("AWS")) if isinstance(p, dict) else []
            foreign = [a for a in aws_principals if a != "*" and rv.account not in a]
            if s.allow and foreign:
                rv.flag("warn", "W7", rp["name"], s.sid, f"Cross-account principals {foreign}.", "Remove them.")
            if rp["kind"] == "lambda" and s.allow:
                has_arn = "aws:sourcearn" in keys
                has_acct = "aws:sourceaccount" in keys
                if not has_arn and not has_acct:
                    rv.flag("warn", "W2", rp["name"], s.sid, "Lambda permission without SourceArn / SourceAccount.",
                            "Set source_arn (and source_account) on the aws_lambda_permission.")
                elif not has_acct:
                    rv.flag("info", "W2", rp["name"], s.sid, "SourceArn set, no SourceAccount: the ARN already "
                            "names this account's resource, so no change needed.")


# ---------------------------------------------------------------- design diff

def design_diff(rv):
    rows = []
    for role in sorted(set(DESIGN_16_1) | set(rv.roles) | {"scheduler"}):
        data = rv.roles.get(role)
        live = []
        if data:
            for s in data["statements"]:
                if s.allow:
                    live += [a for a in s.actions if not a.lower().startswith("logs:")]
        design = DESIGN_16_1.get(role)
        if design is None:
            extra, missing = sorted(set(live)), []
        else:
            extra = sorted({a for a in live if not any(covered_by(a, d) for d in design)})
            missing = sorted({d for d in design if d != "dynamodb:*" and not any(globs_intersect(a, d) for a in live)})
        if data is None and role not in DESIGN_16_1:
            continue
        rows.append((role, extra, missing if data else ["(role not deployed)"], DESIGN_NOTES.get(role, "")))
    return rows


# ---------------------------------------------------------------- analysis entry point

def analyze(rv: Review) -> Review:
    for role, data in rv.roles.items():
        stmts = []
        for doc in data["inline"].values():
            stmts += parse_policy(doc)
        data["statements"] = stmts
        expected = EXPECTED_ROLES.get(role) or OPTIONAL_ROLES.get(role)
        if expected:
            check_h4(rv, role, data["trust"], expected)
        else:
            rv.flag("hard", "H4", role, "trust", "Unexpected role: no expected service principal known.",
                    "Add it to the review's expected roles or remove it.")
        check_h1(rv, role, stmts)
        check_h2(rv, role, stmts)
        check_h5(rv, role, data.get("attached", []), stmts)
        check_h6(rv, role, stmts)
        check_h7(rv, role, stmts)
        warn_findings_writes(rv, role, stmts)
        warn_logs(rv, role, stmts)
        warn_dev_scope(rv, role, stmts)
    check_h3(rv, rv.roles)
    warn_dashboard_scope(rv, rv.roles)
    check_resource_policies(rv)
    return rv


# ---------------------------------------------------------------- AWS collection (read-only)

def collect(session, rv: Review):
    iam = session.client("iam")
    names = []
    for page in iam.get_paginator("list_roles").paginate():
        names += [r["RoleName"] for r in page["Roles"] if r["RoleName"].startswith(rv.prefix)]
    for name in sorted(names):
        role = iam.get_role(RoleName=name)["Role"]
        inline = {}
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=name):
            for pname in page["PolicyNames"]:
                inline[pname] = iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
        attached = []
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
            attached += page["AttachedPolicies"]
        profiles = [p["InstanceProfileName"] for p in
                    iam.list_instance_profiles_for_role(RoleName=name)["InstanceProfiles"]]
        short = short_name(name, rv.prefix)
        rv.roles[short] = {"name": name, "arn": role["Arn"], "trust": role["AssumeRolePolicyDocument"],
                           "inline": inline, "attached": attached, "instance_profiles": profiles,
                           "boundary": (role.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")}
    for short in EXPECTED_ROLES:
        if short not in rv.roles:
            rv.missing_roles.append(short)
            rv.flag("hard", "INV", short, "-", "Expected role is missing.")
    for short in OPTIONAL_ROLES:
        if short not in rv.roles:
            rv.not_deployed.append(short)
    rv.extra_roles = sorted(r for r in rv.roles if r not in EXPECTED_ROLES and r not in OPTIONAL_ROLES)

    lam = session.client("lambda", region_name=rv.region)
    fns = []
    for page in lam.get_paginator("list_functions").paginate():
        fns += [f["FunctionName"] for f in page["Functions"] if f["FunctionName"].startswith(rv.prefix)]
    for fn in sorted(fns):
        try:
            pol = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
            rv.resource_policies.append({"kind": "lambda", "name": fn, "policy": pol, "note": ""})
        except lam.exceptions.ResourceNotFoundException:
            rv.resource_policies.append({"kind": "lambda", "name": fn, "policy": None,
                                         "note": "no resource policy (invoked only by IAM roles of this account)"})

    topic_arn = f"arn:aws:sns:{rv.region}:{rv.account}:{rv.prefix}team-alerts"
    try:
        attrs = session.client("sns", region_name=rv.region).get_topic_attributes(TopicArn=topic_arn)["Attributes"]
        rv.resource_policies.append({"kind": "sns", "name": f"{rv.prefix}team-alerts",
                                     "policy": json.loads(attrs.get("Policy", "{}")), "note": ""})
    except Exception as err:  # noqa: BLE001 - reported, not fatal
        rv.resource_policies.append({"kind": "sns", "name": f"{rv.prefix}team-alerts", "policy": None,
                                     "note": f"could not read: {type(err).__name__}"})

    bucket = f"{rv.prefix}dashboard-artifacts-{rv.account}"
    s3 = session.client("s3", region_name=rv.region)
    try:
        rv.resource_policies.append({"kind": "s3", "name": bucket,
                                     "policy": json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"]), "note": ""})
    except Exception as err:  # noqa: BLE001
        rv.resource_policies.append({"kind": "s3", "name": bucket, "policy": None,
                                     "note": f"no bucket policy / could not read: {type(err).__name__}"})

    sqs = session.client("sqs", region_name=rv.region)
    try:
        url = sqs.get_queue_url(QueueName=f"{rv.prefix}dlq")["QueueUrl"]
        pol = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")
        rv.resource_policies.append({"kind": "sqs", "name": f"{rv.prefix}dlq",
                                     "policy": json.loads(pol) if pol else None,
                                     "note": "" if pol else "no queue policy: senders are authorized by their own "
                                             "role's sqs:SendMessage (same account)"})
    except Exception as err:  # noqa: BLE001
        rv.resource_policies.append({"kind": "sqs", "name": f"{rv.prefix}dlq", "policy": None,
                                     "note": f"could not read: {type(err).__name__}"})


# ---------------------------------------------------------------- IAM policy simulator

ALLOWED = ("allowed",)
DENIED = ("implicitDeny", "explicitDeny")
EXPLICIT = ("explicitDeny",)
INFO = None  # reported, never a failure


@dataclass
class SimCase:
    role: str
    label: str
    action: str
    resource: str
    context: dict
    expect: tuple | None
    note: str = ""


def sim_cases(prefix, account, region, dev_scope, model_id=DEFAULT_BEDROCK_MODEL_ID):
    a, r, p = account, region, prefix
    inst = f"arn:aws:ec2:{r}:{a}:instance/i-0123456789abcdef0"
    vol = f"arn:aws:ec2:{r}:{a}:volume/vol-0123456789abcdef0"
    snap = f"arn:aws:ec2:{r}::snapshot/snap-0123456789abcdef0"
    eip = f"arn:aws:ec2:{r}:{a}:elastic-ip/eipalloc-0123456789abcdef0"

    def table(n):
        return f"arn:aws:dynamodb:{r}:{a}:table/{p}{n}"

    def fn(n):
        return f"arn:aws:lambda:{r}:{a}:function:{p}{n}"

    def stream(n):
        return f"arn:aws:logs:{r}:{a}:log-group:/aws/lambda/{p}{n}:log-stream:review"

    dlq = f"arn:aws:sqs:{r}:{a}:{p}dlq"
    scope = {"ec2:ResourceTag/guardian:dev-scope": dev_scope} if dev_scope else {}
    other = {"ec2:ResourceTag/guardian:dev-scope": "cg-other-"}
    req_scope = {"aws:RequestTag/guardian:dev-scope": dev_scope} if dev_scope else {}
    req_other = {"aws:RequestTag/guardian:dev-scope": "cg-other-"}
    c = []

    for role in EXPECTED_ROLES:
        for action, res in (("ec2:DeleteSnapshot", snap), ("ec2:DeleteSnapshot", "*"),
                            ("ec2:ReleaseAddress", eip), ("ec2:ReleaseAddress", "*")):
            c.append(SimCase(role, f"{action} on {'*' if res == '*' else res.rsplit(':', 1)[-1]}", action, res, {},
                             DENIED))

    # remediation
    for val in ("true", "TRUE", "True"):
        c.append(SimCase("remediation", f"StopInstances, protect={val}", "ec2:StopInstances", inst,
                         {"aws:ResourceTag/guardian:protect": val, **scope}, EXPLICIT))
        c.append(SimCase("remediation", f"DeleteVolume, protect={val}", "ec2:DeleteVolume", vol,
                         {"aws:ResourceTag/guardian:protect": val, **scope}, EXPLICIT))
    c.append(SimCase("remediation", "StopInstances, no protect tag", "ec2:StopInstances", inst, dict(scope), ALLOWED))
    c.append(SimCase("remediation", "DeleteVolume, no protect tag", "ec2:DeleteVolume", vol, dict(scope), ALLOWED))
    c.append(SimCase("remediation", "StopInstances, protect=false", "ec2:StopInstances", inst,
                     {"aws:ResourceTag/guardian:protect": "false", **scope}, ALLOWED))
    c.append(SimCase("remediation", "CreateSnapshot on volume in scope", "ec2:CreateSnapshot", vol, dict(scope),
                     ALLOWED))
    c.append(SimCase("remediation", "CreateSnapshot new snapshot, dev-scope request tag", "ec2:CreateSnapshot", snap,
                     dict(req_scope), ALLOWED))
    c.append(SimCase("remediation", "CreateTags on new snapshot (CreateAction), dev-scope request tag",
                     "ec2:CreateTags", snap, {"ec2:CreateAction": "CreateSnapshot", **req_scope}, ALLOWED))
    c.append(SimCase("remediation", "StopInstances, tag KEY spelled Guardian:Protect=true", "ec2:StopInstances",
                     inst, {"aws:ResourceTag/Guardian:Protect": "true"}, INFO,
                     "shows whether IAM matches the tag key case-insensitively"))
    if dev_scope:
        for action, res in (("ec2:StopInstances", inst), ("ec2:DeleteVolume", vol), ("ec2:CreateSnapshot", vol)):
            name = action.split(":")[1]
            c.append(SimCase("remediation", f"{name} on another dev scope", action, res, other, DENIED))
            c.append(SimCase("remediation", f"{name} without dev-scope tag", action, res, {}, DENIED))
        c.append(SimCase("remediation", "CreateSnapshot new snapshot, other dev-scope request tag",
                         "ec2:CreateSnapshot", snap, req_other, DENIED))
        c.append(SimCase("remediation", "CreateSnapshot new snapshot, no dev-scope request tag",
                         "ec2:CreateSnapshot", snap, {}, DENIED))
        c.append(SimCase("remediation", "CreateTags on new snapshot, no dev-scope request tag", "ec2:CreateTags",
                         snap, {"ec2:CreateAction": "CreateSnapshot"}, DENIED))

    # action
    for res, kind in ((inst, "instance"), (vol, "volume")):
        c.append(SimCase("action", f"CreateTags [guardian:protect]=true on {kind}", "ec2:CreateTags", res,
                         {"aws:TagKeys": ["guardian:protect"], "aws:RequestTag/guardian:protect": "true", **scope},
                         ALLOWED))
    c.append(SimCase("action", "CreateTags [owner]", "ec2:CreateTags", inst,
                     {"aws:TagKeys": ["owner"], "aws:RequestTag/owner": "x@example.com"}, DENIED))
    c.append(SimCase("action", "CreateTags [guardian:protect]=false", "ec2:CreateTags", inst,
                     {"aws:TagKeys": ["guardian:protect"], "aws:RequestTag/guardian:protect": "false"}, DENIED))
    c.append(SimCase("action", "CreateTags [guardian:protect, owner]", "ec2:CreateTags", inst,
                     {"aws:TagKeys": ["guardian:protect", "owner"], "aws:RequestTag/guardian:protect": "true",
                      "aws:RequestTag/owner": "x@example.com"}, DENIED))
    c.append(SimCase("action", "CreateTags on a snapshot", "ec2:CreateTags", snap,
                     {"aws:TagKeys": ["guardian:protect"], "aws:RequestTag/guardian:protect": "true"}, DENIED))
    c.append(SimCase("action", "CreateVolume from snapshot WITHOUT guardian:source-volume", "ec2:CreateVolume", snap,
                     {}, DENIED))
    c.append(SimCase("action", "CreateVolume from snapshot WITH guardian:source-volume", "ec2:CreateVolume", snap,
                     {"aws:ResourceTag/guardian:source-volume": "vol-0abc", **scope}, ALLOWED))
    c.append(SimCase("action", "CreateVolume new volume WITHOUT restored-from request tag", "ec2:CreateVolume", vol,
                     {}, DENIED))
    c.append(SimCase("action", "CreateVolume new volume WITH restored-from request tag", "ec2:CreateVolume", vol,
                     {"aws:RequestTag/guardian:restored-from": "snap-0abc", **req_scope}, ALLOWED))
    c.append(SimCase("action", "CreateTags on restored volume (CreateAction)", "ec2:CreateTags", vol,
                     {"ec2:CreateAction": "CreateVolume", **req_scope}, ALLOWED))
    for label, act, key in (("GetItem", "dynamodb:GetItem", "i-1"), ("UpdateItem", "dynamodb:UpdateItem", "vol-1"),
                            ("ConditionCheckItem", "dynamodb:ConditionCheckItem", "vol-1"),
                            ("UpdateItem", "dynamodb:UpdateItem", "i-1")):
        c.append(SimCase("action", f"{label} findings LeadingKeys [{key}]", act, table("findings"),
                         {"dynamodb:LeadingKeys": [key]}, ALLOWED))
    for key in ("eipalloc-1", "snap-1"):
        c.append(SimCase("action", f"UpdateItem findings LeadingKeys [{key}]", "dynamodb:UpdateItem",
                         table("findings"), {"dynamodb:LeadingKeys": [key]}, DENIED))
    c.append(SimCase("action", "UpdateItem findings, no LeadingKeys key", "dynamodb:UpdateItem", table("findings"),
                     {}, DENIED))
    c.append(SimCase("action", "StopInstances", "ec2:StopInstances", inst, {}, DENIED))
    c.append(SimCase("action", "DeleteVolume", "ec2:DeleteVolume", vol, {}, DENIED))
    if dev_scope:
        protect = {"aws:TagKeys": ["guardian:protect"], "aws:RequestTag/guardian:protect": "true"}
        c.append(SimCase("action", "CreateTags protect on another dev scope", "ec2:CreateTags", inst,
                         {**protect, **other}, DENIED))
        c.append(SimCase("action", "CreateTags protect without dev-scope tag", "ec2:CreateTags", inst, protect,
                         DENIED))
        src = {"aws:ResourceTag/guardian:source-volume": "vol-0abc"}
        c.append(SimCase("action", "CreateVolume from Guardian snapshot of another dev scope", "ec2:CreateVolume",
                         snap, {**src, **other}, DENIED))
        c.append(SimCase("action", "CreateVolume from Guardian snapshot without dev-scope tag", "ec2:CreateVolume",
                         snap, src, DENIED))
        rf = {"aws:RequestTag/guardian:restored-from": "snap-0abc"}
        c.append(SimCase("action", "CreateVolume new volume, other dev-scope request tag", "ec2:CreateVolume", vol,
                         {**rf, **req_other}, DENIED))
        c.append(SimCase("action", "CreateVolume new volume, no dev-scope request tag", "ec2:CreateVolume", vol, rf,
                         DENIED))
        c.append(SimCase("action", "CreateTags on restored volume, no dev-scope request tag", "ec2:CreateTags", vol,
                         {"ec2:CreateAction": "CreateVolume"}, DENIED))

    # scanner
    c.append(SimCase("scanner", "CreateTags [guardian:protect] on volume in scope", "ec2:CreateTags", vol,
                     {"aws:TagKeys": ["guardian:protect"], **scope}, DENIED))
    c.append(SimCase("scanner", "CreateTags [owner] on volume in scope", "ec2:CreateTags", vol,
                     {"aws:TagKeys": ["owner"], **scope}, ALLOWED))
    c.append(SimCase("scanner", "CreateTags [owner] on instance in scope", "ec2:CreateTags", inst,
                     {"aws:TagKeys": ["owner"], **scope}, ALLOWED))
    c.append(SimCase("scanner", "CreateTags [project] on instance", "ec2:CreateTags", inst,
                     {"aws:TagKeys": ["project"], **scope}, DENIED))
    if dev_scope:
        c.append(SimCase("scanner", "CreateTags [owner] on volume of another dev scope", "ec2:CreateTags", vol,
                         {"aws:TagKeys": ["owner"], **other}, DENIED))
        c.append(SimCase("scanner", "CreateTags [owner] on volume without dev-scope tag", "ec2:CreateTags", vol,
                         {"aws:TagKeys": ["owner"]}, DENIED))
    c.append(SimCase("scanner", "StopInstances", "ec2:StopInstances", inst, {}, DENIED))
    c.append(SimCase("scanner", "DeleteVolume", "ec2:DeleteVolume", vol, {}, DENIED))

    # notify
    fnd = table("findings")
    c.append(SimCase("notify", "UpdateItem findings [lastNotifiedAt]", "dynamodb:UpdateItem", fnd,
                     {"dynamodb:Attributes": ["lastNotifiedAt"]}, ALLOWED))
    c.append(SimCase("notify", "UpdateItem findings [resourceId, findingType, lastNotifiedAt]", "dynamodb:UpdateItem",
                     fnd, {"dynamodb:Attributes": ["resourceId", "findingType", "lastNotifiedAt"]}, ALLOWED))
    c.append(SimCase("notify", "UpdateItem findings [status]", "dynamodb:UpdateItem", fnd,
                     {"dynamodb:Attributes": ["status"]}, DENIED))
    c.append(SimCase("notify", "UpdateItem findings [lastNotifiedAt, status]", "dynamodb:UpdateItem", fnd,
                     {"dynamodb:Attributes": ["lastNotifiedAt", "status"]}, DENIED))
    c.append(SimCase("notify", "UpdateItem findings [lastNotifiedAt] ReturnValues=ALL_NEW", "dynamodb:UpdateItem",
                     fnd, {"dynamodb:Attributes": ["lastNotifiedAt"], "dynamodb:ReturnValues": "ALL_NEW"}, DENIED))
    c.append(SimCase("notify", "UpdateItem findings, no dynamodb:Attributes key", "dynamodb:UpdateItem", fnd, {},
                     DENIED))
    c.append(SimCase("notify", "PutItem findings", "dynamodb:PutItem", fnd, {}, DENIED))

    # ebs-timeline
    c.append(SimCase("ebs-timeline", "PutItem findings LeadingKeys [snap-123]", "dynamodb:PutItem", fnd,
                     {"dynamodb:LeadingKeys": ["snap-123"]}, ALLOWED))
    c.append(SimCase("ebs-timeline", "PutItem findings LeadingKeys [vol-123]", "dynamodb:PutItem", fnd,
                     {"dynamodb:LeadingKeys": ["vol-123"]}, DENIED))
    c.append(SimCase("ebs-timeline", "PutItem findings, no LeadingKeys key", "dynamodb:PutItem", fnd, {}, DENIED))
    for key, exp in (("vol-1", ALLOWED), ("snap-1", DENIED), ("i-1", DENIED)):
        c.append(SimCase("ebs-timeline", f"UpdateItem findings LeadingKeys [{key}]", "dynamodb:UpdateItem", fnd,
                         {"dynamodb:LeadingKeys": [key]}, exp))
    c.append(SimCase("ebs-timeline", "UpdateItem findings, no LeadingKeys key", "dynamodb:UpdateItem", fnd, {},
                     DENIED))

    # ec2-timeline
    for key, exp in (("i-1", ALLOWED), ("vol-1", DENIED)):
        c.append(SimCase("ec2-timeline", f"UpdateItem findings LeadingKeys [{key}]", "dynamodb:UpdateItem", fnd,
                         {"dynamodb:LeadingKeys": [key]}, exp))
    c.append(SimCase("ec2-timeline", "UpdateItem findings, no LeadingKeys key", "dynamodb:UpdateItem", fnd, {},
                     DENIED))
    c.append(SimCase("ec2-timeline", "PutItem findings", "dynamodb:PutItem", fnd, {"dynamodb:LeadingKeys": ["i-1"]},
                     DENIED))

    # dashboard
    for action in ("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"):
        c.append(SimCase("dashboard", f"{action.split(':')[1]} findings", action, fnd, {}, DENIED))
    c.append(SimCase("dashboard", "Scan findings (sanity)", "dynamodb:Scan", fnd, {}, ALLOWED))
    c.append(SimCase("dashboard", f"bedrock:InvokeModel on configured profile {model_id}", "bedrock:InvokeModel",
                     f"arn:aws:bedrock:{r}:{a}:inference-profile/{model_id}", {}, INFO,
                     "denied today: Bedrock is not granted until #43"))
    c.append(SimCase("dashboard", "bedrock:InvokeModel on another model", "bedrock:InvokeModel",
                     f"arn:aws:bedrock:{r}::foundation-model/amazon.nova-pro-v1:0", {}, DENIED))

    # scheduler
    c.append(SimCase("scheduler", f"InvokeFunction {p}notify", "lambda:InvokeFunction", fn("notify"), {}, DENIED))
    c.append(SimCase("scheduler", f"InvokeFunction {p}remediation", "lambda:InvokeFunction", fn("remediation"), {},
                     DENIED))
    for target in ("scanner", "daily-cost", "daily-summary"):
        c.append(SimCase("scheduler", f"InvokeFunction {p}{target}", "lambda:InvokeFunction", fn(target), {},
                         ALLOWED))

    # budget-subscriber
    ba = table("budget-alerts")
    c.append(SimCase("budget-subscriber", "PutItem budget-alerts", "dynamodb:PutItem", ba, {}, ALLOWED))
    c.append(SimCase("budget-subscriber", "PutLogEvents own log group", "logs:PutLogEvents", stream("budget-subscriber"),
                     {}, ALLOWED))
    c.append(SimCase("budget-subscriber", "SendMessage DLQ", "sqs:SendMessage", dlq, {}, ALLOWED))
    for action, res in (("dynamodb:GetItem", ba), ("dynamodb:UpdateItem", ba), ("dynamodb:DeleteItem", ba),
                        ("dynamodb:Scan", ba), ("dynamodb:PutItem", fnd),
                        ("sqs:SendMessage", f"arn:aws:sqs:{r}:{a}:{p}other"),
                        ("logs:PutLogEvents", stream("notify")), ("lambda:InvokeFunction", fn("notify")),
                        ("sns:Publish", f"arn:aws:sns:{r}:{a}:{p}team-alerts"),
                        ("ses:SendEmail", f"arn:aws:ses:{r}:{a}:identity/example.com"),
                        ("ec2:CreateTags", vol)):
        c.append(SimCase("budget-subscriber", f"{action} on {res.rsplit(':', 1)[-1]}", action, res, {}, DENIED))
    return c


def _context_entries(ctx):
    out = []
    for key, value in ctx.items():
        if isinstance(value, list):
            out.append({"ContextKeyName": key, "ContextKeyValues": value, "ContextKeyType": "stringList"})
        else:
            out.append({"ContextKeyName": key, "ContextKeyValues": [value], "ContextKeyType": "string"})
    return out


def simulate(iam, rv: Review, cases):
    for case in cases:
        role = rv.roles.get(case.role)
        row = {"case": case, "decision": None, "matched": "", "status": ""}
        if role is None:
            row["status"] = "SKIPPED (role missing)"
            rv.simulation.append(row)
            continue
        try:
            res = iam.simulate_principal_policy(PolicySourceArn=role["arn"], ActionNames=[case.action],
                                                ResourceArns=[case.resource],
                                                ContextEntries=_context_entries(case.context))
            ev = res["EvaluationResults"][0]
            row["decision"] = ev["EvalDecision"]
            row["matched"] = ", ".join(sorted({m.get("SourcePolicyId", "") for m in ev.get("MatchedStatements", [])}))
            missing = ev.get("MissingContextValues") or []
            if missing:
                row["matched"] += f" (missing context: {', '.join(missing)})"
        except Exception as err:  # noqa: BLE001 - a case the simulator cannot evaluate is reported
            row["status"] = f"NOT EVALUATED ({type(err).__name__}: {err})"
            if case.expect is not None:
                rv.flag("hard", "SIM", case.role, "-", f"Simulator could not evaluate: {case.label}.")
            rv.simulation.append(row)
            continue
        if case.expect is None:
            row["status"] = "INFO"
        elif row["decision"] in case.expect:
            row["status"] = "OK"
        else:
            row["status"] = "UNEXPECTED"
            rv.flag("hard", "SIM", case.role, "-", f"Simulator: {case.label} -> {row['decision']}, expected "
                    f"{' / '.join(case.expect)}.")
        rv.simulation.append(row)


# ---------------------------------------------------------------- report

def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def _expect_str(e):
    if e is None:
        return "info"
    if e == ALLOWED:
        return "allowed"
    if e == EXPLICIT:
        return "explicitDeny"
    return "denied"


def render(rv: Review, exit_code: int) -> str:
    L = []
    w = L.append
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    w("# IAM review of the Guardian roles")
    w("")
    w(f"Generated by `platform/tools/iam_review.py` (task #39) at {now}. Read-only: IAM / Lambda / SNS / S3 / SQS "
      "get and list calls and the IAM policy simulator; no Terraform state or plan.")
    w("")
    w(f"- Prefix: `{rv.prefix}` · account `{rv.account}` · region `{rv.region}` · dev scope: "
      f"`{rv.dev_scope or '(none: team stack)'}`")
    w(f"- **Exit code: {exit_code}** · hard failures: {len(rv.hard)} · warnings: {len(rv.warnings)} · "
      f"accepted: {len(rv.accepted)} · "
      f"simulator cases: {len(rv.simulation)} "
      f"({sum(1 for s in rv.simulation if s['status'] == 'OK')} OK, "
      f"{sum(1 for s in rv.simulation if s['status'] == 'UNEXPECTED')} unexpected, "
      f"{sum(1 for s in rv.simulation if s['status'] == 'INFO')} info)")
    w(f"- Roles found: {', '.join(sorted(rv.roles)) or 'none'}")
    w(f"- Missing: {', '.join(rv.missing_roles) or 'none'} · extra: {', '.join(rv.extra_roles) or 'none'} · "
      f"not deployed yet: {', '.join(rv.not_deployed) or 'none'}")
    w(f"- H3 (remediation protect Deny): {rv.h3_note or 'n/a'}")
    w("")
    w("## Hard failures")
    w("")
    if rv.hard:
        w("| Rule | Role | Statement | Problem | Proposed fix |")
        w("|---|---|---|---|---|")
        for i in rv.hard:
            w(f"| {i.rule} | {i.role} | {_cell(i.sid)} | {_cell(i.message)} | {_cell(i.fix)} |")
    else:
        w("None. H1-H7 pass for every role.")
    w("")
    w("## Warnings")
    w("")
    if rv.warnings:
        w("| Rule | Role / resource | Statement | Issue | Proposed fix |")
        w("|---|---|---|---|---|")
        for i in rv.warnings:
            w(f"| {i.rule} | {i.role} | {_cell(i.sid)} | {_cell(i.message)} | {_cell(i.fix)} |")
    else:
        w("None.")
    w("")
    w("Rules: W1 trust without aws:SourceAccount / SourceArn · W2 Lambda permission without SourceArn / "
      "SourceAccount · W3 findings writes without dynamodb:Attributes / LeadingKeys (or ForAllValues without a "
      "Null guard) · W4 dashboard KMS / SSM / S3 scope · W5 logs beyond the role's own log group · W6 mutating EC2 "
      "action without a guardian:dev-scope condition · W7 resource policy principals.")
    w("")
    if rv.accepted:
        w("### Accepted (reviewed, not changed)")
        w("")
        w("| Rule | Role | Statement | Issue | Reason |")
        w("|---|---|---|---|---|")
        for i in rv.accepted:
            w(f"| {i.rule} | {i.role} | {_cell(i.sid)} | {_cell(i.message)} | {_cell(i.fix)} |")
        w("")
    if rv.info:
        w("### Notes (checked, no change needed)")
        w("")
        for i in rv.info:
            w(f"- {i.rule} {i.role} {i.sid}: {i.message}")
        w("")
    w("## Resource * allowlist (H7)")
    w("")
    w("| Action pattern | Used by | Why Resource * |")
    w("|---|---|---|")
    for pat, why in STAR_RESOURCE_ALLOWLIST.items():
        w(f"| `{pat}` | {', '.join(sorted(rv.star_used.get(pat, []))) or '-'} | {why} |")
    w("")
    w("## Roles")
    for short in sorted(rv.roles):
        data = rv.roles[short]
        w("")
        w(f"### {data['name']}")
        w("")
        trust = parse_policy(data["trust"])
        tdesc = "; ".join(f"{s.effect} {', '.join(s.actions)} by {json.dumps(s.principal)}"
                          + (f" if {fmt_cond(s.conditions)}" if s.conditions else "") for s in trust)
        w(f"- Trust: {_cell(tdesc)}")
        w(f"- Inline policies: {', '.join(data['inline']) or 'none'} · attached managed: "
          f"{', '.join(p.get('PolicyArn', '') for p in data.get('attached', [])) or 'none'} · instance profiles: "
          f"{', '.join(data.get('instance_profiles', [])) or 'none'} · boundary: {data.get('boundary') or 'none'}")
        w("")
        w("| Sid | Effect | Actions | Resources | Conditions | Verdict |")
        w("|---|---|---|---|---|---|")
        for s in data.get("statements", []):
            acts = ", ".join(s.actions) if s.actions else "NotAction: " + ", ".join(s.not_actions)
            res = ", ".join(s.resources) if s.resources else "NotResource: " + ", ".join(s.not_resources)
            verdict = ", ".join(rv.verdicts.get((short, s.sid), [])) or "OK"
            w(f"| {_cell(s.sid)} | {s.effect} | {_cell(acts)} | {_cell(res)} | {_cell(fmt_cond(s.conditions))} | "
              f"{verdict} |")
    w("")
    w("## Resource policies")
    w("")
    w("| Kind | Name | Statements | Verdict |")
    w("|---|---|---|---|")
    for rp in rv.resource_policies:
        if rp["policy"] is None:
            w(f"| {rp['kind']} | {rp['name']} | - | {_cell(rp['note'])} |")
            continue
        parts = []
        for s in parse_policy(rp["policy"]):
            parts.append(f"{s.sid}: {s.effect} {', '.join(s.actions)} by {json.dumps(s.principal)}"
                         + (f" if {fmt_cond(s.conditions)}" if s.conditions else ""))
        verdict = ", ".join(v for (r, _), vs in rv.verdicts.items() if r == rp["name"] for v in vs) or "OK"
        w(f"| {rp['kind']} | {rp['name']} | {_cell(' · '.join(parts))} | {verdict} |")
    w("")
    w("## IAM policy simulator")
    w("")
    if not rv.simulation:
        w("Not run (--no-simulate).")
    else:
        w("`iam simulate-principal-policy` on the live roles, one action and one resource ARN per case. Resource "
          "tags, request tags, tag keys and DynamoDB keys are passed as context entries: the simulator does not "
          "read the tags of real resources, so every tag condition is evaluated on the values given here. "
          "Multi-resource actions (CreateVolume checks the snapshot AND the new volume; CreateSnapshot the volume "
          "AND the snapshot) are simulated one resource at a time. No resource policies or SCPs are involved.")
        w("")
        w("| Role | Case | Expected | Decision | Matched statements | Result |")
        w("|---|---|---|---|---|---|")
        for row in rv.simulation:
            cs = row["case"]
            result = row["status"] + (f": {cs.note}" if cs.note else "")
            w(f"| {cs.role} | {_cell(cs.label)} | {_expect_str(cs.expect)} | {row['decision'] or '-'} | "
              f"{_cell(row['matched'])} | {_cell(result)} |")
    w("")
    w("## Design §16.1 vs live")
    w("")
    w("Actions compared at action level (logs permissions ignored; 'DynamoDB' in the design accepts any table "
      "action, tables and conditions are in the notes).")
    w("")
    w("| Role | Live, not in §16.1 | In §16.1, not live | Notes |")
    w("|---|---|---|---|")
    for role, extra, missing, note in design_diff(rv):
        w(f"| {role} | {_cell(', '.join(extra)) or '-'} | {_cell(', '.join(missing)) or '-'} | {_cell(note)} |")
    w("")
    return "\n".join(L)


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--prefix", required=True)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--account", required=True)
    ap.add_argument("--region", default="us-west-2")
    ap.add_argument("--dev-scope", default="", help="the stack's DEV_SCOPE; empty for a team stack")
    ap.add_argument("--bedrock-model-id", default=DEFAULT_BEDROCK_MODEL_ID)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-simulate", action="store_true")
    args = ap.parse_args(argv)

    import boto3
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    actual = session.client("sts").get_caller_identity()["Account"]
    if actual != args.account:
        print(f"profile is for account {actual}, not {args.account}", file=sys.stderr)
        return 2
    rv = Review(prefix=args.prefix, account=args.account, region=args.region, dev_scope=args.dev_scope)
    collect(session, rv)
    analyze(rv)
    if not args.no_simulate:
        simulate(session.client("iam"), rv,
                 sim_cases(args.prefix, args.account, args.region, args.dev_scope, args.bedrock_model_id))
    code = 1 if rv.hard else 0
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(rv, code))
    print(f"exit {code}: {len(rv.hard)} hard failure(s), {len(rv.warnings)} warning(s), "
          f"{len(rv.simulation)} simulator case(s) -> {args.out}")
    for i in rv.hard:
        print(f"  HARD {i.rule} {i.role} {i.sid}: {i.message}")
    return code


if __name__ == "__main__":
    sys.exit(main())
