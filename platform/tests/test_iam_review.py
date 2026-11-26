"""Tests for platform/tools/iam_review.py (task #39): synthetic policy documents for every rule."""
import copy
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import iam_review as ir  # noqa: E402

ACCT = "111122223333"
REGION = "us-west-2"
PREFIX = "cg-dev-"
TABLE = f"arn:aws:dynamodb:{REGION}:{ACCT}:table/{PREFIX}"


def trust(service="lambda.amazonaws.com", **extra):
    stmt = {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
    stmt.update(extra)
    return {"Version": "2012-10-17", "Statement": [stmt]}


def policy(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def allow(sid, actions, resources, cond=None):
    s = {"Sid": sid, "Effect": "Allow", "Action": actions, "Resource": resources}
    if cond:
        s["Condition"] = cond
    return s


def logs(role):
    return allow("OwnLogs", ["logs:CreateLogStream", "logs:PutLogEvents"],
                 f"arn:aws:logs:{REGION}:{ACCT}:log-group:/aws/lambda/{PREFIX}{role}:*")


PROTECT_DENY = {"Sid": "DenyProtected", "Effect": "Deny", "Action": ["ec2:StopInstances", "ec2:DeleteVolume"],
                "Resource": "*",
                "Condition": {"StringEqualsIgnoreCase": {"aws:ResourceTag/guardian:protect": "true"}}}


def good_remediation():
    return policy(logs("remediation"),
                  allow("Ec2Describe", ["ec2:DescribeInstances", "ec2:DescribeVolumes"], "*"),
                  allow("StopInstances", "ec2:StopInstances", f"arn:aws:ec2:*:{ACCT}:instance/*"),
                  allow("DeleteVolumes", "ec2:DeleteVolume", f"arn:aws:ec2:*:{ACCT}:volume/*"),
                  copy.deepcopy(PROTECT_DENY),
                  allow("WriteAudit", "dynamodb:PutItem", TABLE + "audit"))


def review(roles, dev_scope=""):
    rv = ir.Review(prefix=PREFIX, account=ACCT, region=REGION, dev_scope=dev_scope)
    for short, (tr, inline) in roles.items():
        rv.roles[short] = {"name": f"{PREFIX}{short}-role", "arn": f"arn:aws:iam::{ACCT}:role/{PREFIX}{short}-role",
                           "trust": tr, "inline": {"p": inline}, "attached": [], "instance_profiles": []}
    return ir.analyze(rv)


def rules(issues, role=None):
    return sorted({i.rule for i in issues if role is None or i.role == role})


def base_roles():
    return {"remediation": (trust(), good_remediation())}


# ---------------------------------------------------------------- matching helpers

@pytest.mark.parametrize("a,b,expected", [
    ("*", "ec2:DeleteSnapshot", True),
    ("ec2:*", "ec2:DeleteSnapshot", True),
    ("EC2:delete*", "ec2:DeleteSnapshot", True),
    ("ec2:Delete*", "ec2:DeleteVolume", True),
    ("ec2:Release*", "ec2:ReleaseAddress", True),
    ("ec2:?eleteSnapshot", "ec2:DeleteSnapshot", True),
    ("ec2:Delete*", "ec2:Release*", False),
    ("ec2:DeleteVolume", "ec2:DeleteSnapshot", False),
    ("iam:*", "iam:Create*", True),
    ("iam:ListUserTags", "iam:Create*", False),
    ("s3:Get*", "s3:*Object", True),
])
def test_globs_intersect(a, b, expected):
    assert ir.globs_intersect(a, b) is expected


def test_covered_by_treats_action_wildcards_literally():
    assert ir.covered_by("ec2:DescribeInstances", "ec2:Describe*")
    assert ir.covered_by("ec2:Describe*", "ec2:Describe*")
    assert not ir.covered_by("ec2:*", "ec2:Describe*")
    assert not ir.covered_by("*", "ec2:Describe*")


def test_parse_policy_accepts_strings_and_single_values():
    stmts = ir.parse_policy(json.dumps({"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "x"}}))
    assert stmts[0].actions == ["s3:GetObject"] and stmts[0].resources == ["x"] and stmts[0].sid == "#0"


# ---------------------------------------------------------------- clean baseline

def test_good_remediation_role_passes_everything():
    rv = review(base_roles())
    assert rv.hard == []
    assert "case-insensitively" in rv.h3_note
    assert rv.warnings == []
    assert rules(rv.accepted) == ["W1"]  # Lambda trust without SourceAccount: accepted (#39 review)
    assert "iam:PassRole" in rv.accepted[0].fix


def test_w1_non_lambda_trust_without_source_account_is_a_warning():
    roles = base_roles()
    roles["scheduler"] = (trust("scheduler.amazonaws.com"), policy())
    rv = review(roles)
    assert "W1" in rules(rv.warnings, "scheduler") and "W1" not in rules(rv.accepted, "scheduler")


def test_fixed_engine_statements_have_no_dev_scope_gap():
    """The #39 fixes: dev-scope resource tag on existing resources, request tag on new ones."""
    rt = {"StringEquals": {"ec2:ResourceTag/guardian:dev-scope": PREFIX}}
    rq = {"StringEquals": {"aws:RequestTag/guardian:dev-scope": PREFIX, "ec2:CreateAction": "CreateSnapshot"}}
    doc = good_remediation()
    for s in doc["Statement"]:
        if s.get("Sid") in ("StopInstances", "DeleteVolumes"):
            s["Condition"] = rt
    doc["Statement"] += [allow("CreateSnapshotOfVolume", "ec2:CreateSnapshot", f"arn:aws:ec2:*:{ACCT}:volume/*", rt),
                         allow("CreateSnapshotNew", "ec2:CreateSnapshot", "arn:aws:ec2:*::snapshot/*", rq),
                         allow("TagNewSnapshots", "ec2:CreateTags", "arn:aws:ec2:*::snapshot/*", rq)]
    rv = review({"remediation": (trust(), doc)}, dev_scope=PREFIX)
    assert "W6" not in rules(rv.warnings) and rv.hard == []


def test_w3_leading_keys_with_null_guard_is_clean():
    roles = base_roles()
    roles["ec2-timeline"] = (trust("states.amazonaws.com", Condition={"StringEquals": {"aws:SourceAccount": ACCT}}),
                             policy(allow("U", "dynamodb:UpdateItem", TABLE + "findings",
                                          {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["i-*"]},
                                           "Null": {"dynamodb:LeadingKeys": "false"}})))
    assert review(roles).warnings == []


# ---------------------------------------------------------------- H1

@pytest.mark.parametrize("action", ["*", "ec2:*", "ec2:Delete*", "ec2:Release*", "EC2:DELETESNAPSHOT",
                                    "ec2:ReleaseAddress", "ec2:*Snapshot"])
def test_h1_wildcards_matching_forbidden_actions(action):
    roles = base_roles()
    roles["scanner"] = (trust(), policy(allow("Bad", action, f"arn:aws:ec2:*:{ACCT}:volume/*")))
    rv = review(roles)
    assert "H1" in rules(rv.hard, "scanner")


def test_h1_deny_is_not_an_allow():
    roles = base_roles()
    roles["scanner"] = (trust(), policy({"Sid": "D", "Effect": "Deny", "Action": "ec2:*", "Resource": "*"}))
    assert "H1" not in rules(review(roles).hard)


def test_h1_notaction_allow_matches_unless_excluded():
    roles = base_roles()
    roles["scanner"] = (trust(), policy({"Sid": "N", "Effect": "Allow", "NotAction": "s3:*", "Resource": "x"}))
    rv = review(roles)
    assert "H1" in rules(rv.hard, "scanner") and "H2" in rules(rv.hard, "scanner")
    roles["scanner"] = (trust(), policy({"Sid": "N", "Effect": "Allow",
                                         "NotAction": ["ec2:DeleteSnapshot", "ec2:ReleaseAddress"], "Resource": "x"}))
    rv = review(roles)
    assert "H1" not in rules(rv.hard, "scanner") and "H2" in rules(rv.hard, "scanner")


# ---------------------------------------------------------------- H2

@pytest.mark.parametrize("action,fails", [("*", True), ("s3:*", True), ("s3:Get*", False), ("s3:GetObject", False)])
def test_h2_full_wildcards(action, fails):
    roles = base_roles()
    roles["dashboard"] = (trust("ec2.amazonaws.com"), policy(allow("S", action, "arn:aws:s3:::b/*")))
    assert ("H2" in rules(review(roles).hard, "dashboard")) is fails


# ---------------------------------------------------------------- H3

def test_h3_missing_deny_fails():
    doc = good_remediation()
    doc["Statement"] = [s for s in doc["Statement"] if s.get("Sid") != "DenyProtected"]
    rv = review({"remediation": (trust(), doc)})
    assert "H3" in rules(rv.hard)


def test_h3_case_sensitive_operator_is_reported():
    doc = good_remediation()
    for s in doc["Statement"]:
        if s.get("Sid") == "DenyProtected":
            s["Condition"] = {"StringEquals": {"aws:ResourceTag/guardian:protect": "true"}}
    rv = review({"remediation": (trust(), doc)})
    assert "H3" not in rules(rv.hard) and "case-SENSITIVELY" in rv.h3_note


def test_h3_deny_covering_one_action_only_fails():
    doc = good_remediation()
    for s in doc["Statement"]:
        if s.get("Sid") == "DenyProtected":
            s["Action"] = "ec2:StopInstances"
    rv = review({"remediation": (trust(), doc)})
    assert any(i.rule == "H3" and "DeleteVolume" in i.message for i in rv.hard)


def test_h3_wrong_tag_value_or_allow_effect_fails():
    doc = good_remediation()
    for s in doc["Statement"]:
        if s.get("Sid") == "DenyProtected":
            s["Effect"] = "Allow"
    assert "H3" in rules(review({"remediation": (trust(), doc)}).hard)


def test_h3_missing_role_fails():
    rv = review({"scanner": (trust(), policy(logs("scanner")))})
    assert "H3" in rules(rv.hard)


# ---------------------------------------------------------------- H4

def test_h4_wrong_service_aws_principal_star_and_extra_action():
    roles = base_roles()
    roles["ec2-timeline"] = (trust("lambda.amazonaws.com"), policy())
    roles["scanner"] = (policy({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root",
                                                                 "Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole"}), policy())
    roles["notify"] = (policy({"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}), policy())
    roles["action"] = (trust(Action=["sts:AssumeRole", "sts:TagSession"]), policy())
    rv = review(roles)
    for role in ("ec2-timeline", "scanner", "notify", "action"):
        assert "H4" in rules(rv.hard, role), role


def test_h4_source_account_silences_w1_and_ec2_is_info_only():
    roles = base_roles()
    roles["scheduler"] = (trust("scheduler.amazonaws.com",
                                Condition={"StringEquals": {"aws:SourceAccount": ACCT}}), policy())
    roles["dashboard"] = (trust("ec2.amazonaws.com"), policy())
    rv = review(roles)
    assert rules(rv.hard) == []
    assert "W1" not in rules(rv.warnings, "scheduler") and "W1" not in rules(rv.warnings, "dashboard")
    assert "W1" in rules(rv.info, "dashboard")


def test_unexpected_role_fails():
    roles = base_roles()
    roles["mystery"] = (trust(), policy())
    assert "H4" in rules(review(roles).hard, "mystery")


# ---------------------------------------------------------------- H5

def test_h5_attached_managed_policy():
    rv = ir.Review(prefix=PREFIX, account=ACCT, region=REGION, dev_scope="")
    rv.roles["remediation"] = {"name": "r", "arn": "a", "trust": trust(), "inline": {"p": good_remediation()},
                               "attached": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]}
    assert "H5" in rules(ir.analyze(rv).hard)


@pytest.mark.parametrize("action", ["iam:PassRole", "iam:CreateRole", "iam:Put*", "iam:AttachRolePolicy",
                                    "iam:UpdateAssumeRolePolicy", "iam:DeleteRolePolicy", "sts:AssumeRole", "iam:*"])
def test_h5_escalation_actions(action):
    roles = base_roles()
    roles["scanner"] = (trust(), policy(allow("X", action, f"arn:aws:iam::{ACCT}:role/x")))
    assert "H5" in rules(review(roles).hard, "scanner")


def test_h5_list_user_tags_is_fine():
    roles = base_roles()
    roles["scanner"] = (trust(), policy(allow("T", "iam:ListUserTags", f"arn:aws:iam::{ACCT}:user/*")))
    assert rules(review(roles).hard) == []


# ---------------------------------------------------------------- H6

@pytest.mark.parametrize("resource,fails", [
    (TABLE + "findings", False),
    (TABLE + "audit/index/byDay", False),
    (TABLE + "*", True),
    (f"arn:aws:dynamodb:{REGION}:{ACCT}:table/cg-alice-findings", True),
    (f"arn:aws:dynamodb:us-east-1:{ACCT}:table/{PREFIX}findings", True),
    (f"arn:aws:dynamodb:{REGION}:999999999999:table/{PREFIX}findings", True),
    ("*", True),
])
def test_h6_table_scope(resource, fails):
    roles = base_roles()
    roles["daily-summary"] = (trust(), policy(allow("D", "dynamodb:Query", resource)))
    assert ("H6" in rules(review(roles).hard, "daily-summary")) is fails


def test_h6_dynamodb_star():
    roles = base_roles()
    roles["daily-summary"] = (trust(), policy(allow("D", "dynamodb:*", TABLE + "findings")))
    rv = review(roles)
    assert "H6" in rules(rv.hard, "daily-summary") and "H2" in rules(rv.hard, "daily-summary")


# ---------------------------------------------------------------- H7

@pytest.mark.parametrize("action,fails", [
    ("ec2:DescribeInstances", False), ("ec2:Describe*", False), ("cloudwatch:GetMetricStatistics", False),
    ("ce:GetCostAndUsage", False), ("cloudtrail:LookupEvents", False),
    ("ec2:CreateTags", True), ("cloudwatch:GetMetricData", True), ("s3:GetObject", True),
])
def test_h7_star_resource_allowlist(action, fails):
    roles = base_roles()
    roles["scanner"] = (trust(), policy(allow("S", action, "*")))
    rv = review(roles)
    assert ("H7" in rules(rv.hard, "scanner")) is fails
    if not fails:
        assert any("scanner" in used for used in rv.star_used.values())


def test_h7_not_resource_counts_as_star_and_deny_star_is_fine():
    roles = base_roles()
    roles["scanner"] = (trust(), policy({"Sid": "NR", "Effect": "Allow", "Action": "ec2:CreateTags",
                                         "NotResource": "arn:aws:ec2:*:*:snapshot/*"}))
    assert "H7" in rules(review(roles).hard, "scanner")
    # The remediation's DenyProtected uses Resource * and passes (baseline test).


# ---------------------------------------------------------------- warnings

def test_w3_findings_writes_and_null_guard():
    roles = base_roles()
    roles["scanner"] = (trust(), policy(allow("F", ["dynamodb:UpdateItem"], TABLE + "findings")))
    roles["notify"] = (trust(), policy(allow("N", "dynamodb:UpdateItem", TABLE + "findings",
                                             {"ForAllValues:StringEquals": {"dynamodb:Attributes": ["lastNotifiedAt"]}})))
    roles["ebs-timeline"] = (trust("states.amazonaws.com"), policy(allow(
        "P", "dynamodb:PutItem", TABLE + "findings",
        {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["snap-*"]}, "Null": {"dynamodb:LeadingKeys": "false"}})))
    rv = review(roles)
    scanner = [i for i in rv.warnings if i.role == "scanner" and i.rule == "W3"]
    assert scanner and "no dynamodb:Attributes" in scanner[0].message
    notify = [i for i in rv.warnings if i.role == "notify" and i.rule == "W3"]
    assert notify and "Null guard" in notify[0].message and "dynamodb:Attributes" in notify[0].fix
    assert not [i for i in rv.warnings if i.role == "ebs-timeline" and i.rule == "W3"]


def test_w3_reads_on_findings_are_not_writes():
    roles = base_roles()
    roles["daily-summary"] = (trust(), policy(allow("S", "dynamodb:Scan", TABLE + "findings")))
    assert "W3" not in rules(review(roles).warnings)


def test_w5_logs_beyond_own_group():
    roles = base_roles()
    roles["scanner"] = (trust(), policy(allow("L", ["logs:CreateLogGroup", "logs:PutLogEvents"],
                                              f"arn:aws:logs:{REGION}:{ACCT}:log-group:*")))
    msgs = [i.message for i in review(roles).warnings if i.rule == "W5"]
    assert any("beyond its own log group" in m for m in msgs) and any("CreateLogGroup" in m for m in msgs)


def test_w4_dashboard_scope():
    roles = base_roles()
    doc = good_dashboard()
    doc["Statement"] = [x for x in doc["Statement"] if x["Sid"] not in ("GetOriginSecret",)]
    doc["Statement"] += [allow("SSM", "ssm:GetParameter", f"arn:aws:ssm:{REGION}:{ACCT}:parameter/*"),
                         allow("KMS", "kms:Decrypt", f"arn:aws:kms:{REGION}:{ACCT}:key/abc")]
    roles["dashboard"] = (trust("ec2.amazonaws.com"), doc)
    rv = review(roles)
    sids = {i.sid for i in rv.warnings if i.rule == "W4"}
    assert sids == {"SSM", "KMS"}
    assert any(i.sid == "GetDashboardArtifact" for i in rv.info)


# ---------------------------------------------------------------- dashboard (#43)

DASH_MODEL = "us.amazon.nova-2-lite-v1:0"
COUNTER_CONDITIONS = {
    "ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["bedrock#*"]},
    "ForAllValues:StringEquals": {"dynamodb:Attributes": ["counterId", "count", "ttl"]},
    "Null": {"dynamodb:LeadingKeys": "false", "dynamodb:Attributes": "false"},
    "StringEqualsIfExists": {"dynamodb:ReturnValues": ["NONE", "UPDATED_NEW"]},
}


def good_dashboard():
    """Mirrors dashboard/terraform/web.tf (the instance role) after #43."""
    fm = [f"arn:aws:bedrock:{r}::foundation-model/amazon.nova-2-lite-v1:0"
          for r in ("us-east-1", "us-east-2", "us-west-2")]
    return policy(
        allow("ScanFindings", "dynamodb:Scan", TABLE + "findings"),
        allow("QueryAuditByDay", "dynamodb:Query", TABLE + "audit/index/byDay"),
        allow("BatchGetDailySummaries", "dynamodb:BatchGetItem", TABLE + "daily-summaries"),
        allow("QueryBillHistory", "dynamodb:Query", TABLE + "bill-history"),
        allow("ScanBudgetAlerts", "dynamodb:Scan", TABLE + "budget-alerts"),
        allow("UpdateBedrockCounter", "dynamodb:UpdateItem", TABLE + "counters", copy.deepcopy(COUNTER_CONDITIONS)),
        allow("InvokeConfiguredModel", "bedrock:InvokeModel",
              [f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/{DASH_MODEL}"] + fm),
        allow("ViewBudgets", "budgets:ViewBudget", f"arn:aws:budgets::{ACCT}:budget/*"),
        allow("GetDashboardArtifact", "s3:GetObject", f"arn:aws:s3:::{PREFIX}dashboard-artifacts-{ACCT}/dashboard-web/*"),
        allow("GetOriginSecret", "ssm:GetParameter", f"arn:aws:ssm:{REGION}:{ACCT}:parameter/{PREFIX}dashboard/origin-secret"),
    )


def dash_review(doc):
    return review({**base_roles(), "dashboard": (trust("ec2.amazonaws.com"), doc)})


def test_w4_good_dashboard_policy_is_clean():
    rv = dash_review(good_dashboard())
    assert [(i.rule, i.sid, i.message) for i in rv.hard + rv.warnings if i.role == "dashboard"] == []
    info = " | ".join(i.message for i in rv.info if i.role == "dashboard")
    assert "bedrock:InvokeModel limited to the configured profile" in info
    assert f"budgets:ViewBudget limited to arn:aws:budgets::{ACCT}:budget/*" in info
    assert "No bedrock:InvokeModel yet" not in info


def test_dashboard_design_note_mentions_43():
    note = ir.DESIGN_NOTES["dashboard"]
    assert "#43" in note and "bedrock#*" in note and "budgets:ViewBudget" in note and "yet" not in note


@pytest.mark.parametrize("drop,needle", [
    ("InvokeConfiguredModel", "No bedrock:InvokeModel"),
    ("ViewBudgets", "No budgets:ViewBudget"),
    ("UpdateBedrockCounter", "No UpdateItem on counters"),
])
def test_w4_dashboard_missing_parts_warn(drop, needle):
    doc = good_dashboard()
    doc["Statement"] = [x for x in doc["Statement"] if x["Sid"] != drop]
    msgs = [i.message for i in dash_review(doc).warnings if i.rule == "W4"]
    assert any(needle in m for m in msgs), msgs


def _without(conditions, op, key):
    out = copy.deepcopy(conditions)
    del out[op][key]
    return {k: v for k, v in out.items() if v}


@pytest.mark.parametrize("stmt,needle", [
    (allow("X", "bedrock:InvokeModel", f"arn:aws:bedrock:{REGION}::foundation-model/amazon.nova-pro-v1:0"),
     "beyond the configured profile"),
    (allow("X", "bedrock:InvokeModel", f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/*"),
     "beyond the configured profile"),
    (allow("X", "bedrock:InvokeModelWithResponseStream",
           f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/{DASH_MODEL}"), "besides InvokeModel"),
    (allow("X", "budgets:ModifyBudget", f"arn:aws:budgets::{ACCT}:budget/*"), "besides ViewBudget"),
    (allow("X", "budgets:ViewBudget", "arn:aws:budgets::999999999999:budget/*"), "beyond this account's budgets"),
    (allow("X", "dynamodb:PutItem", TABLE + "counters"), "beyond UpdateItem on counters"),
    (allow("X", "dynamodb:UpdateItem", TABLE + "findings", copy.deepcopy(COUNTER_CONDITIONS)),
     "beyond UpdateItem on counters"),
    (allow("X", "dynamodb:UpdateItem", TABLE + "counters",
           _without(COUNTER_CONDITIONS, "Null", "dynamodb:LeadingKeys")), "dynamodb:LeadingKeys without a Null guard"),
    (allow("X", "dynamodb:UpdateItem", TABLE + "counters",
           _without(COUNTER_CONDITIONS, "Null", "dynamodb:Attributes")), "dynamodb:Attributes without a Null guard"),
    (allow("X", "dynamodb:UpdateItem", TABLE + "counters",
           _without(COUNTER_CONDITIONS, "ForAllValues:StringLike", "dynamodb:LeadingKeys")),
     "without dynamodb:LeadingKeys"),
    (allow("X", "dynamodb:UpdateItem", TABLE + "counters",
           _without(COUNTER_CONDITIONS, "ForAllValues:StringEquals", "dynamodb:Attributes")),
     "without dynamodb:Attributes"),
    (allow("X", "dynamodb:UpdateItem", TABLE + "counters",
           {**copy.deepcopy(COUNTER_CONDITIONS),
            "ForAllValues:StringEquals": {"dynamodb:Attributes": ["counterId", "count", "ttl", "foo"]}}),
     "dynamodb:Attributes condition is"),
])
def test_w4_dashboard_scope_warnings(stmt, needle):
    doc = good_dashboard()
    doc["Statement"].append(stmt)
    rv = dash_review(doc)
    w4 = [i for i in rv.warnings if i.rule == "W4" and i.role == "dashboard"]
    assert w4 and any(needle in i.message for i in w4), [i.message for i in rv.warnings]
    assert all(i.sid == "X" for i in w4)


def test_w4_budgets_star_is_a_hard_failure_too():
    doc = good_dashboard()
    doc["Statement"].append(allow("X", "budgets:ViewBudget", "*"))
    rv = dash_review(doc)
    assert "H7" in rules(rv.hard, "dashboard")
    assert any(i.sid == "X" and "beyond this account's budgets" in i.message for i in rv.warnings)


def test_sim_cases_for_dashboard():
    cases = {c.label: c for c in ir.sim_cases(PREFIX, ACCT, REGION, PREFIX, DASH_MODEL) if c.role == "dashboard"}
    profile = cases[f"bedrock:InvokeModel on configured profile {DASH_MODEL}"]
    assert profile.expect == ir.ALLOWED
    assert profile.resource == f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/{DASH_MODEL}"
    assert cases["bedrock:InvokeModel on amazon.nova-pro-v1:0"].expect == ir.DENIED
    ok = cases["UpdateItem counters [bedrock#2026-11-26] attributes [count, ttl]"]
    assert ok.expect == ir.ALLOWED and ok.resource == TABLE + "counters"
    assert ok.context["dynamodb:LeadingKeys"] == ["bedrock#2026-11-26"]
    assert ok.context["dynamodb:Attributes"] == ["count", "ttl"]
    for label in ("UpdateItem counters [other#x] attributes [count, ttl]",
                  "UpdateItem counters [bedrock#2026-11-26] attributes [foo]",
                  "UpdateItem counters, no LeadingKeys / Attributes keys", "PutItem counters",
                  f"budgets:ModifyBudget on {PREFIX}account-monthly", "PutItem findings", "UpdateItem findings"):
        assert cases[label].expect == ir.DENIED, label
    view = cases[f"budgets:ViewBudget on {PREFIX}account-monthly"]
    assert view.expect == ir.ALLOWED and view.resource == f"arn:aws:budgets::{ACCT}:budget/{PREFIX}account-monthly"
    assert all(c.expect is not ir.INFO for c in cases.values())


@pytest.mark.parametrize("cond,warns", [
    (None, True),
    ({"StringEquals": {"ec2:ResourceTag/guardian:dev-scope": PREFIX}}, False),
    ({"StringEquals": {"aws:ResourceTag/guardian:dev-scope": PREFIX}}, False),
    ({"StringEquals": {"aws:RequestTag/guardian:dev-scope": PREFIX}}, False),
    ({"StringEquals": {"ec2:ResourceTag/guardian:dev-scope": "cg-alice-"}}, True),
    ({"StringEquals": {"aws:RequestTag/guardian:restored-from": PREFIX}}, True),
])
def test_w6_dev_scope(cond, warns):
    roles = base_roles()
    roles["action"] = (trust(), policy(allow("C", "ec2:CreateVolume", f"arn:aws:ec2:*:{ACCT}:volume/*", cond)))
    rv = review(roles, dev_scope=PREFIX)
    assert ("W6" in rules(rv.warnings, "action")) is warns


def test_w6_only_with_dev_scope_and_ignores_reads():
    rv = review(base_roles(), dev_scope="")
    assert "W6" not in rules(rv.warnings)
    rv = review(base_roles(), dev_scope=PREFIX)
    w6 = {i.sid for i in rv.warnings if i.rule == "W6"}
    assert w6 == {"StopInstances", "DeleteVolumes"}  # not Ec2Describe, not the Deny
    assert all(i.fix.startswith("engine/terraform/remediation.tf") for i in rv.warnings if i.rule == "W6")


def test_resource_policies_w2_w7():
    rv = ir.Review(prefix=PREFIX, account=ACCT, region=REGION, dev_scope="")
    rv.resource_policies = [
        {"kind": "lambda", "name": "fn-a", "note": "", "policy": policy(
            {"Sid": "NoSource", "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
             "Action": "lambda:InvokeFunction", "Resource": "x"})},
        {"kind": "lambda", "name": "fn-b", "note": "", "policy": policy(
            {"Sid": "Arn", "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
             "Action": "lambda:InvokeFunction", "Resource": "x",
             "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:sns:us-west-2:1:t"}}})},
        {"kind": "sns", "name": "topic", "note": "", "policy": policy(
            {"Sid": "Open", "Effect": "Allow", "Principal": "*", "Action": "sns:Publish", "Resource": "t"},
            {"Sid": "Foreign", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
             "Action": "sns:Publish", "Resource": "t"})},
        {"kind": "s3", "name": "bucket", "note": "", "policy": policy(
            {"Sid": "DenyNonTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "b",
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}})},
        {"kind": "sqs", "name": "dlq", "note": "no queue policy", "policy": None},
    ]
    ir.check_resource_policies(rv)
    got = {(i.rule, i.role, i.sid) for i in rv.warnings}
    assert got == {("W2", "fn-a", "NoSource"), ("W7", "topic", "Open"), ("W7", "topic", "Foreign")}
    assert ("W2", "fn-b", "Arn") in {(i.rule, i.role, i.sid) for i in rv.info}


# ---------------------------------------------------------------- simulator

class FakeIam:
    """Returns a decision per (role arn, action, resource) from a function."""

    def __init__(self, decide):
        self.decide = decide
        self.calls = []

    def simulate_principal_policy(self, **kw):
        self.calls.append(kw)
        decision = self.decide(kw)
        if isinstance(decision, Exception):
            raise decision
        return {"EvaluationResults": [{"EvalDecision": decision,
                                       "MatchedStatements": [{"SourcePolicyId": "p"}]}]}


def _sim_review():
    roles = {short: (trust(svc), policy()) for short, svc in ir.EXPECTED_ROLES.items()}
    roles["remediation"] = (trust(), good_remediation())
    return review(roles, dev_scope=PREFIX)


def test_sim_cases_cover_the_task_list():
    cases = ir.sim_cases(PREFIX, ACCT, REGION, PREFIX)
    by_role = {}
    for c in cases:
        by_role.setdefault(c.role, []).append(c)
    assert set(by_role) == set(ir.EXPECTED_ROLES)
    for role in ir.EXPECTED_ROLES:  # every role: DeleteSnapshot / ReleaseAddress denied
        acts = {c.action for c in by_role[role] if c.expect == ir.DENIED}
        assert {"ec2:DeleteSnapshot", "ec2:ReleaseAddress"} <= acts
    protect = [c for c in by_role["remediation"] if c.expect == ir.EXPLICIT]
    assert {c.context["aws:ResourceTag/guardian:protect"] for c in protect} == {"true", "TRUE", "True"}
    assert not any(c.label.endswith("another dev scope") for c in ir.sim_cases(PREFIX, ACCT, REGION, ""))


def test_context_entries_types():
    entries = ir._context_entries({"aws:TagKeys": ["owner"], "aws:RequestTag/owner": "x"})
    assert entries[0]["ContextKeyType"] == "stringList" and entries[0]["ContextKeyValues"] == ["owner"]
    assert entries[1]["ContextKeyType"] == "string" and entries[1]["ContextKeyValues"] == ["x"]


def test_simulate_ok_unexpected_info_and_errors():
    rv = _sim_review()
    cases = [
        ir.SimCase("remediation", "ok", "ec2:DeleteSnapshot", "*", {}, ir.DENIED),
        ir.SimCase("remediation", "bad", "ec2:StopInstances", "arn:i", {"k": "v"}, ir.EXPLICIT),
        ir.SimCase("remediation", "info", "ec2:StopInstances", "arn:i", {}, ir.INFO),
        ir.SimCase("remediation", "boom", "ec2:Foo", "*", {}, ir.ALLOWED),
        ir.SimCase("no-such-role", "skipped", "x:y", "*", {}, ir.ALLOWED),
    ]

    def decide(kw):
        if kw["ActionNames"] == ["ec2:Foo"]:
            return RuntimeError("cannot evaluate")
        return "implicitDeny" if kw["ActionNames"] == ["ec2:DeleteSnapshot"] else "allowed"

    fake = FakeIam(decide)
    ir.simulate(fake, rv, cases)
    status = [r["status"] for r in rv.simulation]
    assert status[0] == "OK" and status[1] == "UNEXPECTED" and status[2] == "INFO"
    assert status[3].startswith("NOT EVALUATED") and status[4].startswith("SKIPPED")
    sim_failures = [i.message for i in rv.hard if i.rule == "SIM"]
    assert len(sim_failures) == 2
    assert fake.calls[1]["ContextEntries"] == [{"ContextKeyName": "k", "ContextKeyValues": ["v"],
                                                 "ContextKeyType": "string"}]
    assert fake.calls[0]["PolicySourceArn"].endswith(f"role/{PREFIX}remediation-role")


# ---------------------------------------------------------------- collection, report, CLI

class _NotFound(Exception):
    pass


class FakeSession:
    """Read-only AWS calls the collector makes; records every operation name."""

    def __init__(self, roles, function_policies):
        self.roles = roles
        self.function_policies = function_policies
        self.ops = []

    def client(self, name, region_name=None):
        return _FakeClient(self, name)


class _Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kw):
        return self.pages(**kw)


class _FakeClient:
    def __init__(self, session, name):
        self.s, self.name = session, name
        self.exceptions = type("E", (), {"ResourceNotFoundException": _NotFound})

    def get_paginator(self, op):
        self.s.ops.append(f"{self.name}:{op}")
        if op == "list_roles":
            return _Pager(lambda: [{"Roles": [{"RoleName": n} for n in self.s.roles] + [{"RoleName": "other-role"}]}])
        if op == "list_role_policies":
            return _Pager(lambda RoleName: [{"PolicyNames": ["p"]}])
        if op == "list_attached_role_policies":
            return _Pager(lambda RoleName: [{"AttachedPolicies": []}])
        if op == "list_functions":
            return _Pager(lambda: [{"Functions": [{"FunctionName": f} for f in self.s.function_policies]}])
        raise AssertionError(op)

    def __getattr__(self, op):
        def call(**kw):
            self.s.ops.append(f"{self.name}:{op}")
            if op == "get_role":
                return {"Role": {"Arn": f"arn:aws:iam::{ACCT}:role/{kw['RoleName']}",
                                 "AssumeRolePolicyDocument": self.s.roles[kw["RoleName"]][0]}}
            if op == "get_role_policy":
                return {"PolicyDocument": self.s.roles[kw["RoleName"]][1]}
            if op == "list_instance_profiles_for_role":
                return {"InstanceProfiles": []}
            if op == "get_policy":
                pol = self.s.function_policies[kw["FunctionName"]]
                if pol is None:
                    raise _NotFound()
                return {"Policy": json.dumps(pol)}
            if op == "get_topic_attributes":
                return {"Attributes": {"Policy": json.dumps(policy())}}
            if op == "get_bucket_policy":
                raise RuntimeError("NoSuchBucketPolicy")
            if op == "get_queue_url":
                return {"QueueUrl": "https://q"}
            if op == "get_queue_attributes":
                return {"Attributes": {}}
            raise AssertionError(op)
        return call


def test_collect_is_read_only_and_reports_missing_roles():
    roles = {f"{PREFIX}remediation-role": (trust(), good_remediation()),
             f"{PREFIX}extra-role": (trust(), policy())}
    session = FakeSession(roles, {f"{PREFIX}remediation": None})
    rv = ir.Review(prefix=PREFIX, account=ACCT, region=REGION, dev_scope="")
    ir.collect(session, rv)
    assert set(rv.roles) == {"remediation", "extra"}
    assert rv.extra_roles == ["extra"] and "scanner" in rv.missing_roles and "digest" in rv.missing_roles
    assert rv.not_deployed == []  # the digest is an expected role since #42
    assert all(op.split(":")[1].startswith(("get_", "list_")) for op in session.ops), session.ops
    kinds = {rp["kind"]: rp for rp in rv.resource_policies}
    assert kinds["lambda"]["policy"] is None and kinds["s3"]["policy"] is None and kinds["sqs"]["policy"] is None


def test_render_contains_sections():
    rv = _sim_review()
    ir.simulate(FakeIam(lambda kw: "implicitDeny"), rv, ir.sim_cases(PREFIX, ACCT, REGION, PREFIX)[:3])
    text = ir.render(rv, 0)
    for heading in ("## Hard failures", "## Warnings", "## Resource * allowlist (H7)", "## Roles",
                    "## Resource policies", "## IAM policy simulator", "## Design §16.1 vs live"):
        assert heading in text
    assert f"### {PREFIX}remediation-role" in text and "DenyProtected" in text


def test_design_diff_flags_new_and_missing_actions():
    roles = base_roles()
    roles["daily-cost"] = (trust(), policy(allow("CE", "ce:GetCostAndUsage", "*"),
                                           allow("DLQ", "sqs:SendMessage", f"arn:aws:sqs:{REGION}:{ACCT}:{PREFIX}dlq")))
    rows = {r[0]: r for r in ir.design_diff(review(roles))}
    assert rows["daily-cost"][1] == ["sqs:SendMessage"] and rows["daily-cost"][2] == ["ce:GetCostForecast"]
    assert rows["digest"][2] == ["(role not deployed)"]


# ---------------------------------------------------------------- digest (#42)

MODEL = "us.amazon.nova-2-lite-v1:0"


def good_digest():
    """Mirrors dashboard/terraform/digest.tf."""
    fm = [f"arn:aws:bedrock:{r}::foundation-model/amazon.nova-2-lite-v1:0"
          for r in ("us-east-1", "us-east-2", "us-west-2")]
    return policy(logs("digest"),
                  allow("ScanFindingsAndBudgetAlerts", "dynamodb:Scan", [TABLE + "findings", TABLE + "budget-alerts"]),
                  allow("InvokeNotify", "lambda:InvokeFunction", f"arn:aws:lambda:{REGION}:{ACCT}:function:{PREFIX}notify"),
                  allow("InvokeConfiguredModel", "bedrock:InvokeModel",
                        [f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/{MODEL}"] + fm),
                  allow("DeadLetterQueue", "sqs:SendMessage", f"arn:aws:sqs:{REGION}:{ACCT}:{PREFIX}dlq"))


def test_digest_is_an_expected_lambda_role():
    assert ir.EXPECTED_ROLES["digest"] == "lambda.amazonaws.com" and "digest" not in ir.OPTIONAL_ROLES
    assert "Not deployed" not in ir.DESIGN_NOTES["digest"] and "budget-alerts" in ir.DESIGN_NOTES["digest"]


def test_w8_good_digest_policy_is_clean():
    rv = ir.analyze(review({"digest": (trust(), good_digest())}))
    assert [i for i in rv.hard + rv.warnings if i.role == "digest"] == []


@pytest.mark.parametrize("stmt,needle", [
    (allow("B", "bedrock:InvokeModel", f"arn:aws:bedrock:{REGION}::foundation-model/*"), "beyond the configured"),
    (allow("B", "bedrock:InvokeModel", f"arn:aws:bedrock:{REGION}::foundation-model/amazon.nova-pro-v1:0"),
     "beyond the configured"),
    (allow("B", "bedrock:InvokeModel", f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/us.amazon.nova-pro-v1:0"),
     "beyond the configured"),
    (allow("B", "bedrock:InvokeModel", f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/*"),
     "beyond the configured"),
    (allow("B", "bedrock:InvokeModelWithResponseStream",
           f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/{MODEL}"), "besides InvokeModel"),
    (allow("L", "lambda:InvokeFunction", f"arn:aws:lambda:{REGION}:{ACCT}:function:{PREFIX}scanner"), "beyond Notify"),
    (allow("L", "lambda:InvokeFunction", f"arn:aws:lambda:{REGION}:{ACCT}:function:{PREFIX}*"), "beyond Notify"),
    (allow("D", ["dynamodb:Scan", "dynamodb:PutItem"], TABLE + "findings"), "other than Scan"),
    (allow("D", "dynamodb:Scan", TABLE + "audit"), "beyond findings / budget-alerts"),
])
def test_w8_digest_scope_warnings(stmt, needle):
    doc = good_digest()
    doc["Statement"].append(stmt)
    rv = ir.analyze(review({"digest": (trust(), doc)}))
    w8 = [i for i in rv.warnings if i.rule == "W8"]
    assert w8 and any(needle in i.message for i in w8), [i.message for i in rv.warnings]
    assert all(i.sid == stmt["Sid"] for i in w8)


def test_w8_uses_the_configured_model_id():
    rv = review({"digest": (trust(), good_digest())})
    rv.bedrock_model_id = "us.amazon.nova-pro-v1:0"
    ir.analyze(rv)
    assert {i.sid for i in rv.warnings if i.rule == "W8"} == {"InvokeConfiguredModel"}


def test_sim_cases_for_digest_and_scheduler():
    cases = {(c.role, c.label): c for c in ir.sim_cases(PREFIX, ACCT, REGION, PREFIX, MODEL)}
    profile = cases[("digest", f"bedrock:InvokeModel on configured profile {MODEL}")]
    assert profile.expect == ir.ALLOWED
    assert profile.resource == f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/{MODEL}"
    expected = {
        "bedrock:InvokeModel on amazon.nova-pro-v1:0": ir.DENIED,
        f"InvokeFunction {PREFIX}notify": ir.ALLOWED,
        f"InvokeFunction {PREFIX}scanner": ir.DENIED,
        "PutItem findings": ir.DENIED,
        "Scan audit": ir.DENIED,
    }
    for label, exp in expected.items():
        assert cases[("digest", label)].expect == exp, label
    assert cases[("digest", "Scan audit")].resource.endswith(f"table/{PREFIX}audit")
    assert cases[("scheduler", f"InvokeFunction {PREFIX}digest")].expect == ir.ALLOWED


def test_main_refuses_wrong_account(monkeypatch, tmp_path):
    class Sts:
        def get_caller_identity(self):
            return {"Account": "999999999999"}

    class Session:
        def __init__(self, **kw):
            pass

        def client(self, name, **kw):
            return Sts()

    import types
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(Session=Session))
    assert ir.main(["--prefix", PREFIX, "--account", ACCT, "--out", str(tmp_path / "r.md")]) == 2
    assert not (tmp_path / "r.md").exists()
