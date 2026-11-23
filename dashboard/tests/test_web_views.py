"""Pure view logic of the dashboard (no AWS)."""

from datetime import date, datetime, timezone

import pytest

from dashboard.web import views

NOW = datetime(2026, 11, 23, 18, 0, 0, tzinfo=timezone.utc)
TODAY = date(2026, 11, 23)


def f(rid, ftype="EC2_IDLE", status="open", cost=None, **extra):
    item = {"resourceId": rid, "findingType": ftype, "status": status, "region": "us-west-2"}
    if cost is not None:
        item["estimatedMonthlyCost"] = cost
    item.update(extra)
    return item


# ---------------------------------------------------------------- cost so far


def test_cost_so_far_is_monthly_over_730_times_hours():
    # 7.30 USD/month = 0.01 USD/hour; first seen 100 h before NOW -> 1.00
    assert views.cost_so_far(f("i-1", cost=7.3, firstSeenAt="2026-11-19T14:00:00Z"), NOW) == 1.0
    # 11.24/month for 4.05 h -> 11.24 / 730 * 4.05 = 0.06235... -> 0.06
    assert views.cost_so_far(f("i-2", cost=11.24, firstSeenAt="2026-11-23T13:57:00Z"), NOW) == 0.06
    # 730 USD/month = 1 USD/hour over 48 h
    assert views.cost_so_far(f("i-3", cost=730, firstSeenAt="2026-11-21T18:00:00Z"), NOW) == 48.0


def test_cost_so_far_none_without_estimate_or_start_and_never_negative():
    assert views.cost_so_far(f("i-1", firstSeenAt="2026-11-20T00:00:00Z"), NOW) is None
    assert views.cost_so_far(f("i-1", cost=5), NOW) is None
    assert views.cost_so_far(f("i-1", cost=5, firstSeenAt="garbage"), NOW) is None
    assert views.cost_so_far(f("i-1", cost=5, firstSeenAt="2026-11-24T00:00:00Z"), NOW) == 0


# ---------------------------------------------------------------- findings view


def test_findings_sorted_by_waste_desc_not_estimated_last_and_sections():
    items = [
        f("vol-a", "EBS_UNATTACHED", cost=0.8),
        f("i-big", cost=30),
        f("vol-none", "EBS_UNATTACHED"),
        f("i-fail", status="failed", cost=5, failedStep="StopInstance", errorMessage="boom", restartCount=1),
        f("i-prog", status="in_progress", cost=11.24,
          executionArn="arn:aws:states:us-west-2:123456789012:execution:cg-dev-ec2-timeline:ec2-i-prog-gen1"),
        f("i-rem", status="remediated", cost=9, realizedMonthlySavings=9, dryRun=True),
        f("eip-1", "EIP_UNASSOCIATED", cost=3.65, reportOnlyReason="protected"),
        f("i-res", status="resolved", cost=100),
        f("i-res2", status="resolved"),
    ]
    v = views.findings_view(items, NOW)
    assert [r["resourceId"] for r in v["active"]] == ["i-big", "i-prog", "i-fail", "eip-1", "vol-a", "vol-none"]
    assert [r["resourceId"] for r in v["failed"]] == ["i-fail"]
    assert v["failed"][0]["failedStep"] == "StopInstance" and v["failed"][0]["restartCount"] == 1
    assert [r["resourceId"] for r in v["remediated"]] == ["i-rem"]
    assert [r["resourceId"] for r in v["reportOnly"]] == ["eip-1"]
    assert v["resolvedCount"] == 2
    prog = next(r for r in v["active"] if r["resourceId"] == "i-prog")
    assert prog["executionUrl"].startswith("https://us-west-2.console.aws.amazon.com/states/home?region=us-west-2")
    assert prog["executionUrl"].endswith("arn:aws:states:us-west-2:123456789012:execution:cg-dev-ec2-timeline:"
                                         "ec2-i-prog-gen1")


def test_owner_and_project_defaults():
    row = views.findings_view([f("i-1", cost=1)], NOW)["active"][0]
    assert row["owner"] == "unknown" and row["project"] == "untagged"


def test_execution_link_only_for_in_progress_and_us_west_2_arns():
    arn = "arn:aws:states:us-west-2:1:execution:x:y"
    assert views.execution_url(f("i", status="open", executionArn=arn)) is None
    assert views.execution_url(f("i", status="in_progress", executionArn="javascript:alert(1)")) is None
    assert views.execution_url(f("i", status="in_progress", executionArn="arn:aws:states:us-east-1:1:execution:x:y")) \
        is None
    assert views.execution_url(f("i", status="in_progress")) is None


def test_filters_status_region_owner():
    items = [f("a", cost=1, owner="x@example.com"), f("b", cost=2, region="us-east-1"),
             f("c", status="failed", cost=3, owner="x@example.com"), f("d", status="remediated", cost=4)]
    filt = views.clean_filters({"status": "failed"})
    assert [r["resourceId"] for r in views.findings_view(items, NOW, filt)["active"]] == ["c"]
    filt = views.clean_filters({"region": "us-east-1"})
    assert [r["resourceId"] for r in views.findings_view(items, NOW, filt)["active"]] == ["b"]
    filt = views.clean_filters({"owner": "unknown"})
    v = views.findings_view(items, NOW, filt)
    assert [r["resourceId"] for r in v["active"]] == ["b"] and [r["resourceId"] for r in v["remediated"]] == ["d"]
    assert views.clean_filters({"status": "resolved"})["status"] == ""      # not a filter choice
    assert views.clean_filters({"status": "<x>"})["status"] == ""
    # options come from every non-resolved finding, unfiltered
    assert v["options"]["owner"] == ["unknown", "x@example.com"]


# ---------------------------------------------------------------- KPI choice


def test_kpi_prefers_latest_real_over_newer_sample():
    s = {"2026-11-20": {"day": "2026-11-20", "totalMonthlyWaste": 1},
         "2026-11-22": {"day": "2026-11-22", "totalMonthlyWaste": 9, "sample": True}}
    k = views.kpi_view(s)
    assert k["day"] == "2026-11-20" and k["sample"] is False and k["totalMonthlyWaste"] == 1


def test_kpi_falls_back_to_latest_sample_and_flags_it():
    s = {"2026-11-20": {"day": "2026-11-20", "sample": True, "totalMonthlyWaste": 2},
         "2026-11-21": {"day": "2026-11-21", "sample": True, "totalMonthlyWaste": 3}}
    k = views.kpi_view(s)
    assert k["day"] == "2026-11-21" and k["sample"] is True


def test_kpi_none_when_empty():
    assert views.kpi_view({}) is None


# ---------------------------------------------------------------- summaries / activity / bill


def test_summaries_series_marks_sample_days_and_gaps():
    s = {"2026-11-21": {"day": "2026-11-21", "totalMonthlyWaste": 4, "sample": True,
                        "wasteByRegion": {"us-east-1": 1, "us-west-2": 3}},
         "2026-11-23": {"day": "2026-11-23", "totalMonthlyWaste": 2, "countsByType": {"EC2_IDLE": 1}}}
    v = views.summaries_view(s, TODAY, 7)
    assert v["from"] == "2026-11-17" and v["to"] == "2026-11-23" and len(v["series"]) == 7
    by_day = {p["day"]: p for p in v["series"]}
    assert by_day["2026-11-21"]["sample"] is True and by_day["2026-11-21"]["totalMonthlyWaste"] == 4
    assert by_day["2026-11-22"] == {**by_day["2026-11-22"], "present": False, "totalMonthlyWaste": None}
    assert by_day["2026-11-23"]["sample"] is False
    assert v["sampleInRange"] is True
    assert v["latest"]["day"] == "2026-11-23" and v["latest"]["countsByType"] == [{"label": "EC2_IDLE", "value": 1}]


def test_breakdowns_ranked_desc():
    s = {"2026-11-23": {"day": "2026-11-23", "wasteByRegion": {"a": 1, "b": 3, "c": 2}}}
    assert [i["label"] for i in views.summaries_view(s, TODAY, 7)["latest"]["wasteByRegion"]] == ["b", "c", "a"]


def test_weekly_activity_iso_weeks_counts_and_sample():
    audit = {
        "2026-11-23": [{"event": "finding_opened"}, {"event": "finding_opened", "sample": True},
                       {"event": "notice_sent"}],
        "2026-11-16": [{"event": "finding_opened"}],
    }
    summaries = {"2026-11-23": {"day": "2026-11-23", "warningsSent": 2, "actionsTaken": 1, "actionsTakenDryRun": 1},
                 "2026-11-17": {"day": "2026-11-17", "warningsSent": 1, "actionsTaken": 0, "actionsTakenDryRun": 0,
                                "sample": True}}
    weeks = views.weekly_activity(8, TODAY, audit, summaries)        # 2026-11-23 is a Monday, ISO week 48
    assert len(weeks) == 8 and weeks[-1]["week"] == "2026-W48" and weeks[0]["week"] == "2026-W41"
    assert weeks[-1] == {**weeks[-1], "findingsOpened": 2, "findingsOpenedSample": 1, "warningsSent": 2,
                         "actionsTaken": 1, "actionsTakenDryRun": 1, "sample": True}
    assert weeks[-2] == {**weeks[-2], "week": "2026-W47", "findingsOpened": 1, "warningsSent": 1, "sample": True,
                         "sampleDays": 1}
    assert weeks[0]["sample"] is False and weeks[0]["findingsOpened"] == 0
    assert len(views.week_days(8, TODAY)) == 7 * 7 + 1


def test_recent_activity_newest_first_capped_and_details_text():
    audit = {"2026-11-23": [{"ts": f"2026-11-23T10:00:{i:02d}Z#0000000{i % 10}", "event": "x", "sample": i == 3,
                             "details": {"k": "v"}} for i in range(60)]}
    audit["2026-11-22"] = [{"ts": f"2026-11-22T0{h}:00:00Z#aaaaaaaa", "event": "y"} for h in range(10)] * 20
    rows = views.recent_activity(audit, ["2026-11-22", "2026-11-23"])
    assert len(rows) == views.RECENT_MAX
    assert rows[0]["time"] == "2026-11-23T10:00:59Z" and rows[0]["detailsText"] == '{"k": "v"}'
    assert [r["sample"] for r in rows if r["time"] == "2026-11-23T10:00:03Z"] == [True]


def test_bill_top5_other_projects_untagged_and_totals():
    days = ["2026-11-21", "2026-11-22"]
    rows = {d: [{"key": "total", "amount": 1.5, "estimated": d == "2026-11-22"}] for d in days}
    for i in range(7):
        rows["2026-11-21"].append({"key": f"service#S{i}", "amount": 0.1 * (i + 1)})
    rows["2026-11-21"] += [{"key": "project#untagged", "amount": 1.0}, {"key": "project#alpha", "amount": 0.5}]
    rows["2026-11-22"] += [{"key": "project#alpha", "amount": 0.25}]
    v = views.bill_view(rows, days)
    assert v["total"] == [1.5, 1.5] and v["rangeTotal"] == 3.0 and v["hasData"] is True
    assert [s["name"] for s in v["services"]] == ["S6", "S5", "S4", "S3", "S2", "other"]
    assert v["services"][-1]["amounts"] == [0.3, 0.0]       # S0 0.1 + S1 0.2
    assert v["projects"] == [{"name": "untagged", "total": 1.0}, {"name": "alpha", "total": 0.75}]
    assert v["estimatedDays"] == ["2026-11-22"]
    assert v["label"] == "usage cost before credits, USD/day"


def test_bill_missing_day_is_null_not_zero():
    v = views.bill_view({"2026-11-22": [{"key": "total", "amount": 0}]}, ["2026-11-21", "2026-11-22"])
    assert v["total"] == [None, 0] and v["hasData"] is True


def test_budgets_newest_20():
    alerts = [{"budgetName": "b", "receivedAt": f"2026-11-{d:02d}T00:00:00Z"} for d in range(1, 26)]
    out = views.budgets_view(alerts)
    assert len(out) == 20 and out[0]["receivedAt"] == "2026-11-25T00:00:00Z"


@pytest.mark.parametrize("text,expected", [("2026-11-20T16:30:00Z", (16, 30)), ("nope", None), (None, None)])
def test_parse_time(text, expected):
    dt = views.parse_time(text)
    assert (dt.hour, dt.minute) == expected if expected else dt is None
