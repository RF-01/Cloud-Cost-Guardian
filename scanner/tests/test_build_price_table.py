"""The price-table generator's parsing, on saved GetProducts samples (scanner/tests/data; no network)."""

import ast
import copy
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import build_price_table as gen  # noqa: E402

SAMPLE = json.loads((Path(__file__).parent / "data" / "price_list_sample.json").read_text(encoding="utf-8"))
EAST, WEST = SAMPLE["us-east-1"], SAMPLE["us-west-2"]


def test_parse_ec2():
    assert gen.parse_ec2(EAST["ec2"]) == {"t3.micro": "0.0104"}
    # Other regions prefix the usage type (USW2-BoxUsage:...).
    assert gen.parse_ec2(WEST["ec2"]) == {"m5.large": "0.096", "t3.micro": "0.0104"}


def test_parse_ec2_skips_zero_and_rejects_conflicts():
    zero = copy.deepcopy(EAST["ec2"][0])
    for term in zero["terms"]["OnDemand"].values():
        for dim in term["priceDimensions"].values():
            dim["pricePerUnit"]["USD"] = "0.0000000000"
    assert gen.parse_ec2([zero]) == {}
    other = copy.deepcopy(EAST["ec2"][0])
    for term in other["terms"]["OnDemand"].values():
        for dim in term["priceDimensions"].values():
            dim["pricePerUnit"]["USD"] = "0.0200000000"
    with pytest.raises(gen.PriceError, match="two different prices"):
        gen.parse_ec2(EAST["ec2"] + [other])


def test_parse_ebs():
    ebs, notes = gen.parse_ebs(EAST["ebs"])
    assert ebs == {
        "ebs": {"gp2": "0.1", "gp3": "0.08", "io1": "0.125", "io2": "0.125", "sc1": "0.015", "st1": "0.045",
                "standard": "0.05"},
        "iops": {"gp3": "0.005", "io1": "0.065", "io2": [[32000, "0.065"], [64000, "0.0455"], [None, "0.03185"]]},
        "gp3_throughput": "0.04",  # 40.96 per GiBps-mo / 1024
        "snapshot": "0.05",        # EBS:SnapshotUsage only: not archive, outposts or under-billing
    }
    assert notes == []


def test_parse_ebs_prefixed_usage_types():
    ebs, _ = gen.parse_ebs(WEST["ebs"])
    assert ebs["snapshot"] == "0.05" and ebs["gp3_throughput"] == "0.04"


def test_parse_ebs_io2_first_tier_only_is_noted():
    only_first = [p for p in EAST["ebs"] if p["product"]["attributes"].get("group") not in
                  ("EBS IOPS Tier 2", "EBS IOPS Tier 3")]
    ebs, notes = gen.parse_ebs(only_first)
    assert ebs["iops"]["io2"] == [[32000, "0.065"], [64000, "0.065"], [None, "0.065"]]
    assert len(notes) == 1 and "io2" in notes[0]


def test_parse_ipv4_and_fallback():
    assert gen.parse_ipv4(EAST["vpc"]) == ({"in_use": "0.005", "idle": "0.005"}, [])
    found, notes = gen.parse_ipv4([])
    assert found == {"in_use": "0.005", "idle": "0.005"} and len(notes) == 2


def test_usage_prefix():
    assert gen._usage({"usagetype": "USW2-EBS:VolumeUsage.gp3"}) == "EBS:VolumeUsage.gp3"
    assert gen._usage({"usagetype": "EBS:VolumeP-IOPS.gp3"}) == "EBS:VolumeP-IOPS.gp3"
    assert gen._usage({"usagetype": "BoxUsage:t3.micro"}) == "BoxUsage:t3.micro"


def table_from_sample():
    ebs, _ = gen.parse_ebs(EAST["ebs"])
    ipv4, _ = gen.parse_ipv4(EAST["vpc"])
    ec2 = {f"t{i}.micro": "0.01" for i in range(gen.MIN_INSTANCE_TYPES)} | gen.parse_ec2(EAST["ec2"])
    return {"us-east-1": {"ec2": ec2, **ebs, "ipv4": ipv4}}


def test_check_passes_and_fails_loudly():
    table = table_from_sample()
    gen.check(table, ["us-east-1"])
    bad = copy.deepcopy(table)
    bad["us-east-1"]["ebs"]["gp3"] = "0.09"
    del bad["us-east-1"]["ebs"]["sc1"]
    bad["us-east-1"]["snapshot"] = None
    with pytest.raises(gen.PriceError) as err:
        gen.check(bad, ["us-east-1", "us-west-2"])
    text = str(err.value)
    for problem in ("regions differ", "['sc1']", "no snapshot price", "gp3: 0.09"):
        assert problem in text


def test_render_is_a_python_literal():
    table = table_from_sample()
    text = gen.render(table, ["us-east-1"], "2026-11-23T00:00:00Z")
    tree = ast.parse(text)
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)}
    assert values == {"GENERATED_AT": "2026-11-23T00:00:00Z", "REGIONS": ["us-east-1"], "PRICES": table}
    assert "Generated: 2026-11-23T00:00:00Z" in text and "Source: AWS Price List API" in text
