"""The committed, generated price table (scanner/src/scanner/prices_data.py)."""

import re
from decimal import Decimal

from scanner import pricing, prices_data
from scanner.prices_data import PRICES

# Regions enabled by default (describe-regions, opt-in-not-required) when the table was generated.
ENABLED = {"ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-southeast-1", "ap-southeast-2",
           "ca-central-1", "eu-central-1", "eu-north-1", "eu-west-1", "eu-west-2", "eu-west-3", "sa-east-1",
           "us-east-1", "us-east-2", "us-west-1", "us-west-2"}
VOLUME_TYPES = {"gp2", "gp3", "io1", "io2", "st1", "sc1", "standard"}


def test_every_enabled_region_present():
    assert set(PRICES) == ENABLED == set(prices_data.REGIONS)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", prices_data.GENERATED_AT)


def test_us_east_1_sanity_values():
    east = PRICES["us-east-1"]
    assert Decimal(east["ec2"]["t3.micro"]) == Decimal("0.0104")
    assert Decimal(east["ebs"]["gp3"]) == Decimal("0.08")
    assert Decimal(east["ebs"]["gp2"]) == Decimal("0.10")
    assert Decimal(east["snapshot"]) == Decimal("0.05")
    assert Decimal(east["ipv4"]["in_use"]) == Decimal(east["ipv4"]["idle"]) == Decimal("0.005")


def test_every_region_is_complete():
    for region, p in PRICES.items():
        assert len(p["ec2"]) >= 300, region
        assert set(p["ebs"]) == VOLUME_TYPES, region
        assert set(p["iops"]) == {"gp3", "io1", "io2"}, region
        assert [t[0] for t in p["iops"]["io2"]] == [32000, 64000, None], region
        assert Decimal(p["gp3_throughput"]) > 0 and Decimal(p["snapshot"]) > 0, region
        assert set(p["ipv4"]) == {"in_use", "idle"}, region
        prices = list(p["ec2"].values()) + list(p["ebs"].values()) + [p["snapshot"], p["gp3_throughput"]]
        assert all(isinstance(v, str) and Decimal(v) > 0 for v in prices), region


def test_real_table_estimates():
    t3 = {"InstanceId": "i-1", "InstanceType": "t3.micro", "PlatformDetails": "Linux/UNIX"}
    assert pricing.estimate("ec2", "us-east-1", t3) == Decimal("7.59")
    assert pricing.estimate("eip", "us-west-2", {"AllocationId": "eipalloc-1"}) == Decimal("3.65")
    assert pricing.estimate("ebs", "us-west-2", {"VolumeType": "gp3", "Size": 8}) == Decimal("0.64")
    assert pricing.estimate_snapshot("us-west-2", 8) == Decimal("0.40")
