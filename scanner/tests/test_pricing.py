"""pricing.estimate / estimate_snapshot with a small injected table (design §11.1, CONTRACT §3.1)."""

import json
from decimal import Decimal

import pytest

from scanner import pricing

TABLE = {
    "r-1": {
        "ec2": {"t3.micro": "0.0104", "m5.large": "0.096", "odd.type": "0.0123456"},
        "ebs": {"gp2": "0.1", "gp3": "0.08", "io1": "0.125", "io2": "0.125", "st1": "0.045", "sc1": "0.015",
                "standard": "0.05"},
        "iops": {"gp3": "0.005", "io1": "0.065", "io2": [[32000, "0.065"], [64000, "0.0455"], [None, "0.03185"]]},
        "gp3_throughput": "0.04",
        "snapshot": "0.05",
        "ipv4": {"in_use": "0.005", "idle": "0.005"},
    },
}


def eni(owner, ip):
    return {"Association": {"IpOwnerId": owner, "PublicIp": ip}}


def inst(itype="t3.micro", platform="Linux/UNIX", enis=()):
    out = {"InstanceId": "i-1", "InstanceType": itype, "NetworkInterfaces": list(enis)}
    if platform is not None:
        out["PlatformDetails"] = platform
    return out


def est(rtype, resource, region="r-1"):
    return pricing.estimate(rtype, region, resource, table=TABLE)


def unknown_reasons(capsys):
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert all(r["action"] == "price_unknown" and r["result"] == "skipped" for r in lines)
    return [r["reason"] for r in lines]


# ---------------------------------------------------------------- EC2

@pytest.mark.parametrize("enis,expected", [
    ((), "7.59"),                                                          # 0.0104 x 730 = 7.592
    ((eni("amazon", "3.1.1.1"),), "11.24"),                                # + 0.005 x 730 = 3.65
    ((eni("amazon", "3.1.1.1"), eni("amazon", "3.1.1.2")), "14.89"),       # two auto-assigned IPv4
    ((eni("123456789012", "52.0.0.1"),), "7.59"),                          # Elastic IP: own finding, not counted
    ((eni("amazon", "3.1.1.1"), eni("123456789012", "52.0.0.1")), "11.24"),
    (({"PrivateIpAddress": "10.0.0.5"},), "7.59"),                         # no public IP
])
def test_ec2_compute_plus_auto_assigned_ipv4(enis, expected):
    assert est("ec2", inst(enis=enis)) == Decimal(expected)


def test_ec2_same_auto_ip_counted_once():
    assert est("ec2", inst(enis=[eni("amazon", "3.1.1.1"), eni("amazon", "3.1.1.1")])) == Decimal("11.24")


@pytest.mark.parametrize("platform", ["Windows", "Red Hat Enterprise Linux", "Linux with SQL Server Standard", None])
def test_ec2_other_platforms_not_priced(platform, capsys):
    assert est("ec2", inst(platform=platform)) is None
    [reason] = unknown_reasons(capsys)
    assert "platform" in reason


def test_ec2_unknown_type_or_region(capsys):
    assert est("ec2", inst(itype="zz9.huge")) is None
    assert est("ec2", inst(), region="xx-nowhere-1") is None
    first, second = unknown_reasons(capsys)
    assert "zz9.huge" in first and "xx-nowhere-1" in second


# ---------------------------------------------------------------- EBS

def vol(vtype, size, iops=None, throughput=None):
    out = {"VolumeId": "vol-1", "VolumeType": vtype, "Size": size}
    if iops is not None:
        out["Iops"] = iops
    if throughput is not None:
        out["Throughput"] = throughput
    return out


@pytest.mark.parametrize("volume,expected", [
    (vol("gp2", 100, iops=300), "10.00"),
    (vol("gp3", 100, iops=3000, throughput=125), "8.00"),                  # baseline: no extra
    (vol("gp3", 100), "8.00"),                                             # Iops / Throughput absent = baseline
    (vol("gp3", 100, iops=6000, throughput=125), "23.00"),                 # + 3,000 x 0.005
    (vol("gp3", 100, iops=3000, throughput=250), "13.00"),                 # + 125 MiB/s x 0.04
    (vol("gp3", 100, iops=16000, throughput=1000), "108.00"),              # 8 + 65 + 35
    (vol("io1", 100, iops=1000), "77.50"),                                 # 12.5 + 1,000 x 0.065
    (vol("io2", 100, iops=1000), "77.50"),                                 # first tier
    (vol("io2", 100, iops=40000), "2456.50"),                              # 12.5 + 32000x0.065 + 8000x0.0455
    (vol("io2", 100, iops=70000), "3739.60"),                              # ... + 32000x0.0455 + 6000x0.03185
    (vol("st1", 500), "22.50"),
    (vol("sc1", 500), "7.50"),
    (vol("standard", 10), "0.50"),
])
def test_ebs(volume, expected):
    assert est("ebs", volume) == Decimal(expected)


def test_ebs_unknown_type_region_or_size(capsys):
    assert est("ebs", vol("gp9", 10)) is None
    assert est("ebs", vol("gp3", 10), region="xx-nowhere-1") is None
    assert est("ebs", {"VolumeId": "vol-1", "VolumeType": "gp3"}) is None
    assert len(unknown_reasons(capsys)) == 3


# ---------------------------------------------------------------- EIP, snapshot, rounding, never raises

@pytest.mark.parametrize("addr", [{"AllocationId": "eipalloc-1"},
                                  {"AllocationId": "eipalloc-1", "AssociationId": "eipassoc-1"}])
def test_eip(addr):
    assert est("eip", addr) == Decimal("3.65")


def test_snapshot_is_size_times_gb_month():
    assert pricing.estimate_snapshot("r-1", 100, table=TABLE) == Decimal("5.00")
    assert pricing.estimate_snapshot("r-1", 8, table=TABLE) == Decimal("0.40")


def test_snapshot_unknown(capsys):
    assert pricing.estimate_snapshot("xx-nowhere-1", 8, table=TABLE, resource_id="vol-9") is None
    assert pricing.estimate_snapshot("r-1", None, table=TABLE) is None
    assert len(unknown_reasons(capsys)) == 2


def test_rounding_to_two_places():
    value = est("ec2", inst(itype="odd.type"))  # 0.0123456 x 730 = 9.012288
    assert value == Decimal("9.01") and value.as_tuple().exponent == -2
    assert est("ebs", vol("sc1", 1)).as_tuple().exponent == -2           # 0.015 -> 0.02 (half up)
    assert est("ebs", vol("sc1", 1)) == Decimal("0.02")


def test_never_raises(capsys):
    broken = {"r-1": {"ec2": {"t3.micro": "not-a-number"}, "ipv4": {}}}
    assert pricing.estimate("ec2", "r-1", inst(), table=broken) is None
    assert pricing.estimate("ec2", "r-1", None, table=TABLE) is None
    assert pricing.estimate("rds", "r-1", {}, table=TABLE) is None
    assert pricing.estimate("ebs", "r-1", vol("gp3", "ten"), table=TABLE) is None
    reasons = unknown_reasons(capsys)
    assert len(reasons) == 4 and reasons[0].startswith("error:")


def test_unknown_log_line_names_the_resource(capsys):
    est("ebs", vol("gp9", 10))
    [line] = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert line == {"resourceId": "vol-1", "resourceType": "ebs", "region": "r-1", "action": "price_unknown",
                    "result": "skipped", "reason": "no volume type price for 'gp9'"}
