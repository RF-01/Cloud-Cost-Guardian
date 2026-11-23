"""Build scanner/src/scanner/prices_data.py from the AWS Price List API (design §11.1, task #21).

Run locally, not in the Lambda (this file is not packaged):

    AWS_PROFILE=guardian .venv/Scripts/python scanner/tools/build_price_table.py

Reads `pricing:GetProducts` (endpoint us-east-1; read-only, free) for every region enabled by default
(describe-regions, opt-in-status = opt-in-not-required), checks the result (fails loudly) and writes a Python
dict literal, because the Lambda zip packages only *.py. Re-run it to refresh the prices.

Per region:
  ec2             on-demand USD per hour per instance type: Linux, shared tenancy, preInstalledSw NA,
                  capacitystatus Used, "No License required"
  ebs             USD per GB-month per volume type
  iops            USD per provisioned IOPS-month: gp3 (above the free 3,000), io1, io2 as tiers
                  [[up_to_iops, price], ..., [None, price]]
  gp3_throughput  USD per MiB/s-month (above the free 125)
  snapshot        USD per GB-month of standard snapshot storage (not archive)
  ipv4            USD per hour per public IPv4 address, {"in_use", "idle"}
"""

import argparse
import json
import pprint
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src" / "scanner" / "prices_data.py"
VOLUME_TYPES = ("gp2", "gp3", "io1", "io2", "st1", "sc1", "standard")
IPV4_FALLBACK = Decimal("0.005")
# io2 IOPS tiers per volume (AWS: up to 32,000; 32,001-64,000; over 64,000), each its own product.
IO2_TIERS = {"EBS IOPS": 32000, "EBS IOPS Tier 2": 64000, "EBS IOPS Tier 3": None}
MIN_INSTANCE_TYPES = 300
MAX_BYTES = 1_500_000

EC2_FILTERS = {
    "operatingSystem": "Linux",
    "tenancy": "Shared",
    "preInstalledSw": "NA",
    "capacitystatus": "Used",
    "licenseModel": "No License required",
    "marketoption": "OnDemand",
    "operation": "RunInstances",
}


class PriceError(Exception):
    pass


# ---------------------------------------------------------------- parsing (no network; unit-tested)

def _price_str(value):
    """'0.0104000000' -> '0.0104' (exact decimal text, no exponent)."""
    d = Decimal(value)
    if d == 0:
        return "0"
    return format(d.normalize(), "f")


def on_demand(product):
    """The product's on-demand price dimensions: list of (unit, Decimal USD, description)."""
    out = []
    for term in product.get("terms", {}).get("OnDemand", {}).values():
        for dim in term["priceDimensions"].values():
            usd = dim.get("pricePerUnit", {}).get("USD")
            if usd is not None:
                out.append((dim.get("unit", ""), Decimal(usd), dim.get("description", "")))
    return out


def _single_price(product, what):
    dims = on_demand(product)
    if len(dims) != 1:
        raise PriceError(f"{what}: expected 1 on-demand price, got {len(dims)}")
    return dims[0]


def _usage(attrs):
    """Usage type without its region prefix: 'USW2-EBS:VolumeUsage.gp3' -> 'EBS:VolumeUsage.gp3'."""
    usage = attrs.get("usagetype", "")
    head, sep, tail = usage.partition("-")
    return tail if sep and ":" not in head else usage


def parse_ec2(products):
    """{instanceType: price per hour}. Zero prices are skipped; conflicting prices raise."""
    prices = {}
    for product in products:
        attrs = product["product"]["attributes"]
        itype = attrs.get("instanceType")
        if not itype or not _usage(attrs).startswith("BoxUsage:"):
            continue
        unit, usd, _ = _single_price(product, itype)
        if unit != "Hrs" or usd == 0:
            continue
        price = _price_str(usd)
        if prices.get(itype, price) != price:
            raise PriceError(f"{itype}: two different prices {prices[itype]} and {price}")
        prices[itype] = price
    return dict(sorted(prices.items()))


def parse_ebs(products):
    """EBS products of one region -> {ebs, iops, gp3_throughput, snapshot}, plus notes for gaps."""
    ebs, iops, io2, throughput, snapshot, notes = {}, {}, {}, None, None, []
    for product in products:
        family = product["product"].get("productFamily")
        attrs = product["product"]["attributes"]
        vtype, group, usage = attrs.get("volumeApiName"), attrs.get("group"), _usage(attrs)
        if family == "Storage" and group == "EBS Storage" and vtype in VOLUME_TYPES:
            unit, usd, _ = _single_price(product, f"{vtype} storage")
            if unit not in ("GB-Mo", "GB-month"):
                raise PriceError(f"{vtype} storage: unexpected unit {unit}")
            ebs[vtype] = _price_str(usd)
        elif family == "System Operation" and vtype in ("gp3", "io1") and group == "EBS IOPS":
            unit, usd, _ = _single_price(product, f"{vtype} IOPS")
            if unit != "IOPS-Mo":
                raise PriceError(f"{vtype} IOPS: unexpected unit {unit}")
            iops[vtype] = _price_str(usd)
        elif family == "System Operation" and vtype == "io2" and group in IO2_TIERS:
            unit, usd, _ = _single_price(product, f"io2 {group}")
            if unit != "IOPS-Mo":
                raise PriceError(f"io2 {group}: unexpected unit {unit}")
            io2[group] = _price_str(usd)
        elif family == "Provisioned Throughput" and vtype == "gp3":
            unit, usd, _ = _single_price(product, "gp3 throughput")
            if unit == "GiBps-mo":  # priced per GiB/s; 1 GiB/s = 1024 MiB/s
                usd = usd / 1024
            elif unit not in ("MiBps-mo", "MiBps-Mo"):
                raise PriceError(f"gp3 throughput: unexpected unit {unit}")
            throughput = _price_str(usd)
        elif family == "Storage Snapshot" and usage == "EBS:SnapshotUsage":
            unit, usd, _ = _single_price(product, "snapshot")
            if unit not in ("GB-Mo", "GB-month"):
                raise PriceError(f"snapshot: unexpected unit {unit}")
            snapshot = _price_str(usd)
    if "EBS IOPS" in io2:
        if set(io2) != set(IO2_TIERS):
            notes.append(f"io2: only tiers {sorted(io2)}; the first tier is used above 32,000 IOPS")
        last = io2["EBS IOPS"]
        tiers = []
        for group, up_to in IO2_TIERS.items():
            last = io2.get(group, last)
            tiers.append([up_to, last])
        iops["io2"] = tiers
    return {"ebs": dict(sorted(ebs.items())), "iops": iops, "gp3_throughput": throughput,
            "snapshot": snapshot}, notes


def parse_ipv4(products):
    """AmazonVPC products of one region -> ({"in_use", "idle"} or None for each, notes)."""
    found = {}
    for product in products:
        usage = _usage(product["product"]["attributes"])
        key = {"PublicIPv4:InUseAddress": "in_use", "PublicIPv4:IdleAddress": "idle"}.get(usage)
        if key:
            unit, usd, _ = _single_price(product, f"IPv4 {key}")
            if unit != "Hrs":
                raise PriceError(f"IPv4 {key}: unexpected unit {unit}")
            found[key] = _price_str(usd)
    notes = []
    for key in ("in_use", "idle"):
        if key not in found:
            found[key] = _price_str(IPV4_FALLBACK)
            notes.append(f"IPv4 {key}: not in the API, fallback {IPV4_FALLBACK}")
    return found, notes


def check(table, regions):
    """Sanity checks; raises PriceError listing every problem."""
    problems = []
    if sorted(table) != sorted(regions):
        problems.append(f"regions differ: table {sorted(table)} vs enabled {sorted(regions)}")
    for region, prices in table.items():
        if len(prices["ec2"]) < MIN_INSTANCE_TYPES:
            problems.append(f"{region}: only {len(prices['ec2'])} instance types")
        missing = [t for t in VOLUME_TYPES if t not in prices["ebs"]]
        if missing:
            problems.append(f"{region}: no EBS price for {missing}")
        for key in ("gp3", "io1", "io2"):
            if key not in prices["iops"]:
                problems.append(f"{region}: no {key} IOPS price")
        for key in ("gp3_throughput", "snapshot"):
            if not prices.get(key):
                problems.append(f"{region}: no {key} price")
        if set(prices["ipv4"]) != {"in_use", "idle"}:
            problems.append(f"{region}: IPv4 prices incomplete")
    east = table.get("us-east-1")
    if east is None:
        problems.append("us-east-1 missing")
    else:
        expected = [("t3.micro", east["ec2"].get("t3.micro"), "0.0104"), ("gp3", east["ebs"].get("gp3"), "0.08"),
                    ("gp2", east["ebs"].get("gp2"), "0.1"), ("snapshot", east.get("snapshot"), "0.05"),
                    ("IPv4 in use", east["ipv4"].get("in_use"), "0.005"),
                    ("IPv4 idle", east["ipv4"].get("idle"), "0.005")]
        for name, got, want in expected:
            if got is None or Decimal(got) != Decimal(want):
                problems.append(f"us-east-1 {name}: {got}, expected {want}")
    if problems:
        raise PriceError("sanity checks failed:\n  " + "\n  ".join(problems))


def render(table, regions, generated_at):
    header = (
        '"""Price table for cost estimates (design §11.1). GENERATED, do not edit by hand.\n\n'
        f"Generated: {generated_at}\n"
        "Source: AWS Price List API (pricing:GetProducts, us-east-1 endpoint), services AmazonEC2 and AmazonVPC;\n"
        "        EC2: Linux on-demand, shared tenancy, preInstalledSw NA, capacitystatus Used, No License required.\n"
        f"Regions ({len(regions)}, enabled by default): {', '.join(sorted(regions))}\n"
        "Refresh: AWS_PROFILE=guardian .venv/Scripts/python scanner/tools/build_price_table.py\n\n"
        "Units: ec2 USD/hour; ebs USD/GB-month; iops USD/IOPS-month (io2: [[up to IOPS, price], ...]);\n"
        "gp3_throughput USD per MiB/s-month; snapshot USD/GB-month; ipv4 USD/hour. Prices are strings (exact).\n"
        '"""\n\n'
    )
    body = pprint.pformat(table, indent=1, width=118, sort_dicts=True)
    return f"{header}GENERATED_AT = {generated_at!r}\nREGIONS = {sorted(regions)!r}\n\nPRICES = {body}\n"


# ---------------------------------------------------------------- network

def get_products(client, service, filters):
    kwargs = {"ServiceCode": service, "MaxResults": 100,
              "Filters": [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in filters.items()]}
    out = []
    while True:
        page = client.get_products(**kwargs)
        out += [json.loads(item) for item in page["PriceList"]]
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def enabled_regions(session):
    ec2 = session.client("ec2", region_name="us-west-2")
    regions = ec2.describe_regions(AllRegions=True, Filters=[
        {"Name": "opt-in-status", "Values": ["opt-in-not-required"]}])["Regions"]
    return sorted(r["RegionName"] for r in regions)


def build(session, regions):
    from botocore.config import Config
    client = session.client("pricing", region_name="us-east-1",
                            config=Config(retries={"mode": "adaptive", "max_attempts": 10}))
    table, notes = {}, []
    for region in regions:
        ec2 = parse_ec2(get_products(client, "AmazonEC2", dict(EC2_FILTERS, regionCode=region)))
        ebs_products = []
        for family in ("Storage", "System Operation", "Provisioned Throughput", "Storage Snapshot"):
            ebs_products += get_products(client, "AmazonEC2", {"regionCode": region, "productFamily": family})
        ebs, ebs_notes = parse_ebs(ebs_products)
        ipv4, ipv4_notes = parse_ipv4(get_products(client, "AmazonVPC", {"regionCode": region}))
        table[region] = {"ec2": ec2, **ebs, "ipv4": ipv4}
        notes += [f"{region}: {n}" for n in ebs_notes + ipv4_notes]
        print(f"  {region}: {len(ec2)} instance types, EBS {sorted(ebs['ebs'])}", file=sys.stderr)
    return table, notes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", default=None, help="AWS profile (default: AWS_PROFILE)")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)

    import boto3
    session = boto3.Session(profile_name=args.profile)
    regions = enabled_regions(session)
    print(f"regions enabled by default ({len(regions)}): {' '.join(regions)}", file=sys.stderr)
    table, notes = build(session, regions)
    check(table, regions)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = render(table, regions, generated_at)
    size = len(text.encode("utf-8"))
    if size > MAX_BYTES:
        raise PriceError(f"prices_data.py would be {size} bytes (> {MAX_BYTES}); decide what to trim first")
    args.out.write_text(text, encoding="utf-8", newline="\n")

    print(f"\nwrote {args.out} ({size} bytes, {size / 1024:.0f} KiB)")
    print(f"regions: {len(table)}; instance types per region: "
          f"min {min(len(p['ec2']) for p in table.values())}, max {max(len(p['ec2']) for p in table.values())}")
    for region in ("us-east-1", "us-west-2"):
        p = table[region]
        print(f"{region}: t3.micro {p['ec2'].get('t3.micro')}/h, m5.large {p['ec2'].get('m5.large')}/h; "
              f"EBS {p['ebs']}; IOPS {p['iops']}; gp3 throughput {p['gp3_throughput']}; "
              f"snapshot {p['snapshot']}; IPv4 {p['ipv4']}")
    print("notes (prices not in the API, fallbacks):" if notes else "notes: none (every price came from the API)")
    for note in notes:
        print(f"  {note}")


if __name__ == "__main__":
    main()
