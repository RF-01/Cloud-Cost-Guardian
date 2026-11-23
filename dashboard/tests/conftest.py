import sys
from pathlib import Path

import boto3
import pytest

# Make the repo root importable so tests can `import dashboard.web` / load dashboard/tools like `python -m` does.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REGION = "us-west-2"


def create_dashboard_tables(prefix, region=REGION):
    """The five tables the dashboard reads, shaped like platform core's (CONTRACT §3). Call inside mock_aws."""
    ddb = boto3.client("dynamodb", region_name=region)

    def table(name, keys, gsi=None):
        attrs = {k for k, _ in keys}
        params = {
            "TableName": prefix + name,
            "KeySchema": [{"AttributeName": k, "KeyType": t} for k, t in keys],
            "BillingMode": "PAY_PER_REQUEST",
        }
        if gsi:
            attrs |= {"day", "ts"}
            params["GlobalSecondaryIndexes"] = [{
                "IndexName": "byDay",
                "KeySchema": [{"AttributeName": "day", "KeyType": "HASH"},
                              {"AttributeName": "ts", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            }]
        params["AttributeDefinitions"] = [{"AttributeName": a, "AttributeType": "S"} for a in sorted(attrs)]
        ddb.create_table(**params)

    table("findings", [("resourceId", "HASH"), ("findingType", "RANGE")])
    table("audit", [("resourceId", "HASH"), ("ts", "RANGE")], gsi=True)
    table("daily-summaries", [("day", "HASH")])
    table("bill-history", [("day", "HASH"), ("key", "RANGE")])
    table("budget-alerts", [("budgetName", "HASH"), ("receivedAt", "RANGE")])
    return ddb


@pytest.fixture
def make_tables():
    """Fixture form, so test files never `import conftest` (other lanes have their own conftest.py)."""
    return create_dashboard_tables
