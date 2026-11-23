# Dashboard web app (lane D, task #26)

Flask 3 app served by waitress. It reads the Guardian's DynamoDB tables (read-only) and shows findings,
waste and savings, activity, the real bill and budget alerts (design §11.4, §15). It runs on Windows and
Linux with Python 3.11+. It is not a Lambda. On EC2 it runs behind CloudFront (#38).

Not in this task: the origin-secret header check, the EC2 instance and its role and CloudFront (#38); the
"Ask about my costs" box, the Bedrock daily cap and the per-visitor rate limit (#43).

## Run locally

From the repo root (PowerShell):

```powershell
.venv\Scripts\python -m pip install -r dashboard/web/requirements.txt
$env:AWS_PROFILE = "guardian"
$env:NAME_PREFIX = "cg-dev-"
.venv\Scripts\python -m dashboard.web
# open http://127.0.0.1:8080/
```

Git Bash: `AWS_PROFILE=guardian NAME_PREFIX=cg-dev- .venv/Scripts/python -m dashboard.web`.

Tests (moto, no AWS): `.venv\Scripts\python -m pytest dashboard/tests`.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `NAME_PREFIX` | (required unless every `TABLE_*` is set) | table names are `<prefix><name>`, e.g. `cg-dev-findings` |
| `TABLE_FINDINGS`, `TABLE_AUDIT`, `TABLE_DAILY_SUMMARIES`, `TABLE_BILL_HISTORY`, `TABLE_BUDGET_ALERTS` | from `NAME_PREFIX` | override one table name (CONTRACT §6) |
| `PORT` | `8080` | listen port |
| `HOST` | `127.0.0.1` | listen address (on EC2, #38 sets `0.0.0.0` behind the security group) |
| `THREADS` | `8` | waitress worker threads |
| `AWS_REGION` | `us-west-2` | region of the tables |
| `AWS_PROFILE` | none | local only. On EC2 the instance role is used, with no keys |

## Routes (GET / HEAD only; every other method returns 405)

| Route | Returns |
|---|---|
| `/` | the page: KPI tiles, charts, finding tables, recent activity, budget alerts |
| `/api/findings?status=&region=&owner=` | active / failed / remediated / report-only rows, resolved count, filter options |
| `/api/summaries?days=7\|30\|90` | daily series (with a `sample` flag per day), latest breakdowns, KPI summary |
| `/api/bill?days=1..90` | daily `total`, top 5 services plus `other`, spend by project (usage cost before credits, USD/day) |
| `/api/activity?weeks=1..12` | per-ISO-week counts plus the last 7 days of audit entries (max 200) |
| `/api/budgets` | the newest 20 budget alerts |
| `/healthz` | `{"status": "ok"}`, makes no AWS calls |

Cache (in memory, per process): findings 30 s, everything else 300 s.

Security: Jinja autoescape is on. Untrusted text (tag values, `errorMessage`, audit `details`, budget
messages) reaches HTML only through autoescape, and reaches JS only as JSON. Every response has
`Content-Security-Policy: default-src 'self'; ...` (no inline script or style, no CDN), `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and `Cache-Control: no-store`.

Chart.js **4.6.2** is vendored at `static/vendor/chart.umd.min.js` (MIT, licence header kept). It is the
unmodified `dist/chart.umd.min.js` from the npm tarball `https://registry.npmjs.org/chart.js/-/chart.js-4.6.2.tgz`
(registry integrity `sha512-xachB+pPHjp0syJi7llUBA1w3kMYl6NF3o7eVrvjnWCT+IB2zMaF2pX5UYDiwbbfsioFEIRnAjreNOMsGj5TIA==`,
verified). The file's sha256 is `3f288f4f26882c26b58931fb586a9b4f30370b5de38d69dc005b0bd05b08e113`.

## IAM for the instance role (#38, and #43 additions)

The app makes **only** these DynamoDB calls. `store.ReadOnlyDynamo` enforces this list at runtime, and
`test_web_app.py` fails on any other call. The resources use `<account>` and `<prefix>` (e.g. `cg-dev-`), region
`us-west-2`:

| Action | Resource | Used for |
|---|---|---|
| `dynamodb:Scan` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>findings` | findings (paginated) |
| `dynamodb:Query` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>audit/index/byDay` | activity, one query per day (index only, not the base table) |
| `dynamodb:BatchGetItem` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>daily-summaries` | summaries by day key |
| `dynamodb:Query` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>bill-history` | bill, one query per day |
| `dynamodb:Scan` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>budget-alerts` | budget alerts |

Added by #43 (Ask box), and nothing else:

| Action | Resource | Used for |
|---|---|---|
| `dynamodb:UpdateItem` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>counters` (optionally condition `dynamodb:LeadingKeys` = `bedrock#*`) | the global daily question cap (conditional update) |
| `bedrock:InvokeModel` | `arn:aws:bedrock:us-west-2:<account>:inference-profile/us.amazon.nova-2-lite-v1:0`, `arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-2-lite-v1:0`, `arn:aws:bedrock:us-east-2::foundation-model/amazon.nova-2-lite-v1:0`, `arn:aws:bedrock:us-west-2::foundation-model/amazon.nova-2-lite-v1:0` | Ask box (design §12) |

The tables use default (AWS-owned) encryption, so no KMS permission is needed. The role gets no write
permissions on findings, audit, summaries, bill-history, budget-alerts or tokens.

## Demo seed (`dashboard/tools/seed_demo.py`)

The seed works **only** on the demo stack (`--prefix cg-demo-`; any other prefix is refused). It writes sample
daily-summaries and matching audit entries (`sample = true`, actor `sample-seed`) for past days only, and never
overwrites a day that already has a summary. Without `--yes` it only prints what it would write. To remove the
rows, run `--delete --yes`, which deletes only `sample = true` rows. See the script's docstring for details.
