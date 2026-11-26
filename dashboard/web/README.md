# Dashboard web app (lane D, tasks #26, #38, #43)

Flask 3 app served by waitress. It reads the Guardian's DynamoDB tables and shows findings, waste and savings,
activity, the real bill, budget alerts and budget status (design §11.4, §15), plus the "Ask about my costs" box
(Amazon Bedrock, design §12, CONTRACT §4.11). It runs on Windows and Linux with Python 3.11+. It is not a Lambda.
On EC2 it runs behind CloudFront (#38).

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
| `TABLE_FINDINGS`, `TABLE_AUDIT`, `TABLE_DAILY_SUMMARIES`, `TABLE_BILL_HISTORY`, `TABLE_BUDGET_ALERTS`, `TABLE_COUNTERS` | from `NAME_PREFIX` | override one table name (CONTRACT §6) |
| `ACCOUNT_ID` | from STS | account for budgets DescribeBudgets (set on EC2; otherwise GetCallerIdentity, which needs no permission) |
| `RATE_LIMIT_PER_MINUTE` | `60` | requests per visitor IP per sliding 60 s, every route except `/healthz` |
| `ASK_PER_VISITOR_PER_HOUR` | `10` | Ask questions per visitor IP per rolling hour |
| `BEDROCK_MODEL_ID` | `us.amazon.nova-2-lite-v1:0` | inference profile for the Ask box |
| `BEDROCK_MAX_TOKENS` | `500` | output tokens per answer |
| `BEDROCK_DAILY_CAP` | `30` | Ask questions per UTC day for the whole dashboard |
| `BEDROCK_MAX_QUESTION_CHARS` | `500` | question length limit |
| `PORT` | `8080` | listen port |
| `HOST` | `127.0.0.1` | listen address (on EC2: `0.0.0.0`, behind the security group) |
| `THREADS` | `8` | waitress worker threads |
| `AWS_REGION` | `us-west-2` | region of the tables |
| `AWS_PROFILE` | none | local only. On EC2 the instance role is used, with no keys |
| `ORIGIN_SECRET` | empty | if set, every request (all routes, incl. `/healthz` and `/static`) needs header `X-Origin-Verify` with this value, else `403 {"error": "forbidden"}` (compared with `hmac.compare_digest`; never logged) |
| `REQUIRE_ORIGIN_SECRET` | unset | `1` = refuse to start if `ORIGIN_SECRET` is empty (set on EC2, so the instance fails closed) |
| `WARM_CACHE` | unset | `1` = at startup a background thread loads findings, today's summaries, the activity window's audit days, the 30-day bill and budget alerts once; failures are logged (`dashboard_read`, `cache_warm`), not fatal |

## Routes (GET / HEAD, except `/api/ask` which is POST only; every other method / path returns 405)

| Route | Returns |
|---|---|
| `/` | the page: KPI tiles, charts, finding tables, recent activity, budget alerts |
| `/api/findings?status=&region=&owner=` | active / failed / remediated / report-only rows, resolved count, filter options |
| `/api/summaries?days=7\|30\|90` | daily series (with a `sample` flag per day), latest breakdowns, KPI summary |
| `/api/bill?days=1..90` | daily `total`, top 5 services plus `other`, spend by project (usage cost before credits, USD/day) |
| `/api/activity?weeks=1..12` | per-ISO-week counts plus the last 7 days of audit entries (max 200) |
| `/api/budgets` | the newest 20 budget alerts (`alerts`) and this stack's budgets from AWS Budgets (`status`; `null` + `statusError` if unavailable) |
| `POST /api/ask` | the Ask box: `{"question": "..."}` → `{"answer", "remainingToday", "generatedAt"}` (rules below) |
| `/healthz` | `{"status": "ok"}`, makes no AWS calls |

Cache (in memory, per process): findings 30 s, everything else (incl. budget status) 300 s.

## Rate limits and the Ask box (#43, CONTRACT §4.11)

- **Per visitor:** the visitor is the IP in `CloudFront-Viewer-Address` (`<ip>:<port>`, IPv6 too; missing →
  `unknown`). After the origin check, every route except `/healthz` counts: `RATE_LIMIT_PER_MINUTE` per sliding
  60 s, else `429 {"error": "rate_limited"}` + `Retry-After`. In memory; at most 10,000 visitors (expired ones
  pruned, then the one idle the longest dropped). One `rate_limited` log line per refusal.
- **`POST /api/ask`:** needs `Content-Type: application/json` and `X-Requested-With: guardian-dashboard` (else
  403: the CSRF guard; no CORS headers are ever sent), a body of at most 4 KB (413) and a question of 1–500
  characters after trimming (400). Then: at most `ASK_PER_VISITOR_PER_HOUR` per visitor (429
  `ask_rate_limited`), the data for the model from the cache, the global daily cap (one conditional UpdateItem on
  `counters` key `bedrock#<UTC day>`; 429 `daily_cap`; **not refunded** if Bedrock then fails), and Bedrock
  Converse (502 `ai_unavailable` on any error). The whole request stays under CloudFront's 30 s origin timeout
  (data ≤ 3 s, counter ≤ 3 s, Bedrock connect 3 s + read 20 s).
- **What the model sees:** active findings and those remediated in the last 30 days, 30 daily summaries, 30 days
  of bill totals plus service / project sums, audit event counts per day for 7 days, budget alerts of the last
  30 days and the budget status, with totals computed in code. Sample rows are kept with `"sample": true`. Names
  are cut to 64 characters; no `errorMessage`, audit details or budget message text. Compact JSON with `<` / `>`
  escaped inside `<data>…</data>`, at most 30,000 characters. The question comes after the data block.
- **Logs:** one `ask` line per question with its length only (never the text), the result, tokens, ms and
  `remainingToday`.

Security: Jinja autoescape is on. Untrusted text (tag values, `errorMessage`, audit `details`, budget
messages) reaches HTML only through autoescape, and reaches JS only as JSON. Every response has
`Content-Security-Policy: default-src 'self'; ...` (no inline script or style, no CDN), `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and `Cache-Control: no-store`.

Chart.js **4.6.2** is vendored at `static/vendor/chart.umd.min.js` (MIT, licence header kept). It is the
unmodified `dist/chart.umd.min.js` from the npm tarball `https://registry.npmjs.org/chart.js/-/chart.js-4.6.2.tgz`
(registry integrity `sha512-xachB+pPHjp0syJi7llUBA1w3kMYl6NF3o7eVrvjnWCT+IB2zMaF2pX5UYDiwbbfsioFEIRnAjreNOMsGj5TIA==`,
verified). The file's sha256 is `3f288f4f26882c26b58931fb586a9b4f30370b5de38d69dc005b0bd05b08e113`.

## On EC2 (#38)

```
Browser --HTTPS--> CloudFront (basic auth function) --HTTP :80 + X-Origin-Verify--> EC2 t3.micro (this app)
```

- **Where:** instance `<prefix>dashboard` (t3.micro, Amazon Linux 2023, encrypted 8 GB gp3 root, IMDSv2 only, no key
  pair, tagged `guardian:protect=true`) in platform core's public subnet. Terraform: `dashboard/terraform/web.tf`
  (instance, role, security group, artifact bucket, SSM parameter) and `platform/terraform/edge` (CloudFront).
- **How it runs:** user_data (`dashboard/terraform/templates/dashboard_user_data.sh.tftpl`) installs Python 3.12,
  creates the system user `guardian` (no login shell), downloads the code zip from
  `s3://<prefix>dashboard-artifacts-<account>/dashboard-web/<md5>.zip`, unzips it to `/opt/guardian-dashboard`,
  builds a venv there and starts the systemd unit `guardian-dashboard.service` (`python -m dashboard.web` as
  `guardian`, port 80 via `CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, `Restart=always`). Before every start,
  `ExecStartPre` (root) reads the SSM SecureString `/<prefix>dashboard/origin-secret` into
  `/run/guardian-dashboard/origin.env` (0600). The secret is never in user_data, logs or Terraform outputs. The
  unit sets `HOST=0.0.0.0`, `PORT=80`, `THREADS=8`, `NAME_PREFIX`, `ACCOUNT_ID`, every `TABLE_*`, the Ask settings (`BEDROCK_*`, `RATE_LIMIT_PER_MINUTE`, `ASK_PER_VISITOR_PER_HOUR`), `REQUIRE_ORIGIN_SECRET=1` and
  `WARM_CACHE=1`.
- **Open it:** `terraform output dashboard_url` in `infra/stack`. Login = `dashboard_username` (default `guardian`)
  / `dashboard_password` from your `infra/stack/terraform.tfvars`.
- **Redeploy = `terraform apply`** in `infra/stack`. A code change gives a new zip MD5, so a new S3 key and new
  user_data, and Terraform **replaces** the instance (a few minutes of downtime; the new instance gets a new public
  DNS name and the same apply points CloudFront at it). Changing the login is just an apply (CloudFront only).
  **Changing `origin_secret`** is also just an apply: user_data carries the SSM parameter's version number (not
  the value), so a new secret replaces the instance in the same apply and the new instance reads the new value.
- **After a stop / start** (to save money) the public DNS name changes: run `terraform apply` to update CloudFront's
  origin.
- **Logs:** connect with EC2 Instance Connect (console: EC2 → the instance → Connect → EC2 Instance Connect, user
  `ec2-user`; or `aws ec2-instance-connect ssh --instance-id <dashboard_instance_id> --profile guardian`), then
  - `sudo journalctl -u guardian-dashboard -f` (app: one JSON line per event, e.g. `dashboard_start`, `cache_warm`,
    `origin_rejected`)
  - `sudo cat /var/log/guardian-dashboard-setup.log` (first boot setup)
  - `systemctl status guardian-dashboard`, `curl -s -H "X-Origin-Verify: ..." localhost/healthz` (without the
    header you get 403, which is correct).

## IAM for the instance role (#38, #43)

The app makes **only** these DynamoDB reads. `store.ReadOnlyDynamo` enforces this list at runtime, and
`test_web_app.py` fails on any other call. The resources use `<account>` and `<prefix>` (e.g. `cg-dev-`), region
`us-west-2`:

| Action | Resource | Used for |
|---|---|---|
| `dynamodb:Scan` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>findings` | findings (paginated) |
| `dynamodb:Query` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>audit/index/byDay` | activity, one query per day (index only, not the base table) |
| `dynamodb:BatchGetItem` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>daily-summaries` | summaries by day key |
| `dynamodb:Query` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>bill-history` | bill, one query per day |
| `dynamodb:Scan` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>budget-alerts` | budget alerts |

Added by #43 (Ask box and budget status), and nothing else:

| Action | Resource | Used for |
|---|---|---|
| `dynamodb:UpdateItem` | `arn:aws:dynamodb:us-west-2:<account>:table/<prefix>counters`, conditions `ForAllValues:StringLike dynamodb:LeadingKeys = bedrock#*`, `ForAllValues:StringEquals dynamodb:Attributes = counterId, count, ttl`, a `Null … = false` guard on each, `StringEqualsIfExists dynamodb:ReturnValues = NONE, UPDATED_NEW` | the global daily question cap (one conditional update, `store.BedrockCounter`; the app's only write) |
| `bedrock:InvokeModel` | `arn:aws:bedrock:us-west-2:<account>:inference-profile/us.amazon.nova-2-lite-v1:0`, `arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-2-lite-v1:0`, `arn:aws:bedrock:us-east-2::foundation-model/amazon.nova-2-lite-v1:0`, `arn:aws:bedrock:us-west-2::foundation-model/amazon.nova-2-lite-v1:0` (the digest's ARNs, shared local) | Ask box (design §12) |
| `budgets:ViewBudget` | `arn:aws:budgets::<account>:budget/*` | budget status (DescribeBudgets, us-east-1). DescribeBudgets takes only the account ID and names no budget, so `budget/<prefix>*` cannot be relied on to authorize it; `budget/*` of this account is the narrowest resource that surely works (never `*`). Read only; the app shows only `<prefix>*` budgets |

Also granted (#38): `s3:GetObject` on `arn:aws:s3:::<prefix>dashboard-artifacts-<account>/dashboard-web/*` (the code
zip) and `ssm:GetParameter` on `/<prefix>dashboard/origin-secret`. That parameter uses the AWS managed key `aws/ssm`,
whose key policy already allows decrypt through SSM for every principal in the account, so no `kms:Decrypt`.

The tables use default (AWS-owned) encryption, so no KMS permission is needed. The role gets no write
permissions on findings, audit, summaries, bill-history, budget-alerts or tokens, and no budgets write actions.

## Demo seed (`dashboard/tools/seed_demo.py`)

The seed works **only** on the demo stack (`--prefix cg-demo-`; any other prefix is refused). It writes sample
daily-summaries and matching audit entries (`sample = true`, actor `sample-seed`) for past days only, and never
overwrites a day that already has a summary. Without `--yes` it only prints what it would write. To remove the
rows, run `--delete --yes`, which deletes only `sample = true` rows. See the script's docstring for details.
