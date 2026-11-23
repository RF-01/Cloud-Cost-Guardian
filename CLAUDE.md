# CLAUDE.md — Cloud Cost Guardian

Read this file and `CONTRACT.md` before doing anything in this repo.

## What this project is

Cloud Cost Guardian (CMPS 297U, AUB): a serverless FinOps tool that scans an AWS account in every
enabled region, finds idle EC2 instances, unattached EBS volumes, unused Elastic IPs and untagged
resources, emails their owners, runs a warning timeline per resource (Step Functions), and safely
remediates only reversible things. A dashboard on EC2 (behind CloudFront) shows waste, savings and
the real bill, with a Bedrock assistant.

- **Full design (source of truth for behavior):** `docs/design.md`
- **Shared formats between parts (source of truth for interfaces):** `CONTRACT.md`
- If the two disagree on interfaces or data formats (tables, statuses, event payloads, names, module order),
  **`CONTRACT.md` wins**: it was written after the design on purpose and its change log (§10) lists the deliberate
  differences (e.g. the separate `daily-summary` Lambda, the `in_progress` / `remediated` statuses). The design's
  original team split (design §23.1) is replaced by the lanes below.
- For any other disagreement or gap, stop and ask. Do not guess.

## Team lanes and folders

Each lane owns one folder. **Only edit files inside your own lane's folder.** To change anything
outside it (another lane, `common/`, `infra/`, `CONTRACT.md`), stop and tell the human first.

| Lane | Folder | Owner | Covers |
|---|---|---|---|
| A: Lifecycle engine | `engine/` | reda | Step Functions workflows (EC2, EBS), generations and execution names, Catch and restarts, Remediation Lambda, Action Lambda + API Gateway (protect / postpone / restore), workflow alarms, `common/timeline.py` |
| B: Scanner | `scanner/` | reda | Multi-region detection, metrics and classification, price table and cost estimates, tag copying, CloudTrail creator lookup, resolve / reopen |
| C: Platform and delivery | `platform/` | reda | Terraform base, team IAM users and group, guardrails, IAM review, VPC, EC2, CloudFront, SES + Notify Lambda (templates, tokens), SNS, DLQ alarm, Budgets, EventBridge schedules, budget alert subscriber |
| D: Data and dashboard | `dashboard/` | reda | Daily cost Lambda (Cost Explorer), daily summary, Digest Lambda + Bedrock summary, dashboard web app (charts, Ask box, rate limit, secret header check) |

Shared folders:
- `common/` — Python shared by several Lambdas (contract constants, models, `timeline.py`). Changes need agreement.
- `infra/shared/` — account-wide Terraform (one copy for the whole account). Owned by lane C.
- `infra/stack/` — the root config that deploys one full copy of the Guardian. Each lane adds only its own `module` block.
- `bootstrap/` — the Terraform state bucket. Already applied; do not change.
- `docs/` — design doc, report material.

## Git rules (we all work on `main`)

1. `git pull --rebase origin main` before you start and before every push.
2. Small commits, pushed at least daily. Only push code that passes `terraform validate` and its tests.
3. Never commit secrets, state or build output. Run `git status` before every commit. `.gitignore` must not be weakened.
4. Commit messages start with the lane: `engine: add EBS workflow`, `scanner: multi-region loop`.

## AWS rules

- Region `us-west-2` for everything we deploy. The scanner reads every enabled region.
- Never use the root user. Each person uses their own IAM user through an AWS CLI profile
  (`--profile <name>` / `AWS_PROFILE`). Never put access keys in code, files or chat.
- **Ask the human before running** `terraform apply`, `terraform destroy`, or any command that stops,
  deletes, releases or modifies AWS resources. Read-only commands (`describe`, `get`, `list`, `plan`) are fine.
- Keep `DRY_RUN=true` in every personal stack. Only the final team test turns it off, and only for seeded test resources.
- Personal stacks use the dev scope filter (`CONTRACT.md` §6) so one person's scanner never acts on another person's resources.
- SES is in sandbox: 200 emails per day for the whole account. Never write loops that could send unbounded email.
- Launch guardrails (infra/shared): team members' RunInstances / CreateVolume / AllocateAddress need `owner` (an email)
  and `project` tags at create time, on the instance AND its volumes; instance types t3.micro or t3.small only.
  Test with `--dry-run`.

## Terraform rules

- Everything that Terraform can create is created in Terraform. No console changes to resources Terraform manages.
  The only console steps are listed in `docs/manual-setup.md`.
- State lives in S3 bucket `cost-guardian-tfstate-<account id>` with `use_lockfile = true`:
  - `infra/shared` → key `shared/terraform.tfstate`
  - `infra/stack` → key `stacks/<name_prefix>/terraform.tfstate` (one per person, set with `-backend-config`)
- Every resource name starts with `var.name_prefix` (e.g. `cg-dev-`), so personal copies never collide.
- Provider `default_tags`: `project = "cost-guardian"`, `owner = var.owner_email`, `managed-by = "terraform"`.
  EC2 instances also need `volume_tags`.
- Secrets (dashboard password, origin header secret) are `sensitive` variables in an uncommitted `terraform.tfvars`.
- Lambda code is packaged with `archive_file`; each Lambda zip includes `common/`.
- Explicit Lambda timeouts (design §17): scanner 5 min, digest 3 min, remediation / notify / daily cost 60 s,
  budget subscriber 30 s, action 29 s.

## Safety rules (never break these)

- No Guardian role ever gets `ec2:DeleteSnapshot` or `ec2:ReleaseAddress`.
- `ec2:StopInstances` and `ec2:DeleteVolume` are denied on resources tagged `guardian:protect=true` (IAM, not only code).
- The final warning is always sent before any stop or delete, and the resource is re-checked right before acting.
- Action links: GET never changes anything; POST performs the action once (conditional write).
- Least privilege per Lambda. If you need a new permission, say which and why.

## Code conventions

- Python 3.12, boto3. Lambda handlers in `<lane>/src/<function>/handler.py`, function `handler(event, context)`.
- Unit tests with pytest in `<lane>/tests/`, AWS mocked (moto or stubs). Write tests with the code.
- Logs: one JSON line per important event (`resourceId`, `findingType`, `action`, `result`).
- All times ISO 8601 UTC (`2026-11-20T16:30:00Z`). Money in USD per month, stored as DynamoDB numbers.
- Follow `CONTRACT.md` exactly. If something you need is missing from it, stop and say what to add.
