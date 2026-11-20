# CONTRACT.md — shared formats between the lanes

Version 2.1 (draft). Every lane builds against this file. **Do not change it alone:** propose the change,
get agreement from the lanes it affects, then bump the version and note it in §10.

Section numbers like "design §9.1" refer to `docs/design.md`.

---

## 1. Naming

| Thing | Format | Example |
|---|---|---|
| Name prefix (per person's stack) | `cg-<name>-` | `cg-reda-` |
| Every AWS resource name | `<prefix><name>` | `cg-reda-findings`, `cg-reda-scanner` |
| Step Functions execution name | `<ec2\|ebs>-<resourceId>-gen<N>` | `ebs-vol-0abc123-gen2` |
| Region we deploy to | `us-west-2` | |

Lambda functions (all `<prefix>` + name): `scanner`, `remediation`, `notify`, `action`, `digest`,
`daily-cost`, `daily-summary`, `budget-subscriber`.
State machines: `<prefix>ec2-timeline`, `<prefix>ebs-timeline`.

## 2. Common value formats

- **Time:** ISO 8601 UTC string, seconds precision, `Z` suffix: `2026-11-20T16:30:00Z`.
- **Day:** `YYYY-MM-DD` (UTC).
- **TTL attributes:** epoch seconds (number), attribute name `ttl`.
- **Money:** USD per month, DynamoDB number (Python `Decimal`), rounded to 2 decimals.
- **Emails:** lowercase.
- **resourceType:** `ec2` | `ebs` | `eip` | `snapshot`.
- **Finding key in text form** (for maps and links): `<resourceId>#<findingType>`, e.g. `i-0abc123#EC2_IDLE`.
- **Booleans:** DynamoDB boolean, never the strings `"true"`/`"false"` (tags are the exception: they're strings).

## 3. DynamoDB tables (all on-demand, encryption default)

### 3.1 `<prefix>findings`
Key: **`resourceId`** (S, partition) + **`findingType`** (S, sort).

`findingType` values:

| findingType | resourceType | Has a timeline? |
|---|---|---|
| `EC2_IDLE` | ec2 | Yes (`ec2-timeline`), unless report-only |
| `EBS_UNATTACHED` | ebs | Yes (`ebs-timeline`), unless report-only |
| `EIP_UNASSOCIATED` | eip | No, report-only |
| `EIP_ON_STOPPED_INSTANCE` | eip | No, report-only |
| `MISSING_TAGS` | ec2 / ebs / eip | No |
| `SNAPSHOT_REMINDER` | snapshot | No (created by the engine after a volume is deleted) |

Attributes:

| Attribute | Type | Written by | Notes |
|---|---|---|---|
| `resourceType` | S | scanner | §2 |
| `region` | S | scanner | e.g. `us-east-1` |
| `owner` | S | scanner | email, or absent if unknown |
| `ownerSource` | S | scanner | `tag` \| `copied` \| `cloudtrail` \| `unknown` |
| `project` | S | scanner | absent if unknown |
| `name` | S | scanner | the resource's `Name` tag, if any (untrusted text) |
| `status` | S | see §3.2 | `open` \| `in_progress` \| `remediated` \| `resolved` \| `failed` |
| `reportOnlyReason` | S | scanner, action | `protected` \| `autoscaling` \| absent |
| `classification` | S | scanner | EC2 only: `idle` \| `underused` \| `periodic` |
| `estimatedMonthlyCost` | N | scanner | absent for `MISSING_TAGS` |
| `missingTags` | L | scanner | `MISSING_TAGS` only, e.g. `["owner","project"]` |
| `firstSeenAt` | S | scanner | start of the current episode; reset on reopen (§3.2) |
| `lastSeenAt` | S | scanner | every scan that still sees the problem |
| `lastNotifiedAt` | S | **notify only** | set after every successful send, on every finding in the email (§4.1) |
| `generation` | N | `common/timeline.py` | starts at 0; never reset; never a string |
| `executionName` | S | `common/timeline.py` | current timeline's name |
| `executionArn` | S | `common/timeline.py` | |
| `timelineStep` | S | engine workflow | `first_notice` \| `waiting` \| `final_warning` \| `acting` \| `done` (dashboard display) |
| `deadlineAt` | S | engine | when the action is due; also the expiry of Protect / Postpone links |
| `postponeCount` | N | action Lambda | max `MAX_POSTPONES` |
| `restartCount` | N | `common/timeline.py` | automatic restarts after `failed`, max `MAX_RESTARTS` |
| `failedStep` | S | engine Catch | |
| `errorMessage` | S | engine Catch | |
| `realizedMonthlySavings` | N | engine | set when status becomes `remediated` (design §11.1); counted only per §3.6 |
| `snapshotId` | S | engine | EBS: the snapshot created before delete |
| `dryRun` | BOOL | engine | true if the "action" was only logged |
| `resolvedAt`, `remediatedAt` | S | whoever sets that status | |

### 3.2 Finding status lifecycle

```
           scanner                 timeline.start                workflow
  (new) ─────────► open ───────────────────────────► in_progress ─────────► remediated
                    ▲  │ scanner: problem gone             │  │ workflow Catch       │ scanner: real restart
                    │  ▼                                   │  ▼                      │ or terminated (EC2 only)
                    │ resolved ◄─── scanner / workflow ────┘ failed                  ▼
                    │    ▲                                    │                   resolved
                    │    └────────────────────────────────────┼───────────────────────┘
                    └── scanner: problem back (reopen)        └── timeline.start (restartCount < MAX_RESTARTS) ──► in_progress
```

| Transition | Who | Rule |
|---|---|---|
| → `open` | scanner | new finding, or reopen of a `resolved` one (a reopen sets a new `firstSeenAt`, so "cost so far" counts the current episode only) |
| `open` → `in_progress` | scanner via `timeline.start_timeline` | only `EC2_IDLE` / `EBS_UNATTACHED`, not report-only |
| `open` / `in_progress` → `resolved` | scanner (via `timeline.stop_timeline` if a timeline runs), or the workflow's re-check | resource active / attached / associated / deleted / tags now present. **Never applies to `remediated` findings** (see below). |
| `in_progress` → `remediated` | engine workflow | after stop, or snapshot + delete; also in dry-run, with `dryRun = true` |
| `in_progress` → `failed` | engine Catch branch (direct DynamoDB update) | sets `failedStep`, `errorMessage` |
| `failed` → `in_progress` | scanner via `timeline.start_timeline` | only if `restartCount < MAX_RESTARTS`; increments it |
| **`remediated` → `resolved`** | scanner | **EC2 only**, in exactly two cases: (a) instance `state = running` **and** `LaunchTime > remediatedAt` (someone really started it again); (b) the instance no longer exists or is `terminated`. |
| any → report-only | action Lambda (Protect), scanner (protect tag found) | stop timeline, set `reportOnlyReason`, status `open` |
| postpone | action Lambda via `timeline` | stays `in_progress`, generation + 1, `postponeCount` + 1 |

Rules that prevent loops:
- **Dry-run:** a dry-run "stop" leaves the instance running with its old `LaunchTime`, so rule (a) doesn't fire and
  the finding stays `remediated`. No reopen, no new timeline, no repeated emails.
- **EBS:** a volume deleted by the Guardian stays `remediated` for good. The scanner's "deleted → resolved" rule only
  applies to `open` / `in_progress` findings. A restored volume has a new ID and becomes a new finding if left unattached.
- A `remediated` → `resolved` finding that becomes idle again later is reopened like any `resolved` one (next generation).

### 3.3 `<prefix>audit`
Key: **`resourceId`** (S) + **`ts`** (S, `<ISO time>#<8-char random>` to keep it unique).
GSI `byDay`: **`day`** (S) + **`ts`** (S) — for the dashboard's activity view.

| Attribute | Type | Notes |
|---|---|---|
| `day` | S | `YYYY-MM-DD` |
| `actor` | S | `scanner` \| `workflow` \| `remediation` \| `notify` \| `action-link` \| `digest` |
| `event` | S | `finding_opened`, `finding_resolved`, `finding_reopened`, `tags_copied`, `owner_found`, `notice_sent`, `final_warning_sent`, `instance_stopped`, `snapshot_created`, `volume_deleted`, `email_fallback`, `link_protect`, `link_postpone`, `link_restore`, `link_refused`, `workflow_failed`, `timeline_started`, `timeline_stopped` |
| `findingType` | S | if related to a finding |
| `region` | S | |
| `generation` | N | if related to a timeline |
| `dryRun` | BOOL | for actions |
| `result` | S | `ok` \| `error` \| `skipped` |
| `details` | M | free-form, small |

### 3.4 `<prefix>tokens` (action links, design §10.4)
Key: **`tokenHash`** (S, hex SHA-256 of the raw token). TTL on `ttl`.

| Attribute | Type | Notes |
|---|---|---|
| `resourceId`, `findingType` | S | the finding the link acts on (see table below) |
| `generation` | N | must equal that finding's current `generation` |
| `action` | S | `protect` \| `postpone` \| `restore` |
| `recipient` | S | email it was sent to |
| `createdAt` | S | |
| `expiresAt` | S | ISO; the link is refused after this |
| `used` | BOOL | false at creation; set true by one conditional write |
| `ttl` | N | `expiresAt` + 7 days, epoch |

Which finding each action points to, and when it expires:

| Action | Finding | Status required when clicked | `expiresAt` |
|---|---|---|---|
| `protect` | the `EC2_IDLE` or `EBS_UNATTACHED` finding | `in_progress` | the finding's `deadlineAt` |
| `postpone` | same | `in_progress` | the finding's `deadlineAt` |
| `restore` | the **`EBS_UNATTACHED`** finding of the deleted volume (not the `SNAPSHOT_REMINDER`) | `remediated` with `dryRun = false` | `RESTORE_LINK_DAYS` (30) days after the confirmation email |

Restore safety: before creating a volume, the Action Lambda checks that the finding's `snapshotId` still exists and is
tagged `guardian:source-volume=<resourceId>`. If not, it refuses with a clear page ("the snapshot was deleted") and
writes a `link_refused` audit entry. (The IAM condition in design §16 enforces the tag too.)

Raw token: `secrets.token_urlsafe(32)`. Link: `<ACTION_API_URL>/action?t=<token>`. Only the hash is stored.

### 3.5 Other tables

| Table | Key | Attributes | Writer → reader |
|---|---|---|---|
| `<prefix>creator-lookups` | `resourceId` | `region`, `creatorArn`, `email` (or absent), `result` (`found`/`unknown`), `method` (`RunInstances`/`AllocateAddress`/`CreateVolume`/`last-attached`/`Attach`/`Detach`), `lookedUpAt` | scanner → scanner |
| `<prefix>volume-attachments` | `volumeId` | `instanceId`, `region`, `seenAt` | scanner → scanner |
| `<prefix>daily-summaries` | `day` | `totalMonthlyWaste`, `realizedMonthlySavings`, `potentialMonthlySavings`, `countsByType` (M), `wasteByRegion` (M), `wasteByOwner` (M), `wasteByProject` (M), `openFindings`, `warningsSent`, `actionsTaken`, `createdAt` | daily-summary → dashboard, digest |
| `<prefix>bill-history` | `day` + `key` (`service#<name>` \| `project#<name>` \| `total`) | `amount` (N, USD), `estimated` (BOOL), `fetchedAt` | daily-cost → dashboard, digest |
| `<prefix>budget-alerts` | `budgetName` + `receivedAt` | `thresholdType` (`ACTUAL`/`FORECASTED`), `threshold`, `message`, `day` | budget-subscriber → dashboard, digest |
| `<prefix>counters` | `counterId` (e.g. `bedrock#2026-11-20`) | `count` (N), `ttl` | dashboard (conditional update) |

### 3.6 How the daily summary counts money

- **Waste:** `estimatedMonthlyCost` of findings with status `open`, `in_progress` or `failed` (not `MISSING_TAGS`).
- **Realized savings:** `realizedMonthlySavings` of findings **currently** `remediated` **with `dryRun = false`**.
  A finding that leaves `remediated` (real restart, terminated) stops counting.
- **Potential savings:** findings `open` / `in_progress` (not report-only) **plus** `remediated` with `dryRun = true`.

## 4. Lambda interfaces (JSON events)

### 4.1 Notify — called by workflows, scanner, digest, action Lambda

Input (one format for every email):
```json
{
  "template": "FIRST_NOTICE",
  "to": "owner@example.com",
  "findings": [
    {
      "resourceId": "i-0abc123",
      "findingType": "EC2_IDLE",
      "generation": 1,
      "actions": ["protect", "postpone"],
      "expiresAt": "2026-11-23T16:30:00Z"
    }
  ],
  "vars": { "...": "template variables, §4.2" }
}
```
- `to`: email or `null` → team address. Unverified / failed → falls back to the team address and writes an
  `email_fallback` audit entry.
- `findings`: every finding this email is about (one for most templates, many for `DIGEST` and `MISSING_TAGS_GROUPED`).
  - Notify sets **`lastNotifiedAt`** on **every** listed finding after a successful send.
  - For each finding with non-empty `actions`, Notify creates one token per action (§3.4) and makes the URLs available to
    the template as `links["<resourceId>#<findingType>"]["<action>"]`.
  - Token writes go in batches of at most **25** (DynamoDB `BatchWriteItem` limit).
  - `actions` rules: `protect` / `postpone` only for `in_progress` `EC2_IDLE` / `EBS_UNATTACHED` findings;
    `restore` only on `DELETE_CONFIRMATION` (non-dry-run). Everything else (`EIP_*`, `MISSING_TAGS`,
    `SNAPSHOT_REMINDER`, report-only, dry-run) gets `actions: []`. `expiresAt` is required when `actions` is non-empty.
- Output: `{ "sent": true, "recipient": "...", "fallback": false, "messageId": "...", "tokensCreated": 2 }`.
- Errors are raised (so Step Functions retries), not swallowed.
- Notify's role: `ses:SendEmail` (verified sender only), `dynamodb:BatchWriteItem` / `PutItem` on tokens,
  `dynamodb:UpdateItem` on findings (only `lastNotifiedAt`), `PutItem` on audit.

### 4.2 Email templates and their variables

R = required, O = optional. Every template also gets `links` from Notify (§4.1).

| Template | Sent by | Variables |
|---|---|---|
| `FIRST_NOTICE` | engine workflow | R: `resourceId`, `resourceType`, `region`, `estimatedMonthlyCost`, `deadlineAt`, `plannedAction` (`stop` \| `snapshot_and_delete`), `dryRun`. O: `name`, `project`, `idleSummary` (EC2: short text of CPU / network / disk), `daysUnattached` (EBS) |
| `FINAL_WARNING` | engine workflow | same as `FIRST_NOTICE` |
| `STOP_CONFIRMATION` | engine workflow | R: `resourceId`, `region`, `realizedMonthlySavings`, `dryRun`, `elasticIps` (list, may be empty). O: `name` |
| `DELETE_CONFIRMATION` | engine workflow | R: `resourceId`, `region`, `sizeGb`, `snapshotId`, `realizedMonthlySavings`, `dryRun`. O: `name`, `availabilityZone` |
| `WORKFLOW_FAILED` | engine Catch | R: `resourceId`, `region`, `findingType`, `failedStep`, `errorMessage`, `progress` (e.g. "snapshot snap-123 created; volume not deleted") |
| `REPORT_NOTICE` | scanner (new report-only finding, once) | R: `resourceId`, `resourceType`, `region`, `findingType`, `estimatedMonthlyCost`, `reason` (`eip_unassociated` \| `eip_on_stopped_instance` \| `autoscaling`). O: `name`, `autoScalingGroup` |
| `MISSING_TAGS` | scanner (once, when found) | R: `resourceId`, `resourceType`, `region`, `missingTags` (list). O: `creatorLookup` (`unknown` reason text) |
| `MISSING_TAGS_GROUPED` | scanner (once, when found) | R: `instanceId`, `region`, `resources` (list of `{resourceId, resourceType, missingTags}`) |
| `RESTORE_DONE` | action Lambda | R: `sourceVolumeId`, `snapshotId`, `newVolumeId`, `availabilityZone`, `region` |
| `DIGEST` | digest Lambda | R: `findings` (list, below), `protected` (list of `{resourceId, resourceType, region, estimatedMonthlyCost, name?}`), `snapshots` (list of `{snapshotId, sourceVolumeId, region, sizeGb, monthlyCost, ageDays}`), `budgetAlerts` (list of `{budgetName, thresholdType, threshold, receivedAt}`), `missingTags` (list of `{resourceId, resourceType, region, missingTags}`). O: `aiSummary` (empty if Bedrock failed) |

`DIGEST` `findings` items: `{resourceId, findingType, resourceType, region, status, estimatedMonthlyCost, costSoFar,
daysOpen, deadlineAt?, timelineStep?, reportOnlyReason?, name?}`. Every item also appears in the top-level `findings`
list of the Notify input (so it gets `lastNotifiedAt` and, if `in_progress`, its links).

### 4.3 Remediation — called by workflows only
Input: `{ "action": "<ACTION>", "resourceId": "...", "region": "...", "dryRun": true, ... }`

| action | Extra input | Output |
|---|---|---|
| `CHECK_EC2` | — | `{ "stillIdle": bool, "protected": bool, "state": "running" }` |
| `STOP_INSTANCE` | — | `{ "stopped": bool, "dryRun": bool, "elasticIps": ["..."] }` |
| `CHECK_EBS` | — | `{ "stillUnattached": bool, "protected": bool, "exists": bool }` |
| `CREATE_SNAPSHOT` | — | `{ "snapshotId": "snap-...", "dryRun": bool }` |
| `SNAPSHOT_STATUS` | `snapshotId` | `{ "state": "pending" \| "completed" \| "error" }` |
| `DELETE_VOLUME` | `snapshotId` | `{ "deleted": bool, "dryRun": bool }` |

### 4.4 Step Functions input (both state machines)
```json
{
  "resourceId": "vol-0abc123",
  "findingType": "EBS_UNATTACHED",
  "resourceType": "ebs",
  "region": "us-east-1",
  "owner": "owner@example.com",
  "generation": 2,
  "executionName": "ebs-vol-0abc123-gen2",
  "dryRun": true,
  "estimatedMonthlyCost": 0.8,
  "waits": { "beforeFinalSeconds": 950400, "beforeActionSeconds": 259200 }
}
```
Demo / test values for `waits` are minutes (e.g. 120 / 120). Defaults: EC2 2 days + 1 day, EBS 11 days + 3 days.
A postpone starts the next generation with `beforeFinalSeconds` = `POSTPONE_SECONDS`.

### 4.5 `common/timeline.py` (owned by lane A, used by scanner and action Lambda)
```python
start_timeline(resource_id, finding_type, reason) -> dict
    # reason: "new" | "reopen" | "restart" | "postpone"
    # gen+1 with a conditional write, StartExecution with <type>-<id>-gen<N>,
    # handles ExecutionAlreadyExists (design §9.1). Sets status in_progress. Returns the updated finding.
stop_timeline(resource_id, finding_type, new_status, report_only_reason=None) -> dict
    # StopExecution on the current execution (ignores "already finished"), updates status.
```
No other code calls `StartExecution` / `StopExecution` directly.

### 4.6 Action API (API Gateway → Action Lambda)
- The HTTP API and its stage are created by **platform core** (§8); engine adds the route and the Lambda integration.
- `GET /action?t=<token>` → HTML confirmation page. Changes nothing.
- `POST /action` (form field `t`) → performs the action once, returns an HTML result page.
- Refusals (HTML page, HTTP 4xx, `link_refused` audit): unknown token, used, expired, older generation (points to the
  newest email), wrong finding status (§3.4), postpone limit reached, snapshot missing (restore).

### 4.7 Scheduled events (EventBridge Scheduler → Lambda)
`{ "source": "schedule", "job": "scan" | "daily-cost" | "daily-summary" | "digest" }`. Manual test runs send the same event.

## 5. Tags

| Tag | Values | Meaning |
|---|---|---|
| `owner` | email | person responsible |
| `project` | text | project name; cost allocation tag |
| `guardian:protect` | `true` | report-only; IAM denies stop / delete |
| `guardian:source-volume` | volume id | on snapshots the Guardian creates |
| `guardian:dev-scope` | a name prefix, e.g. `cg-reda-` | dev only: which personal stack may act on this test resource (§6) |
| `email` | email | on IAM users, for the CloudTrail lookup |

## 6. Configuration (Lambda environment variables)

| Variable | Used by | Example |
|---|---|---|
| `NAME_PREFIX` | all | `cg-reda-` |
| `TABLE_FINDINGS`, `TABLE_AUDIT`, `TABLE_TOKENS`, `TABLE_CREATOR_LOOKUPS`, `TABLE_VOLUME_ATTACHMENTS`, `TABLE_DAILY_SUMMARIES`, `TABLE_BILL_HISTORY`, `TABLE_BUDGET_ALERTS`, `TABLE_COUNTERS` | as needed | `cg-reda-findings` |
| `DRY_RUN` | engine, scanner (tag copying) | `true` |
| `SCAN_REGIONS` | scanner | `all` or `us-west-2,us-east-1` |
| `DEV_SCOPE` | scanner, engine, action | empty in the team stack; in personal stacks = `NAME_PREFIX`, and only resources tagged `guardian:dev-scope=<same>` are acted on or emailed |
| `DETECTION_WINDOW_MINUTES` | scanner | `30` (demo) / `1440` |
| `EC2_SFN_ARN`, `EBS_SFN_ARN` | `common/timeline.py` | |
| `WAIT_BEFORE_FINAL_SECONDS_EC2`, `WAIT_BEFORE_ACTION_SECONDS_EC2`, same for `_EBS` | scanner, action (passed into workflow input) | `120` |
| `POSTPONE_SECONDS` | action | `604800` (7 days); minutes in tests |
| `NOTIFY_FUNCTION_NAME` | scanner, digest, action, engine | `cg-reda-notify` |
| `SENDER_EMAIL`, `TEAM_EMAIL` | notify | |
| `ACTION_API_URL` | notify | output of platform core (§8) |
| `RESTORE_LINK_DAYS` | engine (sets restore `expiresAt`) | `30` |
| `BEDROCK_MODEL_ID`, `BEDROCK_DAILY_CAP`, `BEDROCK_MAX_TOKENS` | digest, dashboard | |
| `MAX_POSTPONES`, `MAX_RESTARTS` | action, timeline | `2`, `2` |

Thresholds (CPU / network / disk) live in `scanner/` config with the values decided by the team (design §24).

## 7. Who reads whose data

| Data | Written by | Read by |
|---|---|---|
| findings | scanner, engine, action, **notify** (`lastNotifiedAt` only) | engine, digest, daily-summary, dashboard |
| audit | everyone | daily-summary, dashboard |
| tokens | notify | action |
| creator-lookups, volume-attachments | scanner | scanner |
| daily-summaries | daily-summary (lane D) | dashboard, digest |
| bill-history | daily-cost | dashboard, digest |
| budget-alerts | budget-subscriber (lane C) | dashboard, digest |
| counters | dashboard | dashboard |

## 8. Terraform module interfaces

Each lane exposes modules called from `infra/stack/main.tf`, in this order (a straight chain, no cycles):

```
platform core  ──►  engine, scanner, dashboard  ──►  platform edge
```

| Module | Inputs (besides `name_prefix`, `owner_email`, `dry_run`) | Outputs |
|---|---|---|
| `platform/terraform/core` | `team_email`, `sender_email` | table names and ARNs, `team_topic_arn`, `dlq_arn`, `notify_function_arn` / `name`, **`vpc_id`, `public_subnet_id`**, **`action_api_id`, `action_api_execution_arn`, `action_api_url`** (the HTTP API + `$default` stage, no routes) |
| `engine/terraform` | tables, `notify_function_arn` / `name`, `team_topic_arn`, `action_api_id`, `action_api_execution_arn` | `ec2_sfn_arn`, `ebs_sfn_arn`, `remediation_function_arn`, `action_function_arn` (engine adds the `/action` routes, the integration and the Lambda permission to core's API) |
| `scanner/terraform` | tables, sfn ARNs, `notify_function_name`, `scan_regions`, `dev_scope` | `scanner_function_arn` |
| `dashboard/terraform` | tables, `bedrock_model_id`, `vpc_id`, `public_subnet_id`, **`origin_secret`** (sensitive), `notify_function_name` | `daily_cost_function_arn`, `daily_summary_function_arn`, `digest_function_arn`, `dashboard_instance_id`, `dashboard_public_dns` |
| `platform/terraform/edge` | `dashboard_public_dns`, `origin_secret`, `dashboard_password` (sensitive) | `dashboard_url` |

- `origin_secret` and `dashboard_password` are sensitive variables of `infra/stack`, passed to the modules that need them.
- Notify's `ACTION_API_URL` comes from core's own API resource, so it never depends on engine.
- No module-level `depends_on` between lane modules (it would create hidden cycles).
- IAM roles for a Lambda live in the module that owns the Lambda; lane C reviews them.

## 9. Open values (to fill in as the team decides — design §24)

Detection thresholds · real detection window · Elastic IP "stopped too long" threshold · allowed instance types ·
budget amounts · Bedrock model, cap and answer length · team address and sender address.
(Defaults already set here: postpone = 7 days, max 2 postpones, max 2 restarts, restore link = 30 days.)

## 10. Change log

- v1 — first draft.
- v2 — `remediated` → `resolved` rules with the `LaunchTime` check (fixes the dry-run reopen loop), EBS stays
  `remediated`, savings counting rules (§3.6, dry-run counts as potential); link targets and expiry, restore safety
  check (§3.4); Notify input reworked to a `findings` list with per-finding actions and 25-item batches, Notify owns
  `lastNotifiedAt` (§4.1); template variables defined (§4.2), new `REPORT_NOTICE` template; `MISSING_TAGS` emailed
  once then digest only; VPC and the action HTTP API moved into platform core, `origin_secret` passed to dashboard,
  module order fixed (§8); new settings `POSTPONE_SECONDS`, `RESTORE_LINK_DAYS`; `firstSeenAt` resets on reopen.
- v2.1 — removed `scheduled` from `reportOnlyReason` (office-hours scheduling set aside, design §21.1).
