# CONTRACT.md — shared formats between the lanes

Version 2.15 (draft). Every lane builds against this file. **Do not change it alone:** propose the change,
get agreement from the lanes it affects, then bump the version and note it in §10.

Section numbers like "design §9.1" refer to `docs/design.md`.

---

## 1. Naming

| Thing | Format | Example |
|---|---|---|
| Name prefix (per stack) | `cg-<name>-` | `cg-dev-` |
| Every AWS resource name | `<prefix><name>` | `cg-dev-findings`, `cg-dev-scanner` |
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
| `reportOnlyReason` | S | scanner, action, engine workflow (re-check) | `protected` \| `autoscaling` \| absent |
| `classification` | S | scanner | EC2 only: `idle` \| `underused` \| `periodic` |
| `estimatedMonthlyCost` | N | scanner | absent for `MISSING_TAGS` or if never priced; a later scan that can't price it keeps the last estimate (logged as `price_unknown`). EC2: compute + auto-assigned public IPv4 (what stopping saves; EBS and Elastic IPs stay billed); EBS: storage + provisioned IOPS / throughput; EIP: public IPv4 hours. 730 h per month. |
| `estimatedSnapshotMonthlyCost` | N | scanner | `EBS_UNATTACHED` only: size × snapshot GB-month price (upper bound); the EBS timeline sets realized savings = `estimatedMonthlyCost` − this |
| `missingTags` | L | scanner | `MISSING_TAGS` only, e.g. `["owner","project"]` |
| `firstSeenAt` | S | scanner | start of the current episode; reset on reopen (§3.2) |
| `lastSeenAt` | S | scanner | every scan that still sees the problem |
| `lastNotifiedAt` | S | **notify only** | set after every successful send, on every finding in the email (§4.1) |
| `generation` | N | `common/timeline.py` | starts at 0; never reset; never a string |
| `executionName` | S | `common/timeline.py` | current timeline's name |
| `executionArn` | S | `common/timeline.py` | |
| `timelineStep` | S | engine workflow | `first_notice` \| `waiting` \| `final_warning` \| `acting` \| `done` (dashboard display) |
| `deadlineAt` | S | engine | when the action is due; also the expiry of Protect / Postpone links |
| `postponeCount` | N | `common/timeline.py` (postpone) | max `MAX_POSTPONES` |
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
| `open` / `in_progress` → `resolved` | scanner (via `timeline.stop_timeline` if a timeline runs), or the workflow's re-check | resource active / attached / associated / deleted / tags now present; or the workflow's `STOP_INSTANCE` found the instance already stopped by someone else (not dry-run). **Never applies to `remediated` findings** (see below). |
| `in_progress` → `remediated` | engine workflow | after stop, or snapshot + delete; also in dry-run, with `dryRun = true` |
| `in_progress` → `failed` | engine Catch branch (direct DynamoDB update) | sets `failedStep` (the workflow state's name), `errorMessage` (≤ 500 chars), `timelineStep = done`; only with the same generation and status `in_progress`. A failure after the finding left `in_progress` (the `STOP_CONFIRMATION` email) only writes a `workflow_failed` audit entry and fails the execution; the status is unchanged. |
| `failed` → `in_progress` | scanner via `timeline.start_timeline` | only if `restartCount < MAX_RESTARTS`; increments it |
| **`remediated` → `resolved`** | scanner | **EC2 only**, in exactly two cases: (a) instance `state = running` **and** `LaunchTime > remediatedAt` (someone really started it again); (b) the instance no longer exists or is `terminated`. |
| any → report-only | scanner (protect / autoscaling tag found), action Lambda (Protect), engine workflow (re-check) | scanner: `open` → set `reportOnlyReason`; `in_progress` / `failed` → `timeline.stop_timeline(id, type, "open", reason)`; `remediated` → unchanged. Action Lambda (Protect) as before: stop timeline, set `reportOnlyReason`, status `open`. Engine workflow re-check finds the protect tag → status `open`, `reportOnlyReason` `protected` |
| report-only → normal | scanner | tag removed while status is `open`: REMOVE `reportOnlyReason`; the timeline starts on the same scan |
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
| `actor` | S | `scanner` \| `workflow` \| `remediation` \| `notify` \| `action-link` \| `digest` \| `sample-seed` |
| `event` | S | `finding_opened`, `finding_resolved`, `finding_reopened`, `tags_copied`, `owner_found`, `notice_sent`, `final_warning_sent`, `instance_stopped`, `snapshot_created`, `volume_deleted`, `email_fallback`, `link_protect`, `link_postpone`, `link_restore`, `link_refused`, `workflow_failed`, `timeline_started`, `timeline_stopped` |
| `findingType` | S | if related to a finding |
| `region` | S | |
| `generation` | N | if related to a timeline |
| `dryRun` | BOOL | for actions |
| `result` | S | `ok` \| `error` \| `skipped` |
| `details` | M | free-form, small |
| `sample` | BOOL | true only on demo seed rows (dashboard/tools/seed_demo.py, demo stack only); readers treat them as sample data |

`workflow_failed` details: `failedStep`, `errorMessage`, `progress`, `executionName`.

Who writes each event:

| Writer | `actor` | Events |
|---|---|---|
| scanner | `scanner` | `finding_opened` (every new finding, all types incl. `MISSING_TAGS`), `finding_resolved`, `finding_reopened`, `tags_copied`, `owner_found` |
| `common/timeline.py` | the caller (`scanner` / `action-link`) | `timeline_started` (result `started` / `adopted` only; `generation` = the new one), `timeline_stopped` |
| notify | `notify` | `notice_sent`, `final_warning_sent`, `email_fallback` |
| remediation | `remediation` | `instance_stopped` (also a dry-run stop; not when someone else had stopped it), `snapshot_created`, `volume_deleted` |
| workflow (Step Functions) | `workflow` | `workflow_failed` |
| action Lambda | `action-link` | `link_protect`, `link_postpone`, `link_restore`, `link_refused` |
| demo seed (`dashboard/tools/seed_demo.py`) | `sample-seed` | `finding_opened`, `notice_sent`, `final_warning_sent`, `instance_stopped`, `volume_deleted` (demo stack only) |

Audit writes never raise; a failed write is logged (`audit_write_failed`). Shared writer: `common/audit.py`
`write_audit(...)`. No audit entry for the `STOP_CONFIRMATION` email (`instance_stopped` covers the action).
Several entries can share one second; their order within it is not defined (the `ts` suffix is random).

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
| `<prefix>daily-summaries` | `day` | `totalMonthlyWaste`, `realizedMonthlySavings`, `potentialMonthlySavings`, `countsByType` (M), `wasteByRegion` (M), `wasteByOwner` (M), `wasteByProject` (M), `openFindings`, `warningsSent`, `actionsTaken`, `actionsTakenDryRun`, `createdAt`, `sample` (BOOL, seed rows only) | daily-summary → dashboard, digest |
| `<prefix>bill-history` | `day` + `key` (`service#<name>` \| `project#<name>` \| `project#untagged` \| `total`) | `amount` (N, USD **per day**, rounded to **4** decimals: an exception to §2's 2-decimal monthly money, since daily amounts are fractions of a cent), `estimated` (BOOL, Cost Explorer's `Estimated`), `fetchedAt` | daily-cost → dashboard, digest |
| `<prefix>budget-alerts` | `budgetName` + `receivedAt` | `thresholdType` (`ACTUAL`/`FORECASTED`), `threshold`, `message`, `day` | budget-subscriber → dashboard, digest |
| `<prefix>counters` | `counterId` (e.g. `bedrock#2026-11-20`) | `count` (N), `ttl` | dashboard (conditional update) |

daily-summaries notes: one item per UTC day, overwritten by a re-run; the findings part is a snapshot at run time.
Active = open / in_progress / failed (resolved ignored). Waste and its breakdowns exclude MISSING_TAGS and
SNAPSHOT_REMINDER and include report-only; missing owner → `unknown`, missing project → `untagged`. `countsByType` /
`openFindings` count active findings incl. MISSING_TAGS. `warningsSent` = notice_sent + final_warning_sent that day;
`actionsTaken` = instance_stopped + volume_deleted that day, dry-run included (`actionsTakenDryRun` = those with
dryRun true). A remediated finding without `dryRun` counts as dry-run.
Demo seed rows carry sample = true; the dashboard marks them, the digest ignores them.

bill-history notes: amounts are usage cost **before credits** (Cost Explorer `UnblendedCost`, filter `RECORD_TYPE = Usage`;
net of credits every amount would be ~$0). Spend without a `project` tag is `project#untagged`. `total` = sum of
that day's `service#…` rows and is written for every fetched day, even when 0. Rows exist only for amounts > 0.

### 3.6 How the daily summary counts money

- **Waste:** `estimatedMonthlyCost` of findings with status `open`, `in_progress` or `failed` (not `MISSING_TAGS` or `SNAPSHOT_REMINDER`).
- **Realized savings:** `realizedMonthlySavings` of findings **currently** `remediated` **with `dryRun = false`**.
  A finding that leaves `remediated` (real restart, terminated) stops counting.
- **Potential savings:** findings `open` / `in_progress` (not report-only) **plus** `remediated` with `dryRun = true`.
  The potential savings of a dry-run `remediated` finding = its `realizedMonthlySavings` (else `estimatedMonthlyCost`).

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
  - Sent with SES v2 SendEmail (HTML + text). If SES rejects the recipient (`MessageRejected`, e.g. unverified in
    the sandbox), Notify rebuilds the email for the team address with new tokens and writes `email_fallback`
    (one per finding). A null `to` goes to the team address without a fallback entry. Any other send error, or a
    failure sending to the team address, is raised.
  - `DRY_RUN` does not suppress emails; templates show the dry-run state from `vars.dryRun`.
  - After the send, Notify writes `notice_sent` (FIRST_NOTICE) / `final_warning_sent` (FINAL_WARNING) audit entries,
    one per finding. Failures of post-send writes (audit, `lastNotifiedAt`) are logged, not raised, so a retry never
    resends the email.
  - Required variables (§4.2) must be present; money values may be null ("not estimated yet").
- `findings`: every finding this email is about (one for most templates, many for `DIGEST` and `MISSING_TAGS_GROUPED`).
  - Notify sets **`lastNotifiedAt`** on **every** listed finding after a successful send.
  - For each finding with non-empty `actions`, Notify creates one token per action (§3.4) and makes the URLs available to
    the template as `links["<resourceId>#<findingType>"]["<action>"]`.
  - Token writes go in batches of at most **25** (DynamoDB `BatchWriteItem` limit).
  - `actions` rules: `protect` / `postpone` only for `in_progress` `EC2_IDLE` / `EBS_UNATTACHED` findings,
    also on dry-run timelines (reversible, needed for testing); `restore` only on a non-dry-run
    `DELETE_CONFIRMATION`. Everything else (`EIP_*`, `MISSING_TAGS`, `SNAPSHOT_REMINDER`, report-only,
    dry-run `DELETE_CONFIRMATION`) gets `actions: []`. `expiresAt` is required when `actions` is non-empty.
- Output: `{ "sent": true, "recipient": "...", "fallback": false, "messageId": "...", "tokensCreated": 2 }`.
- Errors are raised (so Step Functions retries), not swallowed.
- Notify's role: `ses:SendEmail` on `identity/*` in us-west-2 with condition `ses:FromAddress` = sender (the
  sandbox also checks recipient identities), `dynamodb:BatchWriteItem` / `PutItem` on tokens, `dynamodb:UpdateItem`
  on findings limited to `lastNotifiedAt` (condition `dynamodb:Attributes`), `PutItem` on audit.

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

Notify accepts `elasticIps` missing / null (= empty) or a single string (= one item), because JSONata may drop
empty lists or unwrap one-item lists.

`DIGEST` `findings` items: `{resourceId, findingType, resourceType, region, status, estimatedMonthlyCost, costSoFar,
daysOpen, deadlineAt?, timelineStep?, reportOnlyReason?, name?}`. Every item also appears in the top-level `findings`
list of the Notify input (so it gets `lastNotifiedAt` and, if `in_progress`, its links).

### 4.3 Remediation — called by workflows only
Input: `{ "action": "<ACTION>", "resourceId": "...", "region": "...", "dryRun": true, "findingType": "...",
"generation": 1, ... }`. `findingType` and `generation` are optional (used only for the audit entry, §3.3);
the workflows pass both on every call.

| action | Extra input | Output |
|---|---|---|
| `CHECK_EC2` | — | `{ "stillIdle": bool, "protected": bool, "state": "running" }` |
| `STOP_INSTANCE` | — | `{ "stopped": bool, "dryRun": bool, "elasticIps": ["..."] }` |
| `CHECK_EBS` | — | `{ "stillUnattached": bool, "protected": bool, "exists": bool }` |
| `CREATE_SNAPSHOT` | — | `{ "snapshotId": "snap-...", "dryRun": bool }` |
| `SNAPSHOT_STATUS` | `snapshotId` | `{ "state": "pending" \| "completed" \| "error" }` |
| `DELETE_VOLUME` | `snapshotId` | `{ "deleted": bool, "dryRun": bool }` |

Dry-run: `CREATE_SNAPSHOT` returns `snapshotId: null`; `DELETE_VOLUME` skips the snapshot check. `STOP_INSTANCE` on an
instance that is already stopped returns `stopped: false, dryRun: false` (someone else stopped it; the workflow resolves
the finding).

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
start_timeline(resource_id, finding_type, reason, *, actor="scanner") -> {"result": str, "finding": dict}
    # reason / required status: new -> open, reopen -> open, restart -> failed (restartCount < MAX_RESTARTS,
    #   +1), postpone -> in_progress (stops the current execution first; postponeCount < MAX_POSTPONES, +1).
    # Status, limits and counters are checked/updated in the same conditional write that claims gen+1.
    # A new generation clears failedStep, errorMessage, deadlineAt, remediatedAt, resolvedAt, dryRun,
    #   realizedMonthlySavings.
    # result: started | adopted | already_running | lost_race | superseded.
    # started / adopted -> audit timeline_started (actor; generation; details startResult, reason, executionName).
stop_timeline(resource_id, finding_type, new_status, report_only_reason=None, *, actor="scanner") -> dict
    # StopExecution on the current execution (ignores "already finished"), updates status;
    # sets timelineStep = done only if the finding has an executionName.
    # -> audit timeline_stopped (actor; details newStatus, reportOnlyReason, stopResult, executionName).
```
`actor` is the audit actor (§3.3): the scanner uses the default, the action Lambda passes `"action-link"`.
No other code calls `StartExecution` / `StopExecution` directly.

### 4.6 Action API (API Gateway → Action Lambda)
- The HTTP API and its stage are created by **platform core** (§8); engine adds the route and the Lambda integration.
- `GET /action?t=<token>` → HTML confirmation page. Changes nothing.
- `POST /action` (form field `t`) → performs the action once, returns an HTML result page.
- Refusals (HTML page, HTTP 4xx, `link_refused` audit): unknown token, used, expired, older generation (points to the
  newest email), wrong finding status (§3.4), postpone limit reached, snapshot missing (restore).

### 4.7 Scheduled events (EventBridge Scheduler → Lambda)
`{ "source": "schedule", "job": "scan" | "daily-cost" | "daily-summary" | "digest" }`. Manual test runs send the same event.

`daily-cost` also takes an optional `"days"` (integer 1–90, default 3): it fetches the last `days` full UTC days up
to and including yesterday and overwrites their rows (Cost Explorer revises recent days, so every run re-fetches them).

## 5. Tags

| Tag | Values | Meaning |
|---|---|---|
| `owner` | email | person responsible |
| `project` | text | project name; cost allocation tag |
| `guardian:protect` | `true` | report-only; IAM denies stop / delete |
| `guardian:source-volume` | volume id | on snapshots the Guardian creates |
| `guardian:dev-scope` | a name prefix, e.g. `cg-dev-` | dev only: which personal stack may act on this test resource (§6) |
| `email` | email | on IAM users, for the CloudTrail lookup |

## 6. Configuration (Lambda environment variables)

| Variable | Used by | Example |
|---|---|---|
| `NAME_PREFIX` | all | `cg-dev-` |
| `TABLE_FINDINGS`, `TABLE_AUDIT`, `TABLE_TOKENS`, `TABLE_CREATOR_LOOKUPS`, `TABLE_VOLUME_ATTACHMENTS`, `TABLE_DAILY_SUMMARIES`, `TABLE_BILL_HISTORY`, `TABLE_BUDGET_ALERTS`, `TABLE_COUNTERS` | as needed | `cg-dev-findings` |
| `DRY_RUN` | engine, scanner (tag copying) | `true` |
| `SCAN_REGIONS` | scanner | `all` or `us-west-2,us-east-1` |
| `DEV_SCOPE` | scanner, engine, action | empty in the team stack; in personal stacks = `NAME_PREFIX`, and only resources tagged `guardian:dev-scope=<same>` are acted on or emailed |
| `DETECTION_WINDOW_MINUTES` | scanner, engine (remediation `CHECK_EC2`) | `30` (demo) / `1440` |
| `EC2_SFN_ARN`, `EBS_SFN_ARN` | `common/timeline.py` | |
| `WAIT_BEFORE_FINAL_SECONDS_EC2`, `WAIT_BEFORE_ACTION_SECONDS_EC2`, same for `_EBS` | scanner, action (passed into workflow input) | `120` |
| `POSTPONE_SECONDS` | action | `604800` (7 days); minutes in tests |
| `NOTIFY_FUNCTION_NAME` | scanner, digest, action, engine | `cg-dev-notify` |
| `SENDER_EMAIL`, `TEAM_EMAIL` | notify | |
| `ACTION_API_URL` | notify | output of platform core (§8) |
| `RESTORE_LINK_DAYS` | engine (sets restore `expiresAt`) | `30` |
| `BEDROCK_MODEL_ID` | digest, dashboard | `us.amazon.nova-2-lite-v1:0` (an inference profile ID) |
| `BEDROCK_DAILY_CAP` | dashboard | `30` |
| `BEDROCK_MAX_TOKENS` | digest, dashboard | `500` |
| `BEDROCK_MAX_QUESTION_CHARS` | dashboard | `500` |
| `MAX_POSTPONES`, `MAX_RESTARTS` | action, timeline | `2`, `2` |
| `EIP_STOPPED_THRESHOLD_HOURS` | scanner | `24` |

Thresholds (CPU / network / disk) and the idle classification live in `common/idle.py` (used by the scanner and the
remediation re-check), with the values decided by the team (design §24).

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
| `platform/terraform/core` | `team_email`, `sender_email` | `table_names`, `table_arns` (maps keyed `findings`, `audit`, `tokens`, `creator_lookups`, `volume_attachments`, `daily_summaries`, `bill_history`, `budget_alerts`, `counters`), `team_topic_arn`, `dlq_arn`, `notify_function_arn` / `name`, **`vpc_id`, `public_subnet_id`**, **`action_api_id`, `action_api_execution_arn`, `action_api_url`** (the HTTP API + `$default` stage, no routes) |
| `engine/terraform` | `table_names`, `table_arns`, `notify_function_arn` / `name`, `team_topic_arn`, `action_api_id`, `action_api_execution_arn`, `dev_scope`, `timeline_waits`, `postpone_seconds`, `detection_window_minutes` | `ec2_sfn_arn`, `ebs_sfn_arn`, `remediation_function_arn`, `action_function_arn` (engine adds the `/action` routes, the integration and the Lambda permission to core's API) |
| `scanner/terraform` | `table_names`, `table_arns`, sfn ARNs, `notify_function_name`, `scan_regions`, `dev_scope`, `timeline_waits`, `detection_window_minutes`, `eip_stopped_threshold_hours` | `scanner_function_arn` |
| `dashboard/terraform` | `table_names`, `table_arns`, `dlq_arn`, `bedrock_model_id`, `vpc_id`, `public_subnet_id`, **`origin_secret`** (sensitive), `notify_function_name` | `daily_cost_function_arn`, `daily_summary_function_arn`, `digest_function_arn`, `dashboard_instance_id`, `dashboard_public_dns` |
| `platform/terraform/edge` | `dashboard_public_dns`, `origin_secret`, `dashboard_username`, `dashboard_password` (all three sensitive) | `dashboard_url` |

- `timeline_waits` = object {ec2_before_final, ec2_before_action, ebs_before_final, ebs_before_action} in seconds (defaults §4.4);
  these and `detection_window_minutes`, `eip_stopped_threshold_hours`, `postpone_seconds` are variables of infra/stack.
- The dashboard module's inputs are added as each dashboard task needs them (#27 adds `dlq_arn`).
- `origin_secret`, `dashboard_username` and `dashboard_password` are sensitive variables of `infra/stack`, passed to the modules that need them.
- Notify's `ACTION_API_URL` comes from core's own API resource, so it never depends on engine.
- No module-level `depends_on` between lane modules (it would create hidden cycles).
- IAM roles for a Lambda live in the module that owns the Lambda; lane C reviews them.

## 9. Open values (to fill in as the team decides — design §24)

Detection thresholds · real detection window · Elastic IP "stopped too long" threshold ·
budget amounts.
(Defaults already set here: postpone = 7 days, max 2 postpones, max 2 restarts, restore link = 30 days, allowed instance types = t3.micro, t3.small (launch guardrails, `infra/shared`), Bedrock: Nova 2 Lite via `us.amazon.nova-2-lite-v1:0`, 30 questions/day, 500 output tokens, 500-char questions.)

## 10. Change log

- v1 — first draft.
- v2 — `remediated` → `resolved` rules with the `LaunchTime` check (fixes the dry-run reopen loop), EBS stays
  `remediated`, savings counting rules (§3.6, dry-run counts as potential); link targets and expiry, restore safety
  check (§3.4); Notify input reworked to a `findings` list with per-finding actions and 25-item batches, Notify owns
  `lastNotifiedAt` (§4.1); template variables defined (§4.2), new `REPORT_NOTICE` template; `MISSING_TAGS` emailed
  once then digest only; VPC and the action HTTP API moved into platform core, `origin_secret` passed to dashboard,
  module order fixed (§8); new settings `POSTPONE_SECONDS`, `RESTORE_LINK_DAYS`; `firstSeenAt` resets on reopen.
- v2.1 — removed `scheduled` from `reportOnlyReason` (office-hours scheduling set aside, design §21.1).
- v2.1 (Nov 21): team/sender address decided, removed from §9.
- v2.2 — §8: core exposes the tables as `table_names` / `table_arns` maps (keys listed); engine takes
  `dev_scope` (remediation and action Lambdas, §6).
- v2.2 (Nov 21): prefix examples now cg-dev-
- v2.3 — §4.5: start_timeline returns {result, finding}, checks status per reason, postpone stops the
  current execution and owns postponeCount (§3.1), new generations clear stale fields; stop_timeline sets
  timelineStep only for findings that had a timeline.
- v2.4 — §3.2 report-only rules for in_progress/failed/remediated and tag removal; §6
  EIP_STOPPED_THRESHOLD_HOURS; §8 timing inputs for scanner and engine.
- v2.5 — §8 engine takes `detection_window_minutes` and §6 `DETECTION_WINDOW_MINUTES` is also used by the engine
  (`CHECK_EC2` re-checks over the same window); idle thresholds and classification moved to `common/idle.py`.
  §3.1 / §3.2: the workflow re-check sets report-only (protect tag → `open`, `reportOnlyReason` `protected`), and a
  `STOP_INSTANCE` that finds the instance already stopped by someone else (not dry-run) resolves the finding.
  §4.1: protect / postpone links also on dry-run timelines. §4.3: dry-run outputs of `CREATE_SNAPSHOT` /
  `DELETE_VOLUME` and the already-stopped `STOP_INSTANCE` result.
- v2.6 — §4.1: SES v2 send and MessageRejected fallback with new tokens, DRY_RUN doesn't suppress
  emails, Notify writes notice_sent / final_warning_sent, post-send write failures are not raised, null money
  values allowed, Notify role scoped by ses:FromAddress and dynamodb:Attributes; §4.2 elasticIps tolerance.
- v2.7 — §3.2 Catch rules (failedStep / errorMessage, condition, failure after remediation); §3.3
  workflow_failed details.
- v2.8 — §3.1 `estimatedSnapshotMonthlyCost`; what `estimatedMonthlyCost` covers per resource type.
- v2.9 — §9: allowed instance types decided (t3.micro, t3.small; launch guardrails in `infra/shared`, #25).
- v2.10 — §6 / §9: Bedrock model decided (Amazon Nova 2 Lite, US geo inference profile), daily cap,
  answer and question limits; new `BEDROCK_MAX_QUESTION_CHARS` (#15).
- v2.11 — §3.3 who writes each audit event, audit writes never raise; §4.3 remediation takes findingType /
  generation; §4.5 timeline writes timeline_started / timeline_stopped, new `actor` argument (#29 follow-up).
- v2.12 — §3.5 bill-history amounts per day (4 decimals, usage before credits, project#untagged);
  §4.7 daily-cost `days`; §8 dashboard takes `dlq_arn` (#27).
- v2.13 — §3.5 daily-summaries rules and new `actionsTakenDryRun`; §3.6 potential savings of dry-run
  remediated findings; SNAPSHOT_REMINDER not waste; missing dryRun = dry-run (#28).
- v2.14 — §3.3 / §3.5 `sample` marker and `sample-seed` actor for demo seed rows; §3.6 waste
  excludes SNAPSHOT_REMINDER, matching §3.5 (#26).
- v2.15 — §8 edge takes `dashboard_username` (each deployment chooses its login; default `guardian`) (#38).
