# Cloud Cost Guardian — Full Project Design

> **Purpose of this file:** the single, complete description of the Cloud Cost Guardian project for the whole team (and for any AI assistant helping us). It combines the original design with all the new features and decisions, and **replaces** `cloud-cost-guardian-project.md` and `cloud-cost-guardian-new-features.md` as the reference. Anyone should be able to understand the goals, design, rules and decisions from this file alone.

---

## 1. Context

| Item | Details |
|---|---|
| Course | CMPS 297U – Cloud Computing (AUB) |
| Deliverable | Team project: proposal (submitted October 11, 2026), then implementation and demo |
| Team | Roda Fadlallah, Ahmad El Amine, Khaled Sabeh Ayoun, Meryem Saadouni |
| Status | Setup started (November 20, 2026): Terraform state bucket, account budget alert, Git repo, first IAM user. Implementation follows `CONTRACT.md` and `CLAUDE.md` (§23.4). |
| Last updated | November 20, 2026 (v3) |
| AWS account | One shared sandbox account used only for this project, on the AWS **free plan** (with Free Tier credits) |
| Regions | **All enabled regions** are scanned (§8.1). The Guardian itself is deployed in us-west-2 (US West, Oregon). |
| Infrastructure as code | Terraform for everything Terraform can create; the console only for the few one-time steps it can't (professor's guidance; listed in `docs/manual-setup.md`) |
| Course requirement | Use EC2 or EKS: met by hosting the dashboard on EC2 (§6.3) |

**Project title:** Cloud Cost Guardian: Serverless Detection and Safe Remediation of Idle AWS Resources using EventBridge, Lambda, DynamoDB & SNS.

---

## 2. Problem and goal

Cloud bills often grow because of **forgotten resources** rather than heavy usage: idle EC2 instances, unattached EBS volumes, unused Elastic IPs, untagged resources. Students and small teams running on Free Tier credits lose budget silently this way.

The Guardian is an **automated FinOps tool** that:

1. Scans every enabled region of an AWS account on a schedule.
2. Detects wasteful resources and estimates their monthly cost.
3. Finds the owner of each resource (from tags, from its instance, or from CloudTrail) and emails them, with reminders until someone acts.
4. Runs a **warning timeline** for each wasteful resource (as a Step Functions workflow), then safely remediates what can be undone: stops idle instances, snapshots then deletes unattached volumes. Only after warnings, and only for resources the owner has not protected.
5. Lets owners respond in **one click** from the email (protect, postpone, restore).
6. Never performs irreversible actions on its own (deleting snapshots, releasing Elastic IPs).
7. **Prevents** waste at launch with IAM guardrails (required tags, allowed instance types).
8. Tracks real spending with **AWS Budgets** and **Cost Explorer**, and shows waste, savings and the real bill on a **dashboard** with charts.
9. Explains everything in plain language with an **AI assistant** (Amazon Bedrock): a weekly summary and a question box on the dashboard.
10. Logs every finding and action for auditing.

The scanning and remediation **engine** is serverless (Lambda, Step Functions): it works only a few minutes every few hours, so it must cost almost nothing, scale with account size and need no always-on server. The **dashboard** runs on a small EC2 instance, because it must be always available and interactive, and it is the starting point for a full web application later.

---

## 3. Scope and product approach

### 3.1 Monitored services (only these three)

- **EC2 instances**
- **EBS volumes** (and the snapshots the Guardian creates)
- **Elastic IPs**

Other services (load balancers, NAT gateways, S3, RDS, CloudWatch Logs, snapshots not created by the Guardian) were discussed but are **out of scope**.

### 3.2 Product approach: use existing AWS services smartly

The goal is **not to rebuild tools AWS already offers**, but to combine existing services into one product. For each need, we compared building it ourselves with using an AWS service (§20), and picked the AWS service whenever it is free or very cheap and does the job well.

The Guardian's own value is the **glue**: collecting what these services report, applying our rules (protect tag, warnings before actions, reversible-only automation), routing everything to the right owner, and showing it all in one dashboard.

**Where we still build our own logic, and why:**

- **Detection** of idle EC2, unattached EBS and unused Elastic IPs: AWS's equivalent (Trusted Advisor cost checks) requires a paid Business support plan. Our scanner uses free APIs and free basic CloudWatch metrics.
- **Guardian-specific savings data:** no AWS service knows which savings came from the Guardian's actions; only our own records in DynamoDB do.

---

## 4. Guiding principles

1. **Automate what is reversible; leave irreversible actions to a person.**
   - Stopping an instance → reversible → automated.
   - Deleting a volume after snapshotting it → reversible (restore from snapshot) → automated.
   - Adding labels (tag copying, setting `owner`) → reversible → automated.
   - Deleting a snapshot, releasing an Elastic IP → irreversible → never done by the Guardian.
2. **Metrics show inactivity, not importance.** Some important resources look idle (standby servers, in-memory workloads, rarely used tools). So every automatic action is preceded by warnings, and owners can protect resources.
3. **Safety rules are enforced by IAM, not only by code.** Even a bug cannot stop a protected instance, delete a protected volume, delete a snapshot, or release an Elastic IP.
4. **Dry-run by default.** Actions are logged but not executed until dry-run is turned off.
5. **Prevent before detecting.** IAM guardrails stop untagged or oversized launches before they become waste.
6. **Use existing AWS services where they fit** (§3.2).
7. **Stay at about $0 of actual spend.** Free tiers and free APIs wherever possible; the few small paid items are listed in §18.

---

## 5. Decisions at a glance

| Feature | Status | How |
|---|---|---|
| Multi-region detection of idle EC2, unattached EBS, unused Elastic IPs, missing tags | **In scope** | Our scanner (Lambda) |
| Warning timelines and remediation | **In scope** | AWS Step Functions + Lambda |
| Tag copying from instances | **In scope** | Our scanner |
| Finding who created untagged resources | **In scope** | CloudTrail event history lookup |
| Launch guardrails | **In scope** | IAM policy conditions |
| Skip Auto Scaling instances | **In scope** | Rule in the scanner |
| Owner emails, weekly digest, grouped missing-tag emails | **In scope** | Amazon SES + Notify Lambda (§10.5) |
| Team alerts (budgets, failures) | **In scope** | SNS (§10.5) |
| Email action links (protect, postpone, restore) | **In scope** | API Gateway + Lambda, random one-time tokens |
| One timeline per resource (no duplicates) | **In scope** | Step Functions execution names with generations (§9.1) |
| Workflow failure handling | **In scope** | Step Functions Catch + CloudWatch alarms (§9.1) |
| Account spend limit and forecast | **In scope** | AWS Budgets |
| Per-project spending limits | **In scope** | AWS Budgets filtered by `project` tag |
| Real bill history | **In scope** | AWS Cost Explorer API, once a day |
| Savings and waste charts | **In scope** | Our own charts on the EC2 dashboard |
| Dashboard | **In scope** | EC2 instance (t3.micro) in our own VPC |
| Dashboard HTTPS and team password | **In scope** | CloudFront + CloudFront Function (basic auth, §6.4) |
| AI assistant (weekly summary + questions) | **In scope** | Amazon Bedrock |
| Spending spike detection | Set aside | AWS Cost Anomaly Detection |
| Guardian health dashboard | Set aside | Amazon CloudWatch |
| Dashboard action buttons | Set aside | (needs login) |
| Dashboard per-person login | Set aside | Amazon Cognito |
| Opt-in automatic Elastic IP release | Set aside | `guardian:auto-release=true` tag |
| Real-time detection | Not used | (was CloudTrail + EventBridge) |
| Office-hours scheduling | Set aside | Instance Scheduler on AWS |
| Optimization recommendations | Set aside | AWS Compute Optimizer |
| Resource leases, CI/CD | Set aside | (§21.1) |
| Approvals for expensive launches, Slack/Teams, leaderboard, carbon estimate | Dropped | (§21.2) |

---

## 6. Architecture

### 6.1 Components

| Component | Role |
|---|---|
| **EventBridge Scheduler** | Triggers the Scanner Lambda (default every 3 hours), the daily cost Lambda, the daily summary Lambda, and the weekly digest Lambda. |
| **Scanner Lambda** | Loops over every enabled region; describes resources, reads CloudWatch metrics, classifies findings, copies tags, looks up creators in CloudTrail, estimates cost, writes findings to DynamoDB, and starts or stops Step Functions workflows. Treats Auto Scaling and protected instances as report-only. |
| **Step Functions (Standard workflows)** | One workflow per idle instance or unattached volume: notices, waits, re-checks, then the action (§9). Named by resource and generation so a resource never has two; a Catch branch handles failures. |
| **Remediation Lambda** | Called by the workflows: stops instances, creates snapshots, deletes volumes, checks state. |
| **Notify Lambda** | Builds every owner email from HTML templates, creates the action-link tokens, and sends through SES (§10.5). |
| **Digest Lambda** | Builds the weekly digest per recipient, adds the Bedrock summary, sends it through the Notify Lambda. |
| **Daily cost Lambda** | Calls the Cost Explorer API once a day and stores the bill history. |
| **Daily summary Lambda** | Once a day, computes waste and savings from the findings (§11.4) and writes the daily summary record. Kept separate from the daily cost Lambda so each has one job and one owner. |
| **Budget alert subscriber Lambda** | Subscribed to the team SNS topic; stores each AWS Budgets alert in DynamoDB for the digest and dashboard. |
| **API Gateway + Action Lambda** | Handles email action links over HTTPS: protect, postpone, restore (§10.4). |
| **DynamoDB** | Findings, creator lookups, audit log, daily summaries, bill history, budget alerts, link tokens (hashed), question counter. |
| **Amazon SES** | Delivers personal emails to owners: notices, warnings, confirmations, digests (§10.5). |
| **SNS** | Team alerts only: receives AWS Budgets alerts and CloudWatch alarms, emails the team address. |
| **SQS dead-letter queue + CloudWatch alarms** | Failed asynchronous invocations are retried, then sent to the DLQ. Alarms fire on DLQ messages and on failed or timed-out workflows (§9.1). |
| **AWS Budgets** | Account budget and one budget per project, with actual and forecast alerts to SNS (§11.2). |
| **AWS Cost Explorer** | Source of the real bill history (§11.3). |
| **CloudTrail event history** | Searched by the scanner to find who created an untagged resource (§8.6). |
| **Amazon Bedrock** | Weekly AI summary and the dashboard's question box (§12). |
| **EC2 dashboard server** | t3.micro running the dashboard web app; tagged `guardian:protect=true` (§6.3). |
| **CloudFront + CloudFront Function** | The dashboard's only entrance: HTTPS and a team password check (§6.4). |
| **Own VPC + security group** | Network for the dashboard instance, defined in Terraform; accepts web traffic only from CloudFront (§6.4). |
| **CloudWatch** | Metrics for detection, Lambda logs, the DLQ and workflow alarms. |
| **IAM** | Least-privilege role per component; deny rules for protected resources; launch guardrails for team users (§16). |
| **Terraform** | Provisions everything; `terraform apply` / `terraform destroy`. |

### 6.2 Data flow

```
EventBridge Scheduler ──► Scanner Lambda (all enabled regions)
                            ├─ reads EC2 / EBS / Elastic IPs / CloudWatch metrics
                            ├─ copies tags from instances; looks up creators in CloudTrail; sets owner
                            ├─ Auto Scaling and protected instances: report-only
                            ├─ writes findings ──► DynamoDB
                            └─ starts / stops workflows (named <type>-<id>-gen<N>) ──► Step Functions

Step Functions workflow ──► first notice & final warning (Notify Lambda ──► SES email with action links)
                        ──► re-check ──► Remediation Lambda (stop / snapshot + delete)
                        ──► confirmation email + audit log (DynamoDB)
                        ──► on failure: Catch step marks the finding failed + audit log

Email action link ──HTTPS──► API Gateway ──► Action Lambda
                                              ├─ protect / postpone / restore
                                              ├─ stops or restarts the workflow
                                              └─ audit log (DynamoDB)

Daily cost Lambda ──► Cost Explorer API ──► DynamoDB (bill history)
Daily summary Lambda ──► findings ──► DynamoDB (daily summary)
AWS Budgets ──► SNS ──► team email + DynamoDB (budget alerts) ──► digest + dashboard
Weekly digest Lambda ──► Bedrock (summary) ──► Notify Lambda ──► SES email per recipient
Failures ──► SQS dead-letter queue / failed workflows ──► CloudWatch alarms ──► SNS ──► team email

Browser ──HTTPS──► CloudFront (team password check) ──HTTP──► EC2 dashboard server (own VPC, t3.micro, protected)
                   ├─ reads DynamoDB (findings, savings, bill history, budget alerts)
                   ├─ draws charts
                   └─ "Ask about my costs" ──► Bedrock (global daily cap)

Team IAM users ──► IAM guardrail policy (required tags, allowed instance types)
```

### 6.3 EC2 for the dashboard

The course requires using EC2 or EKS, so the **dashboard runs on an EC2 instance**, while the engine stays serverless.

- **Why the dashboard:** it must be always available and interactive, unlike the engine, which only runs a few minutes every few hours. It is also the starting point for a full web application later.
- **What it runs:** the dashboard UI and a read-only API reading DynamoDB, the savings and bill charts (§11.4), and the "Ask about my costs" box (§12).
- **Why not EKS:** its control plane alone costs about $73/month, which conflicts with the project's ~$0 budget.
- **Why not a static S3 page + API Gateway + Lambda:** cheaper, but harder to grow into a full app, and doesn't meet the EC2 requirement.
- **Protected by our own rule:** the instance is tagged `guardian:protect=true`. It looks idle when nobody uses it, so the Guardian reports it but never stops it, which demonstrates the protect tag live.
- **Security:** reached only through CloudFront with a team password (§6.4); a security group accepting web traffic only from CloudFront (SSH only through EC2 Instance Connect); an IAM instance role with only the permissions it needs (§16); no access keys on the server; an encrypted root volume. The web server refuses requests without the secret origin header (§6.4), and **rate-limits per visitor**: a counter per visitor IP, read from the `CloudFront-Viewer-Address` header (e.g., 60 requests per minute each; over the limit → `429 Too Many Requests`). The counters live in memory, since there is one server. A limit by connecting IP wouldn't work, because behind CloudFront every request comes from a CloudFront server.
- **Cost:** about $7–8/month on-demand plus its public IPv4 address, unless covered by Free Tier or credits. Stop it when not working on the project; its auto-assigned public IP and DNS name change after each stop and start, so run `terraform apply` after starting it to update CloudFront's origin (§6.4).

### 6.4 Networking and dashboard access

**Decision:** our **own small VPC defined in Terraform** (not the default VPC), with **CloudFront and a team password** in front of the dashboard. It costs nothing, makes every network setting explicit in code, and shows the course's VPC material instead of relying on AWS defaults.

```
Browser ──HTTPS──► CloudFront ── CloudFront Function (checks team password) ──HTTP──► EC2 dashboard
```

**VPC resources (all free):**

| Resource | Setting | Why |
|---|---|---|
| VPC | Small CIDR, e.g., `10.20.0.0/24` | Our own isolated network for the dashboard |
| Public subnet | One subnet, e.g., `10.20.0.0/26`, in one Availability Zone | The instance needs a public address; one AZ is enough for a demo tool |
| Internet gateway | Attached to the VPC | Lets CloudFront reach the instance and the instance call AWS APIs (DynamoDB, Bedrock) |
| Route table | `0.0.0.0/0` → internet gateway, associated with the public subnet | The route supplies the path; the security group still decides what is allowed |
| Security group | Inbound port 80 **only from the CloudFront prefix list** (`com.amazonaws.global.cloudfront.origin-facing`); port 22 **only from the EC2 Instance Connect prefix list** of our region (`com.amazonaws.us-west-2.ec2-instance-connect`); all outbound allowed | Only CloudFront can reach the web server (the secret origin header, below, narrows that to *our* distribution); SSH works only through EC2 Instance Connect |
| Network ACL (optional) | Allow inbound 80 and 22, and return traffic on ephemeral ports (1024–65535); deny everything else | Subnet-level second layer; stateless, so reply ports must be allowed explicitly |

**How CloudFront is set up:**

1. A **CloudFront distribution** uses the instance as its origin (its public DNS name, HTTP on port 80). The team opens the dashboard at `https://<id>.cloudfront.net`; CloudFront's own certificate provides HTTPS, so no certificate is set up on the instance.
2. **Viewer protocol policy:** redirect HTTP to HTTPS, so the password is never sent unencrypted.
3. **Caching disabled** (managed `CachingDisabled` policy): CloudFront is used for HTTPS and protection, not speed, and the dashboard data must always be fresh. Allowed methods include POST, for the question box.
4. A **CloudFront Function** (viewer request) checks every request for the team username and password (HTTP basic auth). A request without them gets a `401` and a browser login prompt, and never reaches the instance.
5. **Secret origin header:** our distribution adds a custom origin header with a random secret (e.g., `X-Origin-Verify: <random value>`), and the web server refuses (`403`) any request without the right value. The security group alone isn't enough: the CloudFront prefix list contains **every** CloudFront server, so someone could create their own distribution pointing at our instance's DNS name, pass the security group and skip our password function. The prefix list stops everything that isn't CloudFront; the secret header stops other people's distributions. The secret is a sensitive Terraform variable, like the password.
6. **Origin request policy** that forwards the **`CloudFront-Viewer-Address`** header (the visitor's real IP and port, set by CloudFront itself, free), for the web server's per-visitor rate limit (§6.3).

With the security group and the secret header together, the instance can't be reached except through our distribution, even if its IP or DNS name is known.

**Password handling:** one shared team password, passed to Terraform as a sensitive variable (e.g., in an uncommitted `terraform.tfvars`) and placed into the function at deploy time; **never committed to Git**. To change it, update the variable and run `terraform apply`. (CloudFront KeyValueStore could hold it instead, to change it without redeploying.)

**Origin address changes:** the instance's public DNS name changes every time it is stopped and started. After starting it, run `terraform apply` to update the origin. An Elastic IP would avoid this, but it is billed while the instance is stopped, and the Guardian would report it as waste.

**What stays out, and why:**

- **No private subnets or NAT Gateway:** a NAT Gateway costs about $32/month, and nothing needs to be private: the dashboard is the only resource in the VPC, and it is locked down by the security group.
- **No paid VPC endpoints:** the instance reaches DynamoDB and Bedrock over their public HTTPS endpoints. A free DynamoDB gateway endpoint can optionally keep that traffic inside AWS.
- **The Guardian's Lambdas stay outside the VPC** (the default). They only call AWS APIs; inside a VPC they couldn't reach them without a NAT Gateway or paid endpoints.

**Notes:**

- The CloudFront prefix list counts as **55 rules** against the security group's rule limit (60 inbound by default), so keep the group's other rules few.
- **Identifying visitors:** behind CloudFront, the connecting IP is always a CloudFront server. The visitor's real IP is in `CloudFront-Viewer-Address` (preferred: one value, set by CloudFront). As a fallback, CloudFront also appends it to the **end** of `X-Forwarded-For`; only that **last** entry can be trusted, because a visitor can put fake addresses at the front. Both are trustworthy only because nothing but our distribution can reach the server (security group + secret header).
- **Cost:** free at our scale (CloudFront's always-free tier covers 1 TB of data and 10 million requests per month; CloudFront Functions include 2 million free invocations per month). Effort: about 3–4 hours including the password function, about 30 minutes for the secret header and the per-visitor rate limit, plus 2–3 hours for the VPC.

**Security layers (network, AWS permissions, application):**

| Layer | What it controls | In the Guardian |
|---|---|---|
| Network | Who can reach the dashboard | CloudFront as the only entrance (HTTPS); route table; security group accepting only CloudFront (and Instance Connect for SSH); secret origin header so only *our* distribution is accepted; optional NACL |
| IAM | What our code may do in AWS | Least-privilege role per function (§16); instance role, no access keys; deny on `guardian:protect=true`; no `ec2:DeleteSnapshot` or `ec2:ReleaseAddress`; guardrails for team members (§8.7) |
| Application | Who the user is and what they may do | Team password at CloudFront; per-visitor rate limit on the web server (§6.3); single-use, expiring email action links with a confirmation step (§10.4); dashboard is read-only; Bedrock box with a global daily cap and answer length limit (§12) |

**Remaining gap:** the shared password tells us someone is *on the team*, not *which* team member. That is enough for a read-only dashboard. Per-person accounts (Cognito, §21.1) are only needed if dashboard action buttons are added later.

**Terraform resources:** `aws_vpc`, `aws_subnet`, `aws_internet_gateway`, `aws_route_table`, `aws_route_table_association`, `aws_security_group` (with `aws_ec2_managed_prefix_list` data sources for CloudFront and EC2 Instance Connect), optionally `aws_network_acl`, `aws_cloudfront_distribution` (with the secret custom origin header), `aws_cloudfront_function`, and `aws_cloudfront_origin_request_policy` (forwarding `CloudFront-Viewer-Address`).

---

## 7. Tags

| Tag | Meaning | Who sets it |
|---|---|---|
| `owner` | **Email address** of the person responsible. Used to route emails. Required at launch (§8.7). | Resource owner, or the Guardian (copied from an instance or found in CloudTrail) |
| `project` | Project name. Required at launch. Also activated as a cost allocation tag for per-project budgets. | Resource owner, or the Guardian (copied from an instance) |
| `guardian:protect=true` | Never stop or delete this resource; findings are report-only. Enforced by IAM. Can be added with the "Protect" action link. | Resource owner |
| `guardian:source-volume=<volume id>` | Marks a snapshot created by the Guardian and links it to its original volume. | Guardian |
| `email` (on IAM users) | Email of each team member, used to map CloudTrail identities to owners (§8.6). | Team admin |
| `guardian:dev-scope=<name prefix>` | **Development only:** marks a test resource as belonging to one person's personal stack, so that stack acts on and emails only its own test resources (§23.4). Not used in the team stack. | Team member creating test resources |
| `aws:autoscaling:groupName` | Added automatically by AWS to Auto Scaling instances; the Guardian treats them as report-only (§8.5). | AWS |

Notes:

- Tags are **case-sensitive**: `true` ≠ `True`.
- Tags on an instance **do not** copy to its volumes or Elastic IPs automatically. At launch, the console's "Resource types" setting decides whether volumes get the tags (select both **Instances** and **Volumes**). The Guardian copies missing tags itself (§8.6).
- The earlier opt-in tag `guardian:auto-stop=true` was **dropped** in favor of opt-out with `guardian:protect=true`.

---

## 8. Detection, owners and prevention (FR2)

### 8.1 Multi-region scanning

- The Guardian is deployed once (in us-west-2) but scans **every enabled region**, so a resource launched in the wrong region by mistake is still found.
- Each scan starts with `DescribeRegions`, then runs all detection rules in each region with regional API clients.
- An optional configuration list can restrict scanning to specific regions (e.g., for the demo).
- Every finding stores its `region`, which appears in emails and on the dashboard. Remediation runs in the resource's own region, and cost estimates use that region's prices (§11.1).
- Regions can be scanned in parallel to stay within the 60-second target; if the scan grows too large, it can be split into one Lambda invocation per region.

### 8.2 EC2: idle instances (multi-signal)

Checked on **running instances only** (a stopped instance sends no CPU data and must not be flagged as idle).

Signals, all free basic CloudWatch metrics (5-minute granularity), over a detection window, read with `GetMetricStatistics` (covered by the free API allowance; `GetMetricData` is always billed):

| Signal | Metric | Catches |
|---|---|---|
| CPU | `CPUUtilization` (average **and** maximum) | Computation; periodic jobs show in the max |
| Network | `NetworkIn`, `NetworkOut` | Web servers, APIs, anything serving requests |
| Disk | `VolumeReadOps`, `VolumeWriteOps` on attached EBS volumes | Databases, file processing, logging |

Classification:

| Result | Condition | Action |
|---|---|---|
| **Idle** | CPU, network and disk all below thresholds | Warning workflow starts (§9.1) |
| **Underused** | CPU low, but network or disk active | Never stopped |
| **Periodic** | Low averages, spikes in the max values | Never stopped |

- Thresholds are **small but non-zero**, because an idle Linux instance still has background traffic (updates, time sync, AWS agents).
- Precedent: AWS Trusted Advisor's (legacy) "Low Utilization Amazon EC2 Instances" check flags instances with daily CPU ≤ 10% and network I/O ≤ 5 MB on at least 4 of the last 14 days. We borrow the idea; we do **not** use Trusted Advisor (its cost checks need a paid Business support plan).
- Detection window: **30 minutes for the demo only**; the real tool uses a realistic window (e.g., 24 hours or longer).

### 8.3 EBS: unattached volumes

- `DescribeVolumes` with filter `status=available`.
- Common causes: instance terminated but extra volumes kept (`DeleteOnTermination` is false by default for non-root volumes), volume detached and forgotten, volume created and never attached.
- EBS does not record when a volume was detached, so the Guardian stores `firstSeenAt` when it first sees the volume unattached.

### 8.4 Elastic IPs

- `DescribeAddresses`.
- **Unassociated:** no `AssociationId`.
- **Associated with a stopped instance:** billed but serving nothing. Reported only after the instance has been stopped longer than a set threshold (using `firstSeenAt`).

### 8.5 Instances the Guardian must not stop

- **Auto Scaling instances** (tag `aws:autoscaling:groupName`): report-only. If the Guardian stopped one, the group would mark it unhealthy and launch a replacement, so nothing would be saved. The email suggests scaling the group down instead.
- **Protected instances** (`guardian:protect=true`): report-only.

### 8.6 Missing tags and owner identification

Scanner order: **copy tags first, then look up creators, then report what is still missing, then run the other checks.**

**1. Tag copying (from the instance)**

- If an **attached volume** or **associated Elastic IP** is missing `owner` or `project` and its instance has them, the Guardian copies them (`ec2:CreateTags`) and logs it.
- Purpose: the resource keeps its owner after the instance is terminated, so later emails reach the right person.

**2. Creator lookup (CloudTrail event history)**

When a resource still has no `owner`:

1. The scanner finds the resource's **creation event** with `LookupEvents`:
   - **Instances:** `RunInstances`, looked up by the instance ID.
   - **Elastic IPs:** `AllocateAddress`, looked up by the allocation ID.
   - **Volumes:** see "Volumes: find the instance first" below, because volumes created at launch can't be found by their own ID.
2. The event shows **which IAM identity** made the call.
3. The scanner maps the identity to an email:
   - **IAM user:** reads the user's `email` tag (`iam:ListUserTags`).
   - **Role session** (single sign-on, Terraform, automation): uses the session name if it is an email; otherwise the creator is unknown.
4. If an email is found, the Guardian sets `owner` to it and logs the change.
5. If not (older than 90 days, root user, shared login, automation role), the missing-tag email goes to the team address.
6. The result is stored in DynamoDB, so each resource is looked up **only once**.

**Volumes: find the instance first.** CloudTrail does **not** record a `CreateVolume` event for volumes created during an instance launch, and the `RunInstances` event doesn't include their volume IDs. Volumes attached and detached through `RunInstances` and `TerminateInstances` have no events of their own at all. So a volume left behind after its instance was terminated (the most common orphaned volume) can't be found by its own ID. The scanner tries, in order:

1. **`CreateVolume` event**, looked up by the volume ID. Works for volumes created on their own.
2. **The scanner's own record of the last instance the volume was attached to.** On every scan, for each attached volume, the scanner saves "volume → instance ID" in DynamoDB (it already looks at attached volumes when copying tags). Once the volume is unattached, the scanner looks up that instance's `RunInstances` event by the instance ID.
3. **`AttachVolume` or `DetachVolume` event**, looked up by the volume ID, if the volume was attached or detached by hand. The event names the instance, which leads to its `RunInstances` event as in step 2. (If only a `DetachVolume` event is found, its caller is the person who detached the volume, used as the owner only if no creator is found.)
4. **Nothing found:** the missing-tag email goes to the team address.

This matters less than it sounds: the launch guardrails (§8.7) require tags on volumes at launch, and tag copying gives attached volumes their instance's owner. The lookup is mainly for older resources and anything created by the root user or before the guardrails existed.

Requirements and limits:

- **Each team member must have their own IAM user** with an `email` tag. With a shared login or the root user, CloudTrail sees one identity for everyone and the lookup is useless.
- CloudTrail event history covers only the **last 90 days** (free). For volumes, that's 90 days from the *instance's* launch, in step 2.
- The "last attached instance" record only exists for volumes the scanner saw while still attached, so volumes already orphaned before the Guardian was deployed rely on steps 1 and 3.
- `LookupEvents` allows about **2 requests per second, per account, per region**: only untagged resources are looked up, each only once, with retries on throttling errors.

**3. Reporting what is still missing**

- Resources still missing `owner` or `project` after steps 1–2 are flagged (§10.2 for the emails).

### 8.7 Launch guardrails (prevention)

An IAM policy attached to the **team's IAM group** (not to the Guardian's own roles) with **deny** rules.

**Each rule must be limited to the right resources.** A single `RunInstances` call is checked against several resources at once: the instance and its volumes, but also the network interface, subnet, security group, AMI and key pair. Tags are only placed on the instance and its volumes. If a tag rule applied to every resource (`"Resource": "*"`), IAM would find no `owner` tag on the network interface or subnet and refuse **every** launch, even correctly tagged ones.

| Deny rule | Condition | Applies only to |
|---|---|---|
| `ec2:RunInstances` without `owner` / `project` | `"Null": {"aws:RequestTag/owner": "true"}` (same for `project`) | `arn:aws:ec2:*:*:instance/*`, `arn:aws:ec2:*:*:volume/*` |
| `ec2:CreateVolume` without the tags | Same | `arn:aws:ec2:*:*:volume/*` |
| `ec2:AllocateAddress` without the tags | Same | `arn:aws:ec2:*:*:elastic-ip/*` |
| `ec2:RunInstances` with a type outside the allowed list | `"StringNotEquals": {"ec2:InstanceType": ["t3.micro", "t3.small"]}` | `arn:aws:ec2:*:*:instance/*` only |
| `owner` that doesn't look like an email (optional) | `"StringNotLike": {"aws:RequestTag/owner": "*@*"}` | Instance and volume resources |
| `ec2:CreateSnapshot` without the tags (optional) | `"Null"` on the tags, as above | `arn:aws:ec2:*:*:snapshot/*` |

The other launch resources (network interface, subnet, security group, AMI, key pair) don't need tags: most are existing resources that the launch only uses, and the network interface is deleted with the instance. The Guardian monitors instances, volumes and Elastic IPs, and all three are covered. The snapshot rule is optional because the Guardian only tracks its own snapshots.

**Testing with `--dry-run` (free):** `aws ec2 run-instances --dry-run ...` launches nothing and costs nothing. AWS replies `DryRunOperation` if the launch would be allowed, or `UnauthorizedOperation` if refused. Test cases:

1. Tags on instance and volume, allowed type → **allowed**
2. No tags → **refused**
3. Tags on the instance but not the volume → **refused**
4. Instance type outside the list (e.g., m5.large) → **refused**
5. `CreateVolume` and `AllocateAddress` with and without tags → refused only without

**Limitation: it stops mistakes, not deliberate bypassing.** Team members are admins in the account, so any of them could detach the guardrail policy from their group, and IAM never restricts the root user. The guardrail reliably catches the realistic risk for a student team: forgetting tags or picking a large instance by accident.

*Considered:* **service control policies (SCPs) in AWS Organizations**, which set a ceiling that even account admins and the member account's root user can't remove. Not used because:

- SCPs don't apply to an organization's **management account**, so the project would need a second AWS account under it.
- Enabling Organizations (or IAM Identity Center) on a **free-plan account** upgrades it to the paid plan, and the remaining Free Tier credits expire immediately (upgrading to the paid plan first keeps them, but the account is then pay-as-you-go).
- SCPs don't replace IAM anyway: they only limit, never grant. A real setup uses both.

For the report: in a real company, the same rules would also be set as SCPs, so even account admins couldn't remove them.

Notes:

- Console launches must include the tags with both **Instances** and **Volumes** selected under Resource types, or they are refused.
- Terraform must tag everything it creates (e.g., `default_tags` in the provider plus `volume_tags` on instances).
- IAM policies **cannot restrict the root user**, so root must not be used for daily work.
- The Guardian always tags what it creates (snapshots, restored volumes).

### 8.8 Known limitations of detection

| Case | Why it looks idle |
|---|---|
| Standby / failover server | Its job is to wait |
| Rarely used but needed (weekly admin tool, monthly webhook, jump server) | Use happens less often than the window |
| Tiny but critical traffic (heartbeat, license check) | Smaller than OS background noise |
| State held in memory (cache, paused process) | No CPU/network/disk activity; CloudWatch has no memory metric without an agent |
| Someone working interactively over SSH | Almost no traffic |
| Scheduled job outside the window | Looks idle within any shorter window |

Mitigations: longer windows, max values, warnings before acting, the protect tag and the one-click "Protect" link.

---

## 9. Warning timelines and remediation (FR5)

Dry-run mode (default) logs every action without executing it. Any resource tagged `guardian:protect=true` is report-only.

### 9.1 Step Functions workflows

Each idle instance and unattached volume gets its own **Step Functions Standard workflow**, which runs its warning timeline.

**Why Step Functions instead of timestamps in DynamoDB:** with timestamps, a deadline is only noticed at the next scan (up to one scan interval late). A Step Functions **Wait** step works like an alarm: AWS wakes the workflow at the exact deadline. It also replaces most of the timestamp bookkeeping, has built-in retries, and shows each resource's progress as a **live diagram** in the console, with a full step-by-step history.

**How it connects to the rest:**

- The **scanner** starts a workflow when it finds a new idle instance or unattached volume, stores the workflow's name and generation in the finding, and sets its status to **`in_progress`** (finding statuses: §9.7).
- If a later scan finds the resource resolved (active, attached, deleted), the scanner **stops** the workflow and marks the finding resolved. If the problem comes back later, the **same finding is reopened** (its key `resourceId + findingType` doesn't change, §10.1) and the **next generation** of its workflow starts, so the owner gets a full new grace period.
- **Protect** link → stops the workflow. **Postpone** link → stops it and starts the next generation with the later deadline (§10.4).
- Wait times and the dry-run flag are inputs to the workflow, so they can be set to **minutes for testing and the demo**.
- A Standard workflow can run for up to a year, so 14-day timelines are fine. Each workflow has a **timeout** (e.g., 30 days, longer than any timeline including postpones).
- **Cost:** about $0.025 per 1,000 state transitions, with 4,000 free per month; waiting is free. Roughly 8 transitions per EC2 timeline and 20 per EBS timeline, so about $0 at our scale.

**Exactly one timeline per resource: execution names.**

Two timelines for the same resource could start if scans overlap (a long all-region scan still running when the next one begins), or if the scanner starts a workflow and then crashes before saving its ID, so a retry starts another. The owner would get every notice twice, and a **Protect** click would stop only the workflow whose ID was saved, while the other could still stop or delete the resource.

The fix: every execution gets a **predictable name**, and Step Functions does not allow two executions with the same name in the same workflow.

- Name format: `<type>-<resource-id>-gen<N>`, e.g., `ebs-vol-0abc123-gen1`, `ec2-i-0def456-gen1`.
- The **generation** `N` goes up by one each time a new timeline starts for that resource: after a postpone, after an automatic restart following a failure (below), or when a resolved finding is reopened.
- The current generation is stored in the finding and **never reset**, because Step Functions keeps finished execution names reserved for 90 days.

How the scanner starts a timeline:

1. Compute the next name (`gen` + 1).
2. Record "starting `<name>`" in the finding with a **conditional write** (only if the stored generation is still the old one). If another scan already did this, the write fails and this scan does nothing.
3. Call `StartExecution` with that name. If an execution with that name already exists (e.g., this is a retry), Step Functions refuses to start a second one or returns the existing one.
4. If the start itself fails, the next scan retries with the same name.

Result: the scanner is safe to run again at any time. Action-link tokens include the generation, and links from an older generation are refused (§10.4).

Rules for the generation in code:

- **Store it as a number** in DynamoDB (`generation: 10`), and build the `-gen10` text only when creating the name. Compared as text, `"gen10"` sorts before `"gen9"`, which would make the generation check refuse valid links.
- **Never use it to count postpones or restarts.** It also goes up on reopen, so the limits use `postponeCount` and `restartCount`.
- **If `StartExecution` fails with `ExecutionAlreadyExists`** and that execution isn't the one the finding expects (e.g., the findings table was reset while Step Functions still remembers the old names for 90 days), add 1 to the generation and try again.

**Failure handling: Catch step + CloudWatch alarms.**

Workflows don't use the Lambda dead-letter queue. Without extra handling, a workflow that fails partway (e.g., the snapshot step errors or a permission is missing) is marked *Failed* and nothing else happens: no email, the finding still looks "in progress", and the scanner won't start a new workflow because it sees one recorded.

| Part | For | What it does |
|---|---|---|
| **Catch step** | The system | Keeps the Guardian's records correct and lets the resource be retried |
| **CloudWatch alarms** | The team | Emails the team that something broke |

Catch step (in both workflows):

1. Every task step's errors (after its own retries) go to one **Handle failure** branch.
2. It updates the finding to **`failed`**, with the failed step's name and the error message (direct Step Functions → DynamoDB integration, no extra Lambda).
3. It writes an **audit log** entry recording where the workflow stopped, e.g., "snapshot `snap-123` created; volume not deleted".
4. It emails the owner through the Notify Lambda: the Guardian couldn't finish handling the resource, nothing further will happen to it, and the team has been told.
5. The workflow then ends in a **Fail** state, so it still counts in the `ExecutionsFailed` metric and triggers the alarm.

Retrying: the scanner treats a `failed` finding like a new one and starts its next generation on the next scan, up to **2 automatic restarts** per finding. After that, the finding stays `failed` (shown on the dashboard) until a team member fixes the cause and resets it, so a permanent error can't create an endless loop of workflows and emails.

Alarms: one per workflow (EC2 and EBS) on the built-in metric **`ExecutionsFailed` ≥ 1** in 5 minutes, and one per workflow on **`ExecutionsTimedOut` ≥ 1**. All send to the team SNS topic, like the DLQ alarm. Cost: $0 (Step Functions metrics are free; 4 alarms plus the DLQ alarm fit in CloudWatch's 10 free alarms).

### 9.2 EC2 — opt-out stop after warnings

```
Send first notice (with Protect / Postpone links)              Day 0
      ↓
Wait 2 days
      ↓
Re-check: still idle and unprotected? ── no ──► End (resolved)
      ↓ yes
Send final warning (with Protect / Postpone links)              Day 2
      ↓
Wait 1 day
      ↓
Re-check: still idle and unprotected? ── no ──► End (resolved)
      ↓ yes
Stop instance (or log only, in dry-run)                         Day 3
      ↓
Send confirmation (how to start it again; mention any Elastic IP still billed)
```

The EC2 timeline is deliberately shorter than EBS: idle instances waste money faster, and stopping is reversible. The detection window is also a buffer, since the instance has already been idle that long before the first notice.

What stopping does (for reference):

| | Stop | Terminate |
|---|---|---|
| Compute charge | Ends | Ends |
| Can be started again | Yes | No |
| Root EBS volume and files | Kept, still billed | Deleted by default |
| RAM contents | Lost | Lost |
| Associated Elastic IP | Still billed | Disassociated, still billed until released |
| Auto-assigned public IPv4 | Released, new one on start | Released |

Stopping releases the physical host; the instance (ID, settings, tags, EBS disk) remains. The Guardian uses a graceful shutdown ("Skip OS shutdown" off).

### 9.3 EBS — snapshot then delete after warnings

```
Send first notice (with Protect / Postpone links)               Day 0
      ↓
Wait 11 days   (weekly digest reminders continue meanwhile)
      ↓
Re-check: still unattached and unprotected? ── no ──► End (resolved)
      ↓ yes
Send final warning (with Protect / Postpone links)              Day 11
      ↓
Wait 3 days
      ↓
Re-check ── no ──► End (resolved)
      ↓ yes
Create snapshot (copy tags + guardian:source-volume)            Day 14
      ↓
Wait and check until the snapshot is complete
      ↓
Delete volume (or log only, in dry-run)
      ↓
Send confirmation (snapshot ID + Restore link)
```

- Snapshotting an unattached volume is consistent (nothing is writing to it).
- The snapshot-completion check waits a reasonable time between checks; each check adds transitions.
- **Snapshots are never deleted by the Guardian.** Owners get reminders in the weekly digest (e.g., after 30 days) with the snapshot's monthly cost and delete it manually.
- **Restoring:** the owner uses the **Restore** link (§10.4) or the console (EC2 → Snapshots → Create volume from snapshot). The new volume has a new ID and must be attached and mounted again; it can be larger (not smaller) or another type; first reads are slow unless Fast Snapshot Restore (extra cost) is used; encryption is preserved.
- Snapshots are cheaper: ~$0.05/GB-month (standard) vs ~$0.08/GB-month for gp3, and they store only blocks that contain data.

### 9.4 Elastic IPs — never released

- Report-only, with weekly reminders. No workflow.
- Releasing is irreversible: another customer may get the address, and DNS records or allowlists pointing to it break silently. Savings are small (~$3.65/month per address).
- Disassociating does **not** stop charges, so it is not a remediation.

### 9.5 Safety rules for every stop or deletion

- The **final warning must be sent before any action**: the workflow's order guarantees it, and if sending fails, the workflow retries or stops instead of acting.
- The resource's state is **re-checked right before acting** (an explicit workflow step).
- The **clock resets** if the resource becomes active, attached or associated again (the workflow is stopped; a new finding starts a new one).
- IAM denies stopping or deleting anything tagged `guardian:protect=true`, and the Guardian has no permission to delete snapshots or release Elastic IPs (§16).

### 9.6 Summary per service

| | EC2 | EBS | Elastic IP |
|---|---|---|---|
| Waste detected | Idle (CPU, network, disk) | Unattached | Unassociated, or on a stopped instance |
| Automatic action | Stop after warnings (opt-out) | Snapshot then delete after warnings | None |
| Runs as | Step Functions workflow | Step Functions workflow | Report only |
| Reversible? | Yes | Yes, via snapshot | No |
| Emails | First notice, final warning, confirmation | First notice, weekly reminders, final warning, confirmation; snapshot reminders | Weekly reminders |
| Action links | Protect, Postpone | Protect, Postpone, Restore | — |
| Tag copying | — | From instance | From instance |

### 9.7 Finding statuses and what happens after remediation

Every finding has one status: **`open`** (found, no timeline running, e.g. report-only), **`in_progress`** (its warning timeline is running), **`remediated`** (the Guardian stopped the instance, or snapshotted and deleted the volume), **`resolved`** (the problem went away) or **`failed`** (the workflow failed, §9.1). The exact transitions, and who may make each one, are in `CONTRACT.md` §3.2.

**After remediation**, the scanner must not treat the result as "the problem went away":

- **EC2:** a stopped instance isn't checked for idleness, so it would look resolved. A `remediated` EC2 finding becomes `resolved` only if (a) the instance is running **and** its `LaunchTime` is later than the remediation (someone really started it again), or (b) the instance was terminated. If it later goes idle again, it reopens with a new timeline like any resolved finding.
- **Why the `LaunchTime` check:** in dry-run the instance is never stopped. Without the check, every scan would see it running, resolve the finding, see it idle, reopen it and start a new timeline, sending emails every cycle until the SES daily limit runs out. With the check, a dry-run "stop" stays `remediated`.
- **EBS:** a volume deleted by the Guardian stays `remediated` permanently. Its snapshot gets its own **snapshot reminder** finding for the weekly digest (§9.3). A restored volume has a new ID and is treated as a new resource.
- **Reopening** sets a new `firstSeenAt`, so "cost so far" in emails counts the current episode only.

---

## 10. Alerts, reminders and action links (FR4)

### 10.1 Emails and digest

- **Recipient:** the email address in the resource's `owner` tag; the team address if the owner is unknown. Sent through SES (§10.5).
- **Deduplication:** findings keyed by `resourceId + findingType`; only new findings trigger an immediate email. New findings with a timeline get the workflow's first notice; new **report-only** findings (Elastic IPs, Auto Scaling instances) get one short **report notice** from the scanner.
- **Weekly digest:** one email per recipient (not one per finding) listing open findings (unattached volumes, Elastic IPs, Guardian-created snapshots, and any other open finding) and the recipient's protected resources (below), with the **cost so far** (e.g., "unattached for 21 days, about $2.40 so far"), plus budget alerts (§11.2) and the AI summary at the top (§12). A finding is included if it's still open and more than 7 days have passed since `lastNotifiedAt`.
- Reminders stop when the finding is resolved: resource deleted or released, attached or associated again (with a running instance), or tagged `guardian:protect=true`.
- **Protected resources** (like the dashboard instance) are still *reported* (§6.3) but get no reminders and no timeline. They appear in the owner's weekly digest in a short **"Protected"** section, one line each: the resource, its region and its estimated monthly cost, with no action links. This keeps protection visible, so a resource protected months ago and since forgotten still shows what it costs.
- All timings are **configurable defaults**.

### 10.2 Missing-tag emails

| Case | Guardian action | Email |
|---|---|---|
| Resource untagged, its instance tagged | Copies tags, logs it | No alert (at most an info line in the digest) |
| Resource untagged, creator found in CloudTrail | Sets `owner`, logs it | No alert (at most an info line in the digest) |
| Resource and its instance both untagged, creator unknown | Nothing to copy | **One grouped email** to the team address covering both, explaining that tagging the instance is enough (the Guardian then copies the tags on the next scan) |
| Untagged, not attached or associated, creator unknown | Nothing to copy | Missing-tag alert to the team address |
| Tag copy or lookup fails | Logs the failure | Missing-tag alert |

Missing-tag emails are sent **once**, when the finding is new. After that, the finding appears only as a line in the weekly digest (the normal 7-day rule) until the scanner sees the tags and resolves it.

### 10.3 Notes in other emails

- EC2 stop confirmations mention any Elastic IP still attached and billed.
- Emails about Auto Scaling instances suggest scaling the group instead.

### 10.4 Email action links

Warning and reminder emails include links that let the owner act in one click, without opening the AWS console.

| Action | Effect | Risk |
|---|---|---|
| **Protect** | Adds `guardian:protect=true` and stops the resource's workflow | Low: only prevents actions |
| **Postpone** | Stops the workflow and restarts it with a later deadline (e.g., +7 days) | Low: only delays |
| **Restore from snapshot** | Creates a new volume from the Guardian's snapshot | Low: creates, never deletes |

**"Approve now"** (act immediately, skipping the wait) is **left out**: a mistaken or forwarded click on it could stop an instance early.

**Why API Gateway + Lambda (not the dashboard server):** API Gateway provides HTTPS without any certificate setup, so tokens never travel unencrypted, and it keeps write actions off the public dashboard server, which stays read-only.

**Why links and not dashboard buttons:** an email link proves who the person is by *where it was sent* (only the owner received it). Dashboard buttons would need a login, which is set aside.

**How it works:**

1. When the Notify Lambda (§10.5) builds an email, it creates one **random token** per action link: 256 random bits (e.g., Python's `secrets.token_urlsafe(32)`), impossible to guess.
2. It stores one item per token in a DynamoDB **tokens table**, keyed by the **SHA-256 hash** of the token (not the token itself): finding ID, workflow **generation** (§9.1), action, expiry, `used = false`, and a **TTL** attribute so DynamoDB deletes old tokens automatically.
3. The link contains only the token: `https://<api>/action?t=<token>`.
4. Clicking the link opens a **confirmation page** (HTTP GET): the Action Lambda hashes the token, looks it up, and shows what will happen. Nothing changes on a GET, because email security scanners often open links automatically.
5. The action runs only when the user presses Confirm (HTTP POST). The Action Lambda marks the token as used with **one conditional write**, which succeeds only if the token is unused, not expired, and its generation still matches the finding's current generation. So a token works at most once, even if clicked twice at the same moment.
6. It performs the action, writes the audit log, and shows the result.

**Why random tokens, not signed tokens:** the single-use check already needs a DynamoDB lookup, so the table can hold all the token's details and a signature adds nothing. This removes the signing secret (and Parameter Store), the signing and verification code, and the worst case of a signed design: if a signing key leaked, anyone could forge links for any resource. Storing only hashes means even someone who can read the tokens table can't use the links in it.

**Rules:**

- Tokens are **single-use** and **expire**: Protect and Postpone links at the deadline of the timeline they belong to (after it, the action has already happened); Restore links **30 days** after the confirmation email (the snapshot itself is kept; after that, restore from the console).
- Before restoring, the Action Lambda checks that the snapshot still exists and carries the `guardian:source-volume` tag; otherwise it shows a clear "snapshot no longer exists" page.
- Tokens from an **older generation** are refused (e.g., a Protect link from the first timeline after a postpone started a new one), with a message pointing to the newest email.
- Postponing is limited (e.g., at most 2 postpones per finding).
- A restored volume is created in the original volume's Availability Zone with the original tags, and its new ID is emailed to the owner.

### 10.5 Email delivery — SES for owners, SNS for team alerts

Emails to individual owners are sent with **Amazon SES**. SNS is kept only for alerts that go to one fixed audience, the team address.

**Why SNS doesn't work for owner emails:**

1. SNS publishes one message to everyone subscribed to a topic; it has no "send to this one address" call. Per-owner email would need a topic (or a filter) per owner, managed by the Guardian.
2. Every SNS email recipient must **confirm a subscription** first. Until a new owner confirms, their warnings are silently dropped while the timeline keeps running toward a stop or delete.
3. Every SNS email includes an **unsubscribe link**. One accidental click cuts the owner off from all future warnings, and the Guardian is not told.
4. The action links (§10.4) are **single-use secrets for one owner**. They must never be sent to a shared audience.
5. SNS emails are plain text, so action links appear as long raw URLs instead of buttons.

**Who sends what:**

| Email | Sent with | Recipient |
|---|---|---|
| First notice, final warning, confirmation (with action links) | **SES** | The resource's `owner` |
| Weekly digest | **SES** | Each owner (their own findings); the team address (unowned findings) |
| Missing-tag emails | **SES** | Owner if known, otherwise the team address |
| Workflow failure notice to the owner (§9.1) | **SES** | The resource's `owner` |
| Budget alerts (§11.2) | **SNS** | Team address, plus a Lambda subscriber that stores the alert for the digest and dashboard |
| DLQ alarm, workflow failure alarms (§9.1) | **SNS** | Team address |

**How it works:**

1. The **Notify Lambda** builds each email from an HTML template (buttons for action links, plain-text version included) and calls the SES `SendEmail` API. Step Functions workflows, the scanner and the digest Lambda all call this one function, so templates live in one place.
2. One **sender address** (`rif07@mail.aub.edu`, also the team address) is verified in SES.
3. SES stays in **sandbox mode**: it can only send to verified addresses, up to 200 emails per day and 1 per second. Each team member verifies their address once. This is enough for the course; production access is not needed.
4. If an owner's address is not verified (or the send fails), the Notify Lambda **falls back to the team address**, the same way as a missing `owner` tag, and records this in the audit log.
5. SES runs in us-west-2, with the rest of the Guardian.

**Cost:** about $0.10 per 1,000 emails, so about $0 at our scale.

---

## 11. Cost estimation and cost visibility (FR3)

### 11.1 Cost estimation (Guardian's own estimates)

- Internal **price table per region** of on-demand prices (prices differ between regions); each finding is priced with its own region's table, including the hourly charge for every public IPv4 address, attached or not ($0.005/hour ≈ $3.65/month since February 2024).
- For stopped instances, savings = instance cost minus the EBS storage that is still billed (as written in the proposal).
- For snapshotted and deleted volumes, savings = volume cost minus snapshot cost.
- Untagged resources are flagged without a cost estimate.
- EBS is billed per provisioned GB-month regardless of usage; a running EC2 instance is billed per second regardless of CPU usage.
- **Detection never uses the Cost Explorer API** (billed per request, ~24 h delay); it is only used once a day for bill history (§11.3).

### 11.2 Spending limits — AWS Budgets

**Account budget:**

1. One budget on the account's total monthly cost (e.g., $5).
2. Alerts on **actual** spend (e.g., 80%, 100%) and **forecasted** spend (e.g., 100%).
3. Alerts go to an SNS topic; the Guardian stores them and shows them in the digest and on the dashboard. (The topic's access policy must allow the Budgets service to publish.)
4. Optional emergency brake: a **budget action** that stops specific EC2 instances or applies a restrictive IAM policy when the budget is exceeded.

**Per-project budgets:**

1. Activate `project` (and `owner`) as **cost allocation tags**, in the Billing console or with Terraform (`aws_ce_cost_allocation_tag`). A tag key only appears for activation after it has been on at least one resource.
   - **Activate early, but late isn't permanent:** by default, cost data is grouped by a tag only from activation onward. Since March 2024, a **backfill** request (Billing console → Cost allocation tags → Backfill tags) applies the tags to up to **12 months** of past cost data.
   - Backfill only works for resources that **already had the tag** at the time, so what must happen early is tagging the resources themselves (enforced by the guardrails, §8.7).
   - One backfill request per 24 hours; Cost Explorer shows the result after its next daily refresh. AWS documents backfill for management-account users; check that the button appears in our standalone account.
2. One budget per project, filtered on `project = <name>`, with actual and forecast alerts to the same SNS topic.

**Why Budgets instead of building it:** it uses the real bill, covers every AWS service (not just the three we monitor), has forecasting built in, and is free.

**Cost:** monitoring and notifications are free; the first two action-enabled budgets are free, then $0.10 per day each.

**Limits:** billing data is delayed by up to about a day; only resources tagged with `project` count toward project budgets; each new project needs a new budget.

### 11.3 Real bill history — AWS Cost Explorer

**Budgets vs Cost Explorer:** both read the same billing data. **Budgets watches** spending and alerts when a limit is crossed; **Cost Explorer shows** where the money went, with history and forecasts.

1. Enable Cost Explorer in the Billing console (current month's data after about 24 hours, older data within a few days; it can't be disabled afterward).
2. The daily cost Lambda calls `GetCostAndUsage` **once a day** (daily granularity, grouped by service, optionally by `project` tag), and optionally `GetCostForecast`.
3. Results are stored in DynamoDB; the dashboard charts them and links to the Cost Explorer console.

**Cost:** the console is free; the API costs **$0.01 per request**, so about $0.30–0.60 per month. The API is **never** called on dashboard page loads.

**Notes:** data refreshes at least once every 24 hours; up to 13 months of history; forecasts up to 18 months. The API is served from the us-east-1 endpoint. It shows the real bill but can't tell which savings came from the Guardian.

### 11.4 Savings and waste charts on the dashboard

**Why build it ourselves:** the data is ours anyway (Guardian findings and actions, plus the daily Cost Explorer data), and the numbers belong on the dashboard users open. CloudWatch custom metrics would put charts in the AWS console instead, with every breakdown billed as an extra metric.

1. Once a day, the **daily summary Lambda** writes a **daily summary** record to DynamoDB: total estimated monthly waste of open findings, realized savings, potential savings, counts by resource type, region, `owner` and `project`.
2. The dashboard draws charts with a JavaScript chart library (e.g., Chart.js).

**How the money is counted:**

- **Waste:** estimated monthly cost of findings that are `open`, `in_progress` or `failed`.
- **Realized savings:** only findings **currently** `remediated` and **not** in dry-run. If a stopped instance is started again or terminated, it stops counting.
- **Potential savings:** open or in-progress findings, plus anything "remediated" in dry-run (nothing was actually changed).

**Charts:**

- **Waste over time** (open findings' estimated monthly waste, per day).
- **Savings over time:** *realized* (instances stopped, volumes replaced by snapshots) and *potential* (open or dry-run findings), shown separately.
- **Breakdowns:** waste by region, resource type, `owner` and `project`.
- **Activity:** findings, warnings sent and actions taken per week.
- **Real bill** from Cost Explorer next to the Guardian's own savings.
- **Budget status** per account and project.

---

## 12. AI assistant — Amazon Bedrock

**What it is:** Amazon Bedrock lets code call large language models through an API, with no servers to run, billed per amount of text processed.

**What it does:**

1. **AI-written weekly summary:** the digest Lambda sends the week's findings to a model, which writes a short plain-language summary at the top of the digest. Example: *"This week the account is wasting about $14/month. Most of it comes from two unattached volumes in us-east-1 unused for 3 weeks. Your idle instance guardian-test-2 will be stopped on Thursday unless you protect it."*
2. **"Ask about my costs" on the dashboard:** the dashboard server takes a question, collects the relevant data from DynamoDB (findings, audit log, daily summaries, bill history), sends both to the model, and shows the answer.

**Rules:**

- **Read-only:** the assistant only explains; it never stops, deletes or changes anything.
- **Grounded in our data:** the model is told to answer only from the data it receives and to say when it doesn't know. The real numbers are always shown next to the AI text.
- **Untrusted input:** tag values (e.g., a resource's `Name`) are written by users and passed to the model as data. The assistant can't take actions, so the impact is limited, but prompts keep data clearly separated from instructions.
- **Cost limits are required:** the dashboard is behind the team password (§6.4), but a shared password can leak, so every question costs a bounded amount:
  - a **global daily cap** for the whole dashboard (e.g., 100 questions per day, counted in DynamoDB with a conditional update). A per-visitor cap would be possible (the visitor's IP is available in `CloudFront-Viewer-Address`, §6.4), but a single global counter is simpler and puts a fixed ceiling on the daily cost; the per-visitor web rate limit (§6.3) already stops one visitor from flooding the box;
  - a **maximum answer length** set on every Bedrock call, and a limit on question length;
  - the account budget (§11.2) as the last safety net, since it covers Bedrock spending too.
- If Bedrock fails, the digest is sent without the summary.

**Setup:** choose a model available in **us-west-2** and enable access to it in the Bedrock console. Permission: `bedrock:InvokeModel` on that one model only, for the digest Lambda and the dashboard instance role.

**Cost:** not free; billed per amount of text in and out. A weekly summary plus capped questions keeps it small. Check the chosen model's pricing before setting the cap.

---

## 13. End-to-end workflows

### 13.1 Life of an idle instance

1. A team member launches an instance. IAM guardrails require `owner` and `project` tags and an allowed instance type.
2. The scanner (every few hours, all regions) measures CPU, network and disk over the detection window.
3. If it's in an Auto Scaling group or protected → report-only.
4. If idle → a finding is stored and a Step Functions workflow starts.
5. First notice with Protect / Postpone links.
6. Wait, re-check, final warning, wait, re-check.
7. If still idle and unprotected → stop (or log in dry-run), confirmation email, audit log entry.
8. Realized savings appear in the next daily summary and on the dashboard charts.

### 13.2 Life of an unattached volume

1. A volume becomes unattached (e.g., its instance was terminated).
2. The scanner finds it; if it lacks tags, copies them from its instance or looks up its creator in CloudTrail.
3. A workflow starts; first notice with Protect / Postpone links.
4. Weekly digest reminders with the cost so far.
5. Final warning, re-check, then snapshot (tags copied) and delete the volume.
6. Confirmation email with the snapshot ID and a **Restore** link.
7. The snapshot appears in reminders until the owner deletes it manually.

### 13.3 Unused Elastic IP

1. The scanner finds an unassociated address, or one on an instance stopped longer than the threshold.
2. Tags are copied or looked up as in §8.6.
3. The finding appears in the weekly digest with the cost so far until it's released, associated with a running instance, or protected.

### 13.4 Untagged resource

1. The scanner finds a resource missing `owner` or `project`.
2. Copies tags from its instance if possible.
3. Otherwise looks up its creator in CloudTrail and sets `owner`.
4. If neither works, a missing-tag email goes to the team address (grouped with its instance if both are untagged).

### 13.5 Daily and weekly routines

- **Every few hours:** scan all regions.
- **Daily:** fetch the real bill from Cost Explorer; write the daily summary. Budget alerts arrive whenever thresholds are crossed.
- **Weekly:** digest email per recipient with open findings, cost so far, budget alerts and the Bedrock summary.

---

## 14. Data stored in DynamoDB (FR6)

| Data | Fields / purpose |
|---|---|
| **Findings** | `resourceId` + `findingType` (deduplication key), `region`, `owner`, `project`, status (open / in_progress / remediated / resolved / failed, §9.7), `firstSeenAt` (cost so far, Elastic IP threshold; reset on reopen), `lastNotifiedAt` (digest), workflow name and generation, `postponeCount`, `restartCount` (failure retries), failed step and error, estimated monthly cost |
| **Creator lookups** | Resource ID, creator identity, email found (or unknown), lookup time; so each resource is looked up only once |
| **Audit log** | Every finding and action (who, what, when, result): notices, warnings, stops, snapshots, deletions, tag copies, owner lookups, action-link clicks |
| **Daily summaries** | Date, total waste, realized and potential savings, counts by type, region, owner and project |
| **Bill history** | Daily cost from Cost Explorer, by service and project |
| **Budget alerts** | Alerts received from AWS Budgets |
| **Link tokens** | SHA-256 hash of each action-link token, with finding ID, generation, action, expiry, `used` flag and a TTL for automatic deletion (§10.4) |
| **Last attached instance** | For each volume seen attached: the instance ID, used to find the creator after the volume is orphaned (§8.6) |
| **Question counter** | Daily count of Bedrock questions (for the cap) |

The exact table names, keys, attributes and status rules are defined in `CONTRACT.md` §3.

---

## 15. Dashboard (FR7)

- Runs on the EC2 instance (§6.3), reading DynamoDB, reached only through CloudFront with the team password (§6.4).
- Shows current findings (with region, owner, status and timeline step), actions taken, budget status, and the charts in §11.4.
- `failed` findings (§9.1) are shown in their own section, with the failed step and error, until resolved.
- Links to the Cost Explorer console.
- "Ask about my costs" box with Bedrock (§12).
- Read-only: no buttons that change resources (they need a login, which is set aside). Actions are done through email links.
- The web server rate-limits each visitor by their real IP from `CloudFront-Viewer-Address` (§6.3). This protects the server from one noisy visitor or script; it is not user authentication.

---

## 16. Security and IAM

### 16.1 Roles and permissions

| Role | Key permissions |
|---|---|
| **Scanner Lambda** | Describe EC2, EBS, Elastic IPs, regions; `cloudwatch:GetMetricStatistics`; `ec2:CreateTags` (tag copying, setting `owner`); `cloudtrail:LookupEvents`; `iam:ListUserTags`; `states:StartExecution`, `states:StopExecution`; DynamoDB |
| **Step Functions execution role** | Invoke the Guardian's Lambdas (including the Notify Lambda); `dynamodb:UpdateItem` and `dynamodb:PutItem` on the findings and audit log tables (Catch branch) |
| **Notify Lambda** | `ses:SendEmail` (verified sender identity only); DynamoDB write (tokens table; audit log for fallbacks); `dynamodb:UpdateItem` on findings (only `lastNotifiedAt`) |
| **Remediation Lambda** | `ec2:StopInstances` and `ec2:DeleteVolume`, **denied** on resources tagged `guardian:protect=true`; `ec2:CreateSnapshot`; `ec2:CreateTags` (snapshot tags); describe calls; DynamoDB |
| **Action Lambda** | `ec2:CreateTags` (only the `guardian:protect` key); `ec2:CreateVolume` (only from snapshots tagged `guardian:source-volume`); `states:StartExecution`, `states:StopExecution`; DynamoDB (tokens table, findings, audit log) |
| **Daily cost Lambda** | `ce:GetCostAndUsage`, `ce:GetCostForecast`; DynamoDB (bill history) |
| **Daily summary Lambda** | DynamoDB read (findings, audit log); DynamoDB write (daily summaries) |
| **Digest Lambda** | DynamoDB read; `bedrock:InvokeModel` (one model); invoke the Notify Lambda |
| **Budget alert subscriber Lambda** | DynamoDB write (budget alerts), triggered by the team SNS topic |
| **Dashboard instance role** | DynamoDB read (plus write for the question counter); `bedrock:InvokeModel` (one model) |
| **Team IAM group** | Launch guardrail **deny** rules (§8.7) |

**Never granted to any Guardian role:** `ec2:DeleteSnapshot`, `ec2:ReleaseAddress`.

### 16.2 Other security points

- Least privilege everywhere; no access keys on the dashboard server (instance role only).
- Each team member has their own IAM user (with an `email` tag); the root user is not used for daily work.
- Action links: HTTPS through API Gateway, random single-use expiring tokens stored only as hashes, tied to the current workflow generation, confirmation page before acting. No signing secret to leak.
- Dashboard: reached only through CloudFront (HTTPS) with a team password; security group accepting web traffic only from the CloudFront prefix list, SSH only from the EC2 Instance Connect prefix list; a secret origin header so only our distribution is accepted; per-visitor rate limiting (§6.3, §6.4). The password and the header secret are sensitive Terraform variables, never committed to Git.
- Owner emails only through SES, never to a shared audience (§10.5).
- Encryption at rest: DynamoDB default encryption and an encrypted EBS root volume on the dashboard instance. All AWS API calls use HTTPS.
- Bedrock: read-only, global daily cap, answer length limit, data separated from instructions.
- Launch guardrails stop mistakes, not deliberate bypassing by admins; SCPs would be the real enforcement in a company setup (§8.7).

---

## 17. Non-functional requirements

| Area | Requirement |
|---|---|
| Cost | About $0 actual spend within Free Tier/credits; account budget at $5; small paid items listed in §18 |
| Performance | Full scan of up to 100 resources across all enabled regions in under 60 seconds |
| Timeliness | Workflow actions happen at their deadline (not at the next scan) |
| Reliability | Managed services; retries in Lambda and Step Functions; SQS DLQ + CloudWatch alarm; Catch step + `ExecutionsFailed` / `ExecutionsTimedOut` alarms on workflows; at most 2 automatic restarts per failed finding; no duplicate timelines (execution names with generations) |
| Lambda timeouts | Set explicitly for every function (table below): Lambda's default is 3 seconds, too short for an all-region scan |
| Auditing | All findings and actions in DynamoDB; all Lambda executions in CloudWatch Logs; workflow history in Step Functions |
| Maintainability | Terraform for everything Terraform can create (the few console steps are listed in `docs/manual-setup.md`); everything Terraform creates is tagged (`default_tags`, `volume_tags`) |

**Lambda timeouts.** Each timeout is set to the upper end of a safe range, well above the expected run time, so a slow day (throttling retries, a slow AWS API) never cuts a run short. The expected times are estimates; measure the real ones in CloudWatch Logs (`Duration` on each run's REPORT line) once the code exists.

| Lambda | Expected run time | Timeout | Notes |
|---|---|---|---|
| Scanner | ~10–60 s (about 17 regions, metrics per instance, CloudTrail lookups at ~2/s) | **5 min** | Hard limit is 15 min; past that, split into one invocation per region (§8.1). Memory 256–512 MB for more CPU |
| Digest | ~10–60 s (one Bedrock call per recipient) | **3 min** | Grows with the number of recipients |
| Remediation | ~1–3 s (stop and snapshot calls return immediately; Step Functions waits for the snapshot) | **60 s** | |
| Notify | ~1–2 s (template + SES call + token writes) | **60 s** | |
| Daily cost | ~1–3 s (one or two Cost Explorer calls) | **60 s** | |
| Daily summary | ~2–10 s (reads findings and the day's audit entries) | **60 s** | |
| Budget alert subscriber | < 1 s (one DynamoDB write) | **30 s** | |
| Action | ~1–3 s (token check + one action) | **29 s** | Behind API Gateway, whose integration timeout is about 30 s: a longer Lambda timeout wouldn't help, the browser would get an error first |

Step Functions task steps that call a Lambda should allow at least the Lambda's own timeout.

## 18. Cost overview

| Item | Expected cost at project scale |
|---|---|
| Lambda, DynamoDB, SNS (team alerts), SQS, EventBridge Scheduler, API Gateway | ~$0 (free tiers) |
| Step Functions | ~$0 (4,000 free transitions per month) |
| CloudWatch basic metrics and `GetMetricStatistics` | ~$0 (free metrics and free API allowance) |
| CloudTrail event history and lookups | Free |
| AWS Budgets (alerts) | Free |
| Amazon SES (sandbox) | ~$0 (about $0.10 per 1,000 emails) |
| CloudFront + CloudFront Function | ~$0 (always-free tier: 1 TB, 10M requests, 2M function invocations per month) |
| CloudWatch alarms (DLQ + 4 workflow alarms) | ~$0 (10 alarms free) |
| Own VPC, subnet, internet gateway, route table, security group | Free |
| Cost Explorer API (once a day) | ~$0.30–0.60 per month |
| Amazon Bedrock | Small, per amount of text; bounded by the daily cap |
| EC2 dashboard (t3.micro + public IPv4) | ~$7–8 per month on-demand unless covered by Free Tier or credits; stop when not in use |
| Test resources (instances, volumes, Elastic IPs, snapshots) | Small; keep short-lived, `terraform destroy` after testing |

---

## 19. Success criteria

- **Detection accuracy:** 100% of seeded waste found (idle EC2, unattached EBS, unassociated Elastic IPs, Elastic IPs on stopped instances, untagged resources), with no false positives on healthy resources, including waste seeded in a second region.
- **Alert latency:** first notice within 5 minutes of a scan finding new waste.
- **Timelines:** each workflow sends its warnings and acts at its deadline; stopping a workflow (protect, resolve) prevents the action; running the scanner twice at once never creates a second timeline for the same resource.
- **Failures:** a forced failure in a workflow step marks the finding `failed`, records where it stopped, and emails the team through the alarm; the finding is retried at most twice.
- **EC2:** unprotected idle instances stopped after the warning period; protected and Auto Scaling instances never stopped.
- **EBS:** protected volumes never deleted; every deleted volume has a snapshot that restores its data.
- **Elastic IPs:** never released by the Guardian.
- **Tags and owners:** attached volumes / associated Elastic IPs of a tagged instance carry its tags after one scan; untagged resources created by a team member get that member's email as `owner`.
- **Guardrails:** launching an untagged instance, or a disallowed instance type, is refused, and a correctly tagged launch is allowed (the five `--dry-run` tests in §8.7).
- **Action links:** protect, postpone and restore work once; reused, expired, tampered or older-generation links are refused; opening a link without confirming changes nothing.
- **Emails:** owner emails arrive through SES with working buttons; an unverified owner address falls back to the team address.
- **Dashboard access:** the dashboard opens over HTTPS only after the team password; the instance can't be reached directly by its IP; a request without the secret origin header is refused.
- **Reminders:** an open finding appears in the weekly digest after 7 days; resolved findings don't; protected resources appear once per digest in the "Protected" section, with their cost and no action links.
- **Cost visibility:** budget alerts, daily bill history and savings charts appear on the dashboard.
- **AI assistant:** the weekly summary appears in the digest; dashboard questions are answered from our data and stop at the daily cap.
- **Dashboard load:** the dashboard on the t3.micro handles ≥ 20 requests/second in total with < 1% errors. A load test from one machine counts as one visitor, so it runs with the per-visitor limit raised, or from several machines; a separate test checks that one visitor over the limit gets `429`.
- **Spend:** within Free Tier/credits (~$0 apart from the small items in §18), shown by Budgets and Cost Explorer.
- **Demo:** deploy waste → scan → warning emails with action links → live workflow diagram → dashboard charts and AI question → auto-stop and snapshot-then-delete → restore from the email link.

**Stretch goals:** a custom domain for the dashboard (Route 53 + an ACM certificate on CloudFront); per-person dashboard login (Cognito).

---

## 20. Build vs AWS service: decisions

| Need | Build ourselves | AWS service | Decision |
|---|---|---|---|
| Detection of idle EC2, unattached EBS, unused Elastic IPs | Own scanner on free APIs | Trusted Advisor (paid plan) | **Build ourselves** |
| Account spend limit and forecast | Sum our estimates, own forecast | AWS Budgets | **AWS Budgets** |
| Per-project spending | Sum estimates per tag | Budgets filtered by tag | **AWS Budgets** |
| Real bill history | Own daily estimate of running costs | Cost Explorer (API daily) | **Cost Explorer** |
| Headline numbers and charts | Own charts from DynamoDB | CloudWatch custom metrics | **Build ourselves** |
| Who created a resource | — | CloudTrail lookup vs EventBridge (real-time) | **CloudTrail lookup** |
| Preventing untagged or oversized launches | — | IAM policy conditions | **IAM** |
| Warning timelines | Timestamps in DynamoDB, checked each scan | Step Functions | **Step Functions** |
| Explaining findings | — | Amazon Bedrock | **Bedrock** |
| Personal emails with action links | — | SNS (topics + subscriptions) vs SES (direct email) | **SES** (SNS kept for team alerts) |
| Dashboard HTTPS and access control | Certificate on the instance, IP allowlist | CloudFront + CloudFront Function | **CloudFront** |
| Enforcing guardrails | IAM policy on the team group | AWS Organizations SCPs | **IAM** (SCPs need a second account and can end free-plan credits) |
| Sudden spending spikes | Simple rule on daily bill data | Cost Anomaly Detection | **Set aside** |
| Guardian health | Self-reported scan records | CloudWatch metrics, dashboard, alarms | **Set aside** |
| Guardian-specific savings and findings | Own DynamoDB data | None exists | **Build ourselves** (only option) |

---

## 21. Set aside and not used, with reasons

### 21.1 Set aside (may be added later)

- **Cost Anomaly Detection:** detects unusual spending in any service, at no additional cost. Set aside because the account budget already catches overspending in any service, it needs at least 10 days of history, a student account's small and changing spend gives little to learn from, and it can't be shown live. Valuable in the full-product phase.
- **Guardian health dashboard (CloudWatch):** a CloudWatch dashboard and alarms on the Guardian's Lambdas and the dashboard instance. Set aside; the error alarm on the dead-letter queue stays, and the workflow failure alarms (§9.1) are added.
- **Dashboard action buttons:** the same actions as the email links, on the dashboard. Need a per-person login to know who clicked; can reuse the action API later.
- **Dashboard per-person login (Cognito):** user accounts and roles. Set aside with the buttons; the shared team password at CloudFront (§6.4) covers read-only access.
- **Opt-in automatic Elastic IP release** (`guardian:auto-release=true`): opt-in because releasing is irreversible.
- **Office-hours scheduling (Instance Scheduler on AWS):** starts and stops instances on tag-based schedules (e.g., weekdays 08:00–19:00). Set aside to keep scope manageable; if added, scheduled instances would be report-only and not reported as waste while stopped on schedule.
- **Optimization recommendations (AWS Compute Optimizer):** free rightsizing and gp2 → gp3 suggestions, shown as recommendations only. Set aside; it also needs about 30 hours of metrics per instance before it recommends anything.
- **Resource leases** (`guardian:expires=<date>` tag): overlaps with idle detection.
- **CI/CD with GitHub Actions** (tests and `terraform plan` on every push): useful for the team, not a user feature.

### 21.2 Not used

- **Real-time detection with CloudTrail + EventBridge:** EventBridge rules reacting to API calls within seconds. Not used because idle detection still needs the scheduled scan; the "who did it" information comes from the CloudTrail lookup without new services; waste builds up slowly, so finding it within the scan interval is enough; and prevention is handled better by IAM guardrails. Of the lookup's three limits (90-day history, identity-to-email mapping, rate limit), EventBridge only removes the rate limit, which is easy to work around.
- **Approval for expensive launches:** needs a login; the IAM guardrails cover the need.
- **Slack/Teams notifications, savings leaderboard, carbon estimate:** dropped; outside the core goal (the carbon estimate would only be a rough approximation).

---

## 22. Former "under discussion" items

All the items that were under discussion have been decided (November 20, 2026): office-hours scheduling, Compute Optimizer recommendations, resource leases and CI/CD are **set aside** (§21.1); approvals, Slack/Teams, the leaderboard and the carbon estimate are **dropped** (§21.2). The section number is kept so references elsewhere stay valid.

---

## 23. Team, testing and setup

### 23.1 Team lanes

The work is split into four lanes that can be built in parallel against a shared contract (`CONTRACT.md`). Each lane owns one folder in the repo.

| Lane | Folder | Owner | Covers |
|---|---|---|---|
| A: Lifecycle engine | `engine/` | Reda | Step Functions workflows (EC2, EBS), generations and execution names, Catch and restarts, Remediation Lambda, Action Lambda + API Gateway routes (protect, postpone, restore), workflow alarms, the shared timeline helper |
| B: Scanner | `scanner/` | Reda | Multi-region detection, metrics and classification, price table and cost estimates, tag copying, CloudTrail creator lookup, resolve / reopen |
| C: Platform and delivery | `platform/` | Reda | Terraform base, team IAM users and group, guardrails, IAM review, VPC, EC2 networking, CloudFront and the password, SES + Notify Lambda (templates, tokens), SNS, DLQ alarm, Budgets, schedules, budget alert subscriber, the action API itself |
| D: Data and dashboard | `dashboard/` | Reda | Daily cost and daily summary Lambdas, Digest Lambda + Bedrock summary, dashboard web app (charts, Ask box, rate limit, secret-header check) |

*(The original split from the proposal — Roda: Terraform/IAM/Budgets; Ahmad: scanner; Khaled: remediation and alerts; Meryem: dashboard, testing, documentation — was replaced by these lanes when the new features were added.)*

### 23.2 Testing notes

- Seed resources with different tag combinations: fully tagged, missing `owner`, protected idle instance, unprotected idle instance, tagged instance with untagged volume, untagged resource created by a team member's IAM user.
- Seed at least one wasteful resource in a second region (e.g., us-east-1).
- Launch an instance inside an Auto Scaling group to check it's never stopped.
- Healthy EC2 test instances need generated load (CPU, network or disk) to stay above thresholds.
- Set workflow waits to minutes and the detection window to 30 minutes; scans can be triggered manually.
- Test guardrails: an untagged launch and a disallowed instance type must be refused.
- Test guardrails with `aws ec2 run-instances --dry-run` (free; the five cases in §8.7).
- Test action links: each works once; reused, expired, modified or older-generation links are refused; opening without confirming changes nothing.
- Test duplicates: trigger two scans at the same time; only one timeline starts per resource.
- To reset test data, redeploy the workflows with Terraform rather than only clearing the findings table: Step Functions remembers execution names for 90 days, so a cleared table would restart at `gen1` and collide with old names.
- Test failures: remove a permission on purpose; the Catch step marks the finding `failed`, the alarm emails the team, and retries stop after 2.
- Test dashboard access: without the password → 401; direct access by the instance's IP → refused; a request missing the secret origin header → 403; one visitor sending too many requests → 429.
- Test Bedrock limits: the daily cap and answer length limit stop extra questions.
- Run everything in dry-run first; test the IAM deny rules on purpose.
- Use tiny instances, keep paid resources short-lived, `terraform destroy` after testing.
- In personal stacks (§23.4), tag test resources with `guardian:dev-scope=<your name prefix>` and keep `DRY_RUN=true`, so one person's Guardian never acts on another person's resources.

### 23.3 Things to do early (setup that takes time)

Console-only steps, with the reason for each, are kept in `docs/manual-setup.md`.

- [x] **Turn on MFA for the root user.**
- [x] **Check the AWS account's plan:** free plan with Free Tier credits. So **never** enable AWS Organizations or IAM Identity Center: on the free plan, either one upgrades the account and ends the credits (§8.7).
- [x] **Activate IAM user and role access to Billing information** (root only), so IAM users can open Budgets and Cost Explorer.
- [x] **Create one IAM user per team member**, each with an `email` tag; stop using the root user for daily work. *(First admin user created by hand; teammates' users via Terraform.)*
- [x] **Enable Cost Explorer** (data takes a day or more to appear).
- [x] **Create the Terraform state bucket and the account budget alert** (`bootstrap/`).
- [x] **Verify the sender address and each team member's address in SES** (Terraform creates the identities; each person clicks the verification email).
- [ ] **Activate `project` and `owner` as cost allocation tags** (Terraform), once at least one resource carries them. If done late, request a backfill (§11.2).
- [ ] **Enable access to the chosen Bedrock model** in us-west-2, if the model requires it, and check its pricing.

### 23.4 Repository and ways of working

- **Repo:** private GitHub repository. Key files: `CLAUDE.md` (rules for everyone, including AI coding assistants), `CONTRACT.md` (shared data formats and interfaces between the lanes; wins over this document on interfaces), `docs/design.md` (this file), `docs/manual-setup.md`.
- **Branching:** everyone works on `main`; pull with rebase before every push; each lane edits only its own folder.
- **Terraform state:** in an S3 bucket created by `bootstrap/`, with S3 native locking. `infra/shared` holds account-wide resources (one copy); `infra/stack` deploys a full Guardian.
- **Personal stacks:** each person deploys their own copy with a name prefix (e.g., `cg-reda-`) and their own state, in dry-run, scoped by the `guardian:dev-scope` tag. The final team stack is deployed once for integration testing and the demo.
- **AI assistance:** the team builds with AI coding assistants; `CLAUDE.md` requires asking a person before any `terraform apply`, `destroy` or deleting command.

## 24. Open decisions

Decide before building the part that needs it:

- **Which Bedrock model**, its daily cap and maximum answer length.
- Whether to add the optional network ACL (§6.4).
- Exact timings: scan interval, detection window for the real tool, workflow waits, reminder intervals, Elastic IP "stopped too long" threshold. *(Defaults set in `CONTRACT.md`: postpone 7 days, at most 2 postpones, at most 2 automatic restarts, restore links valid 30 days.)*
- Detection thresholds for CPU, network and disk (tuned during testing).
- Allowed instance types for the guardrails.
- Budget amounts per project and alert thresholds (the account budget is $5).
- Whether to scan all enabled regions by default or only a configured list, and which regions the price table covers.

*Decided: own VPC with CloudFront and a team password (§6.4); missing-tag findings are emailed once, then shown in the weekly digest (§10.2); all former "under discussion" items (§22); team and sender address `rif07@mail.aub.edu` (verified in SES; AUB DMARC is p=none; test emails reached the inbox).*

---

## Sources

- [AWS Budgets pricing](https://aws.amazon.com/aws-cost-management/aws-budgets/pricing)
- [AWS Cost Explorer pricing](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/)
- [AWS Cost Explorer FAQs](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/faqs/)
- [Analyzing your costs and usage with AWS Cost Explorer](https://docs.aws.amazon.com/console/billing/costexplorer)
- [AWS Cost Anomaly Detection FAQs](https://aws.amazon.com/aws-cost-management/aws-cost-anomaly-detection/faqs)
- [AWS blog: Cost Explorer users can automatically detect cost anomalies](https://aws.amazon.com/blogs/aws-cloud-financial-management/new-aws-cost-explorer-users-can-now-automatically-detect-cost-anomalies)
- [Amazon CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/)
- [CloudFront: request and response behavior for custom origins](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html) (`X-Forwarded-For` handling)
- [AWS re:Post: identify the real client IP when using CloudFront](https://repost.aws/articles/AR-VvhzdKVRgOIYl4SJMTcHg/how-to-identify-the-real-client-ip-on-alb-when-using-cloudfront-as-a-front-end) (`CloudFront-Viewer-Address`)
- [Secure Content Delivery with CloudFront: custom origin](https://docs.aws.amazon.com/whitepapers/latest/secure-content-delivery-amazon-cloudfront/custom-origin-with-cloudfront.html) (prefix list + header inspection)
- [Limit access to your origins using the AWS-managed prefix list for CloudFront](https://aws.amazon.com/blogs/networking-and-content-delivery/limit-access-to-your-origins-using-the-aws-managed-prefix-list-for-amazon-cloudfront) (counts as 55 rules)
- [AWS Cost Allocation Tags now support retroactive application](https://aws.amazon.com/about-aws/whats-new/2024/03/aws-cost-allocation-tags-retroactive-application)
- [Backfill cost allocation tags](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-allocation-backfill.html)
- [AWS Free Tier Terms](https://aws.amazon.com/free/terms) (Organizations and free-plan accounts)
- [AWS Free Tier FAQs](https://aws.amazon.com/ru/free/faqs/) (credits expire when joining an Organization)
- [AWS re:Post: find the user who created an EBS volume](https://aws.amazon.com/ru/premiumsupport/knowledge-center/find-ebs-user-config-cloudtrail/) (no `CreateVolume` event for volumes created at launch)
- [AWS re:Post: attachment history of an EBS volume](https://aws.amazon.com/es/premiumsupport/knowledge-center/list-attachments-history-ebs-volume/)
