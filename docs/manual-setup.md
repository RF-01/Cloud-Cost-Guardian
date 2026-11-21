# Manual setup (console steps)

Professor's guidance: create everything possible with Terraform; use the console only for what Terraform can't create.
These are the only console steps. Everything else is in Terraform.

| # | Step | Who | Why it's manual | Status |
|---|---|---|---|---|
| 1 | MFA on the root user | root | Root security setting, not infrastructure | Done |
| 2 | Activate IAM user and role access to Billing information | root | Account setting only the root user can change | Done |
| 3 | First admin IAM user (`email` tag) and its access key | root | Terraform needs an identity to run as before it can manage IAM | Done |
| 4 | Open Cost Explorer once to turn it on | admin | No API or Terraform resource enables it | Done |
| 5 | Click the SES verification email for each address | each person | Proves ownership of the address; Terraform creates the identity, the click is by design manual | Done |
| 6 | Bedrock model access (if the chosen model asks for it) | admin | One-time agreement in the console | |
| 7 | Cost allocation tag backfill (only if tags were activated late) | admin | Console button | Not needed yet |
| 8 | Confirm the SNS subscription email for the team-alerts topic | rif07 | AWS requires the recipient to click | |

Terraform order notes:
- `bootstrap/` creates the state bucket (its own state stays local).
- `aws_ce_cost_allocation_tag` only works after the tag keys have appeared on resources and in billing (up to a day): apply once, then activate.
