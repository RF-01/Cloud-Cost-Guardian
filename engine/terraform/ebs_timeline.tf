# EBS timeline state machine (design §9.3, CONTRACT §4.4). Started only by common/timeline.py.
# The definition is ebs_timeline.asl.json (JSONata); it reuses the shared parts of sfn.tf
# (timeline_parts, remediation_args, failure_parts).

locals {
  # Snapshot completion check: every 2 minutes, at most 90 times (about 3 hours), then the failure branch.
  snapshot_poll_seconds = 120
  snapshot_max_polls    = 90
  # Restore link lifetime in the DELETE_CONFIRMATION email (CONTRACT §3.4 / §6 RESTORE_LINK_DAYS).
  restore_link_days = 30

  ebs_timeline_parts = merge(local.timeline_parts, {
    check_payload           = jsonencode(merge({ action = "CHECK_EBS" }, local.remediation_args))
    create_snapshot_payload = jsonencode(merge({ action = "CREATE_SNAPSHOT" }, local.remediation_args))
    snapshot_status_payload = jsonencode(merge({ action = "SNAPSHOT_STATUS" }, local.remediation_args, { snapshotId = "{% $snap.snapshotId %}" }))
    # snapshotId is null in dry-run (CONTRACT §4.3).
    delete_payload = jsonencode(merge({ action = "DELETE_VOLUME" }, local.remediation_args, { snapshotId = "{% $snap.snapshotId %}" }))

    snapshot_poll_seconds = local.snapshot_poll_seconds
    snapshot_max_polls    = local.snapshot_max_polls
    restore_link_days     = local.restore_link_days
  })
}

resource "aws_iam_role" "ebs_timeline" {
  name               = "${var.name_prefix}ebs-timeline-role"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

data "aws_iam_policy_document" "ebs_timeline" {
  statement {
    sid     = "InvokeGuardianLambdas"
    actions = ["lambda:InvokeFunction"]
    # Known values, like the EC2 policy (no deferred read on every remediation code change).
    resources = [local.remediation_arn, var.notify_function_arn]
  }

  # Every UpdateItem in ebs_timeline.asl.json is keyed by $input.resourceId: an EBS_UNATTACHED volume ID.
  statement {
    sid       = "UpdateFindings"
    actions   = ["dynamodb:UpdateItem"]
    resources = [var.table_arns["findings"]]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["vol-*"]
    }
    condition {
      test     = "Null"
      variable = "dynamodb:LeadingKeys"
      values   = ["false"]
    }
  }

  # CreateSnapshotReminder: the only new item this workflow writes is a SNAPSHOT_REMINDER keyed by its snapshot ID.
  statement {
    sid       = "PutSnapshotReminder"
    actions   = ["dynamodb:PutItem"]
    resources = [var.table_arns["findings"]]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["snap-*"]
    }
    condition {
      test     = "Null"
      variable = "dynamodb:LeadingKeys"
      values   = ["false"]
    }
  }

  statement {
    sid       = "WriteFailureAudit"
    actions   = ["dynamodb:PutItem"]
    resources = [var.table_arns["audit"]]
  }
}

resource "aws_iam_role_policy" "ebs_timeline" {
  name   = "ebs-timeline"
  role   = aws_iam_role.ebs_timeline.id
  policy = data.aws_iam_policy_document.ebs_timeline.json
}

resource "aws_sfn_state_machine" "ebs_timeline" {
  name       = "${var.name_prefix}ebs-timeline"
  type       = "STANDARD"
  role_arn   = aws_iam_role.ebs_timeline.arn
  definition = templatefile("${path.module}/ebs_timeline.asl.json", merge(local.ebs_timeline_parts, local.failure_parts))

  depends_on = [aws_iam_role_policy.ebs_timeline]
}
