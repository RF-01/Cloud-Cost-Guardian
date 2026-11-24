# EC2 timeline state machine (design §9.2, CONTRACT §4.4). Started only by common/timeline.py.
# The definition is ec2_timeline.asl.json (JSONata); the shared pieces below are injected as JSON and are also
# used by the EBS timeline (ebs_timeline.tf).

locals {
  # Lambda service errors, retried with backoff (AWS's recommended set for lambda:invoke).
  lambda_service_retry = {
    ErrorEquals = [
      "Lambda.ServiceException",
      "Lambda.AWSLambdaException",
      "Lambda.SdkClientException",
      "Lambda.TooManyRequestsException",
    ]
    IntervalSeconds = 2
    MaxAttempts     = 3
    BackoffRate     = 2
    JitterStrategy  = "FULL"
  }

  # Arguments of every Remediation Lambda call, shared with the EBS timeline (#30). findingType and generation
  # are for the remediation's audit entries (CONTRACT §4.3); "{% $input.generation %}" stays a number.
  remediation_args = {
    resourceId  = "{% $input.resourceId %}"
    region      = "{% $input.region %}"
    dryRun      = "{% $input.dryRun %}"
    findingType = "{% $input.findingType %}"
    generation  = "{% $input.generation %}"
  }

  # Template parts used by both timelines (ec2_timeline.asl.json, ebs_timeline.asl.json).
  timeline_parts = {
    findings_table  = var.table_names["findings"]
    notify_arn      = var.notify_function_arn
    remediation_arn = aws_lambda_function.remediation.arn

    finding_key = jsonencode({
      resourceId  = { S = "{% $input.resourceId %}" }
      findingType = { S = "{% $input.findingType %}" }
    })

    # Notify: service errors only. A Notify failure (after retries) fails the execution, so the
    # instance is never stopped without its final warning (design §9.5).
    notify_retry = jsonencode([local.lambda_service_retry])

    # Remediation: safety refusals are never retried; other errors (e.g. EC2 throttling) twice more.
    remediation_retry = jsonencode([
      { ErrorEquals = ["RefusedError"], MaxAttempts = 0 },
      local.lambda_service_retry,
      { ErrorEquals = ["States.TaskFailed"], IntervalSeconds = 10, MaxAttempts = 2, BackoffRate = 2 },
    ])

    ddb_retry = jsonencode([{
      ErrorEquals = [
        "DynamoDB.ProvisionedThroughputExceededException",
        "DynamoDB.ThrottlingException",
        "DynamoDB.RequestLimitExceeded",
        "DynamoDB.InternalServerErrorException",
      ]
      IntervalSeconds = 2
      MaxAttempts     = 3
      BackoffRate     = 2
      JitterStrategy  = "FULL"
    }])
  }

  ec2_timeline_parts = merge(local.timeline_parts, {
    check_payload = jsonencode(merge({ action = "CHECK_EC2" }, local.remediation_args))
    stop_payload  = jsonencode(merge({ action = "STOP_INSTANCE" }, local.remediation_args))
  })

  # ---- Failure branch (design §9.1 "Catch step"), shared with the EBS timeline (#30). -----------------------
  # Every timeline catcher Assigns failedStep, progress, error and errorMessage, so each state of the branch
  # (MarkFailed, WriteFailureAudit, NotifyFailure, ConfirmationFailed, Failed) only reads variables.
  failure_parts = {
    audit_table = var.table_names["audit"]

    # "<Error>: <message>", at most 500 chars, from $states.errorOutput. Lambda errors: the errorMessage inside
    # the JSON Cause, found with $match (never $parse: nothing in the failure path may throw). The regex spells
    # the backslash as \x5c because the JSONata lexer miscounts brackets after "\]".
    error_message = jsonencode("{% ${trimspace(file("${path.module}/failure_error_message.jsonata"))} %}")

    # workflow_failed audit entry (CONTRACT §3.3). Used by WriteFailureAudit and ConfirmationFailed.
    failure_audit_item = jsonencode({
      resourceId  = { S = "{% $input.resourceId %}" }
      ts          = { S = "{% $fromMillis($millis(), '[Y0001]-[M01]-[D01]T[H01]:[m01]:[s01]Z') & '#' & $substring($uuid(), 0, 8) %}" }
      day         = { S = "{% $fromMillis($millis(), '[Y0001]-[M01]-[D01]') %}" }
      actor       = { S = "workflow" }
      event       = { S = "workflow_failed" }
      findingType = { S = "{% $input.findingType %}" }
      region      = { S = "{% $input.region %}" }
      generation  = { N = "{% $string($input.generation) %}" }
      dryRun      = { BOOL = "{% $input.dryRun = true %}" }
      result      = { S = "error" }
      details = { M = {
        failedStep    = { S = "{% $failedStep %}" }
        errorMessage  = { S = "{% $errorMessage %}" }
        progress      = { S = "{% $progress %}" }
        executionName = { S = "{% $states.context.Execution.Name %}" }
      } }
    })
  }
}

data "aws_iam_policy_document" "sfn_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "ec2_timeline" {
  name               = "${var.name_prefix}ec2-timeline-role"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

data "aws_iam_policy_document" "ec2_timeline" {
  statement {
    sid     = "InvokeGuardianLambdas"
    actions = ["lambda:InvokeFunction"]
    # Built from known values, not aws_lambda_function.remediation.arn: otherwise every code change defers this
    # read and shows a no-op policy update in the plan.
    resources = [local.remediation_arn, var.notify_function_arn]
  }

  statement {
    sid       = "UpdateFindings"
    actions   = ["dynamodb:UpdateItem"]
    resources = [var.table_arns["findings"]]
  }

  statement {
    sid       = "WriteFailureAudit"
    actions   = ["dynamodb:PutItem"]
    resources = [var.table_arns["audit"]]
  }
}

resource "aws_iam_role_policy" "ec2_timeline" {
  name   = "ec2-timeline"
  role   = aws_iam_role.ec2_timeline.id
  policy = data.aws_iam_policy_document.ec2_timeline.json
}

resource "aws_sfn_state_machine" "ec2_timeline" {
  name       = "${var.name_prefix}ec2-timeline"
  type       = "STANDARD"
  role_arn   = aws_iam_role.ec2_timeline.arn
  definition = templatefile("${path.module}/ec2_timeline.asl.json", merge(local.ec2_timeline_parts, local.failure_parts))

  depends_on = [aws_iam_role_policy.ec2_timeline]
}
