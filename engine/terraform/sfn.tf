# EC2 timeline state machine (design §9.2, CONTRACT §4.4). Started only by common/timeline.py.
# The definition is ec2_timeline.asl.json (JSONata); the shared pieces below are injected as JSON.

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

  ec2_timeline_parts = {
    findings_table  = var.table_names["findings"]
    notify_arn      = var.notify_function_arn
    remediation_arn = aws_lambda_function.remediation.arn

    finding_key = jsonencode({
      resourceId  = { S = "{% $input.resourceId %}" }
      findingType = { S = "{% $input.findingType %}" }
    })

    check_payload = jsonencode({
      action     = "CHECK_EC2"
      resourceId = "{% $input.resourceId %}"
      region     = "{% $input.region %}"
      dryRun     = "{% $input.dryRun %}"
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

    # The only Catch until task #19: the finding moved on, so this execution ends quietly.
    superseded_catch = jsonencode([{
      ErrorEquals = ["DynamoDB.ConditionalCheckFailedException"]
      Next        = "Superseded"
    }])
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
  definition = templatefile("${path.module}/ec2_timeline.asl.json", local.ec2_timeline_parts)

  depends_on = [aws_iam_role_policy.ec2_timeline]
}
