# DynamoDB tables, exactly as CONTRACT §3. All on-demand, default encryption (AWS owned key),
# point-in-time recovery off (cost).

resource "aws_dynamodb_table" "findings" {
  name         = "${var.name_prefix}findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "resourceId"
  range_key    = "findingType"

  attribute {
    name = "resourceId"
    type = "S"
  }
  attribute {
    name = "findingType"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_dynamodb_table" "audit" {
  name         = "${var.name_prefix}audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "resourceId"
  range_key    = "ts"

  attribute {
    name = "resourceId"
    type = "S"
  }
  attribute {
    name = "ts"
    type = "S"
  }
  attribute {
    name = "day"
    type = "S"
  }

  # Dashboard activity view (CONTRACT §3.3).
  global_secondary_index {
    name            = "byDay"
    projection_type = "ALL"

    key_schema {
      attribute_name = "day"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "ts"
      key_type       = "RANGE"
    }
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_dynamodb_table" "tokens" {
  name         = "${var.name_prefix}tokens"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tokenHash"

  attribute {
    name = "tokenHash"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_dynamodb_table" "creator_lookups" {
  name         = "${var.name_prefix}creator-lookups"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "resourceId"

  attribute {
    name = "resourceId"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_dynamodb_table" "volume_attachments" {
  name         = "${var.name_prefix}volume-attachments"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "volumeId"

  attribute {
    name = "volumeId"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_dynamodb_table" "daily_summaries" {
  name         = "${var.name_prefix}daily-summaries"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "day"

  attribute {
    name = "day"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_dynamodb_table" "bill_history" {
  name         = "${var.name_prefix}bill-history"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "day"
  range_key    = "key"

  attribute {
    name = "day"
    type = "S"
  }
  attribute {
    name = "key"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_dynamodb_table" "budget_alerts" {
  name         = "${var.name_prefix}budget-alerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "budgetName"
  range_key    = "receivedAt"

  attribute {
    name = "budgetName"
    type = "S"
  }
  attribute {
    name = "receivedAt"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_dynamodb_table" "counters" {
  name         = "${var.name_prefix}counters"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "counterId"

  attribute {
    name = "counterId"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }
}

locals {
  # Keys fixed by CONTRACT §8.
  tables = {
    findings           = aws_dynamodb_table.findings
    audit              = aws_dynamodb_table.audit
    tokens             = aws_dynamodb_table.tokens
    creator_lookups    = aws_dynamodb_table.creator_lookups
    volume_attachments = aws_dynamodb_table.volume_attachments
    daily_summaries    = aws_dynamodb_table.daily_summaries
    bill_history       = aws_dynamodb_table.bill_history
    budget_alerts      = aws_dynamodb_table.budget_alerts
    counters           = aws_dynamodb_table.counters
  }
}
