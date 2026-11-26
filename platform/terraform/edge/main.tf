# CloudFront in front of the dashboard instance (task #38, design §6.4):
#   Browser --HTTPS--> CloudFront --(basic auth function, viewer request)--HTTP + X-Origin-Verify--> EC2:80
# Caching disabled; the origin request policy forwards only CloudFront-Viewer-Address (the per-visitor rate
# limit), Content-Type and X-Requested-With (the Ask box's JSON body and CSRF check, #43) and the query string.
# The viewer's Authorization header and cookies never reach the instance. The origin read timeout stays at its
# default, 30 s: the Ask request is kept under it (CONTRACT §4.11).

locals {
  dashboard_name = "${var.name_prefix}dashboard"
  origin_id      = "dashboard-ec2"
}

# The credentials go into the function code as the full expected header, precomputed here; the code (and so
# the plan) is sensitive. Changing the login = change the variable and run terraform apply.
resource "aws_cloudfront_function" "basic_auth" {
  name    = "${var.name_prefix}basic-auth"
  runtime = "cloudfront-js-2.0"
  comment = "Team login for ${local.dashboard_name} (basic auth)"
  publish = true
  code = templatefile("${path.module}/templates/basic_auth.js.tftpl", {
    expected = "Basic ${base64encode("${var.dashboard_username}:${var.dashboard_password}")}"
  })
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

resource "aws_cloudfront_origin_request_policy" "dashboard" {
  name    = local.dashboard_name
  comment = "Dashboard: viewer address (rate limit), Ask box headers, query strings; no cookies"

  headers_config {
    header_behavior = "whitelist"
    headers {
      items = ["CloudFront-Viewer-Address", "Content-Type", "X-Requested-With"]
    }
  }

  query_strings_config {
    query_string_behavior = "all"
  }

  cookies_config {
    cookie_behavior = "none"
  }
}

resource "aws_cloudfront_distribution" "dashboard" {
  enabled         = true
  comment         = local.dashboard_name
  price_class     = "PriceClass_100"
  http_version    = "http2and3"
  is_ipv6_enabled = false

  origin {
    origin_id   = local.origin_id
    domain_name = var.dashboard_public_dns

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only" # no certificate on the instance; CloudFront terminates HTTPS
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    # Proves the request came through THIS distribution (the SG alone admits every CloudFront server).
    custom_header {
      name  = "X-Origin-Verify"
      value = var.origin_secret
    }
  }

  default_cache_behavior {
    target_origin_id         = local.origin_id
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"] # POST: Ask box (#43)
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.dashboard.id
    compress                 = true

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.basic_auth.arn
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = { Name = local.dashboard_name }
}
