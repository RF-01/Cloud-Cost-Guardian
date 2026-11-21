# HTTP API for the email action links (CONTRACT §4.6). Core creates the API and its stage only;
# engine adds the /action routes, the integration and the Lambda permission.

resource "aws_apigatewayv2_api" "action" {
  name          = "${var.name_prefix}action-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.action.id
  name        = "$default"
  auto_deploy = true

  # Caps on the public action endpoint (requests per second, whole API).
  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }
}

locals {
  # Base URL with no trailing slash, so links are <ACTION_API_URL>/action?t=<token> (CONTRACT §3.4).
  # With the $default stage there is no stage path, so the API endpoint is the invoke URL.
  action_api_url = aws_apigatewayv2_api.action.api_endpoint
}
