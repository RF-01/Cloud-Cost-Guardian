# Own small VPC for the dashboard instance (design §6.4). All free: no NAT gateway, no endpoints.
# The security group belongs to the dashboard module.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true # the instance needs a public DNS name as CloudFront's origin

  tags = { Name = "${var.name_prefix}vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.0.0/26"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.name_prefix}public" }
}

# The VPC's default security group is unused: take it over with no rules, so nothing placed in it
# by mistake can send or receive traffic.
resource "aws_default_security_group" "locked" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}default-locked" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.name_prefix}public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
