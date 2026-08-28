data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_vpc" "experiment" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.experiment_group}-vpc"
  }
}

resource "aws_internet_gateway" "experiment" {
  vpc_id = aws_vpc.experiment.id

  tags = {
    Name = "${var.experiment_group}-igw"
  }
}

resource "aws_subnet" "nodes" {
  vpc_id                  = aws_vpc.experiment.id
  cidr_block              = var.node_subnet_cidr
  availability_zone_id    = var.availability_zone_id
  map_public_ip_on_launch = var.associate_public_ip_address

  tags = {
    Name = "${var.experiment_group}-nodes"
  }
}

resource "aws_route_table" "nodes" {
  vpc_id = aws_vpc.experiment.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.experiment.id
  }

  tags = {
    Name = "${var.experiment_group}-nodes"
  }
}

resource "aws_route_table_association" "nodes" {
  subnet_id      = aws_subnet.nodes.id
  route_table_id = aws_route_table.nodes.id
}

resource "aws_security_group" "nodes" {
  name_prefix = "${var.experiment_group}-nodes-"
  description = "Private protocol traffic and outbound SSM only"
  vpc_id      = aws_vpc.experiment.id

  egress {
    description = "Outbound package, SSM, and artifact access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.experiment_group}-nodes"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "private_self" {
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  description                  = "All private traffic between experiment nodes"
  ip_protocol                  = "-1"
}

resource "aws_security_group" "management_endpoints" {
  count = var.enable_private_management_endpoints ? 1 : 0

  name_prefix = "${var.experiment_group}-endpoints-"
  description = "TLS from experiment nodes to private AWS management endpoints"
  vpc_id      = aws_vpc.experiment.id

  tags = {
    Name = "${var.experiment_group}-endpoints"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "management_endpoint_tls" {
  count = var.enable_private_management_endpoints ? 1 : 0

  security_group_id            = aws_security_group.management_endpoints[0].id
  referenced_security_group_id = aws_security_group.nodes.id
  description                  = "HTTPS from experiment nodes"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_endpoint" "management" {
  for_each = var.enable_private_management_endpoints ? toset(["ssm", "ssmmessages", "ec2messages"]) : toset([])

  vpc_id              = aws_vpc.experiment.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.nodes.id]
  security_group_ids  = [aws_security_group.management_endpoints[0].id]
  private_dns_enabled = true

  tags = {
    Name = "${var.experiment_group}-${each.value}"
  }
}

resource "aws_vpc_endpoint" "s3" {
  count = var.enable_private_management_endpoints ? 1 : 0

  vpc_id            = aws_vpc.experiment.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.nodes.id]

  tags = {
    Name = "${var.experiment_group}-s3"
  }
}

locals {
  protocol_public_cidr_chunks = var.enable_public_protocol ? chunklist(
    var.protocol_public_peer_cidrs,
    var.protocol_public_cidrs_per_group,
  ) : []
}

resource "aws_security_group" "public_protocol" {
  for_each = {
    for index, cidrs in local.protocol_public_cidr_chunks : tostring(index) => cidrs
  }

  name_prefix = "${var.experiment_group}-protocol-${each.key}-"
  description = "Exact public protocol source shard ${each.key}"
  vpc_id      = aws_vpc.experiment.id

  ingress {
    description = "Protocol TCP from exact experiment peer IPv4 addresses"
    from_port   = var.protocol_public_port_from
    to_port     = var.protocol_public_port_to
    protocol    = "tcp"
    cidr_blocks = each.value
  }

  tags = {
    Name = "${var.experiment_group}-protocol-${each.key}"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "nodes" {
  name_prefix        = "${var.experiment_group}-"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Name = "${var.experiment_group}-nodes"
  }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "nodes" {
  name_prefix = "${var.experiment_group}-"
  role        = aws_iam_role.nodes.name

  tags = {
    Name = "${var.experiment_group}-nodes"
  }
}

resource "aws_instance" "node" {
  count = var.instance_count

  ami           = var.ami_id != "" ? var.ami_id : data.aws_ssm_parameter.al2023_arm64.value
  instance_type = var.instance_type
  subnet_id     = aws_subnet.nodes.id
  private_ip    = cidrhost(aws_subnet.nodes.cidr_block, count.index + var.node_private_ip_offset)
  vpc_security_group_ids = concat(
    [aws_security_group.nodes.id],
    [for group in aws_security_group.public_protocol : group.id],
  )
  associate_public_ip_address = var.associate_public_ip_address
  iam_instance_profile        = aws_iam_instance_profile.nodes.name

  instance_market_options {
    market_type = "spot"

    spot_options {
      instance_interruption_behavior = "terminate"
      spot_instance_type             = "one-time"
    }
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted             = true
    delete_on_termination = true
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
  }

  user_data = "${file("${path.module}/user-data.sh")}\nprintf '%s\\n' '${count.index + var.node_slot_offset}' > /etc/rladkr/node-slot\nprintf '%s\\n' '${var.logical_node_ids_by_instance[count.index]}' > /etc/rladkr/logical-node-ids\n"

  tags = {
    Name     = format("%s-node-%03d", var.experiment_group, count.index + var.node_slot_offset)
    NodeSlot = tostring(count.index + var.node_slot_offset)
  }

  lifecycle {
    precondition {
      condition     = !var.enable_public_protocol || var.associate_public_ip_address
      error_message = "Public protocol mode requires associate_public_ip_address=true."
    }
    precondition {
      condition     = length(var.logical_node_ids_by_instance) == var.instance_count
      error_message = "logical_node_ids_by_instance must contain one entry per physical instance."
    }
    precondition {
      condition     = length(aws_security_group.public_protocol) <= 4
      error_message = "Public protocol ingress requires at most four sharded security groups."
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm,
    aws_vpc_endpoint.management,
    aws_vpc_endpoint.s3,
  ]
}
